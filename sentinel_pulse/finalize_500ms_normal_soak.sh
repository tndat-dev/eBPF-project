#!/usr/bin/env bash
# Freeze, export and evaluate one preregistered three-worker normal soak.
set -euo pipefail

EVIDENCE_ROOT=${1:?usage: finalize_500ms_normal_soak.sh EVIDENCE_ROOT}
LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
MODEL_SOURCE=${MODEL_SOURCE:?MODEL_SOURCE must contain the frozen manifest.json}
POLICY_SOURCE=${POLICY_SOURCE:-$LOCAL_ROOT/sentinel_pulse/protocol/decision-policy-semantic-v4.json}
SSH_USER=${SSH_USER:-dat}
FINALIZE_MARGIN_SECONDS=${FINALIZE_MARGIN_SECONDS:-300}
MINIMUM_SCORED_WINDOWS=${MINIMUM_SCORED_WINDOWS:-86400}
MARKER="$EVIDENCE_ROOT/SOAK_START.json"
WORKERS_FILE="$EVIDENCE_ROOT/workers.txt"

: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
command -v sshpass >/dev/null
command -v kubectl >/dev/null
command -v jq >/dev/null
command -v tar >/dev/null
[[ $FINALIZE_MARGIN_SECONDS =~ ^[0-9]+$ ]] || exit 2
test -f "$MARKER"
test -f "$WORKERS_FILE"
test -f "$EVIDENCE_ROOT/ACTIVE"
test ! -e "$EVIDENCE_ROOT/FAILED"
test ! -e "$EVIDENCE_ROOT/NORMAL_PASS"
test -f "$MODEL_SOURCE/manifest.json"
test -f "$POLICY_SOURCE"

remote() {
  local host=$1; shift
  sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 \
    "$SSH_USER@$host" "$@"
}

remote_sudo() {
  local host=$1; shift
  printf '%s\n' "$SSHPASS" | sshpass -e ssh \
    -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" \
    "sudo -S -p '' $*"
}

run_id=$(jq -er '.run_id' "$MARKER")
model_sha=$(jq -er '.model_manifest_sha256' "$MARKER")
policy_sha=$(jq -er '.decision_policy_sha256' "$MARKER")
eligible_epoch=$(python3 - "$MARKER" <<'PY'
from datetime import datetime
import json, pathlib, sys
marker = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(int(datetime.fromisoformat(marker["eligible_finalize_after"]).timestamp()))
PY
)
(( $(date +%s) >= eligible_epoch + FINALIZE_MARGIN_SECONDS )) || {
  echo "normal soak is not yet eligible plus finalization margin" >&2
  exit 3
}
[[ $(sha256sum "$MODEL_SOURCE/manifest.json" | awk '{print $1}') == "$model_sha" ]]
[[ $(sha256sum "$POLICY_SOURCE" | awk '{print $1}') == "$policy_sha" ]]

finalizing="$EVIDENCE_ROOT/FINALIZING"
printf 'started_at=%s\nsource_commit=%s\n' "$(date -u +%FT%TZ)" \
  "$(git -C "$LOCAL_ROOT" rev-parse HEAD)" >"$finalizing"
complete=false
on_exit() {
  local rc=$?
  if [[ $complete != true ]]; then
    printf 'failed_at=%s\nexit_code=%s\n' "$(date -u +%FT%TZ)" "$rc" \
      >"$EVIDENCE_ROOT/FINALIZE_FAILED"
  fi
}
trap on_exit EXIT

kubectl get nodes -o json >"$EVIDENCE_ROOT/finalize-nodes-before.json"
kubectl -n production get pods -o json \
  >"$EVIDENCE_ROOT/finalize-production-pods-before.json"
[[ $(kubectl get nodes -o json | PYTHONPATH="$LOCAL_ROOT" python3 \
  -m sentinel_pulse.cluster_health --resource nodes --count) -eq 0 ]]
[[ $(kubectl -n production get pods -o json | PYTHONPATH="$LOCAL_ROOT" python3 \
  -m sentinel_pulse.cluster_health --resource pods --grace-seconds 0 --count) -eq 0 ]]

mkdir -p "$EVIDENCE_ROOT/workers"
declare -a hosts decision_paths capture_paths detector_dirs
while read -r host node expected_feature; do
  [[ $expected_feature == "/var/lib/sentinel-pulse-500ms/runs/$run_id/features.jsonl" ]]
  detector_dir="/var/lib/sentinel-pulse-detector/runs/$model_sha-$policy_sha-$run_id"
  snapshot=$(remote_sudo "$host" bash -c \
    "'source /etc/sentinel-pulse-detector-candidate.env; printf \"collector=%s\\ndetector=%s\\nrestarts=%s\\ndecisions=%s\\nalerts=%s\\nfeature=%s\\nrun=%s\\n\" \"\$(systemctl is-active sentinel-pulse-collector-500ms-experiment)\" \"\$(systemctl is-active sentinel-pulse-detector-candidate)\" \"\$(systemctl show sentinel-pulse-detector-candidate -p NRestarts --value)\" \"\$(wc -l < \"\$PULSE_DECISIONS\")\" \"\$(wc -l < \"\$PULSE_ALERTS\")\" \"\$PULSE_FEATURES\" \"\$PULSE_RUN_ID\"'" )
  snapshot_file="$EVIDENCE_ROOT/workers/$host-pre-finalize.txt"
  printf '%s\n' "$snapshot" >"$snapshot_file"
  value() { sed -n "s/^$1=//p" <<<"$snapshot"; }
  [[ $(value collector) == active ]]
  [[ $(value detector) == active ]]
  [[ $(value restarts) == 0 ]]
  [[ $(value alerts) == 0 ]]
  [[ $(value feature) == "$expected_feature" ]]
  [[ $(value run) == "$run_id" ]]
  hosts+=("$host")
  capture_paths+=("${expected_feature%/features.jsonl}")
  detector_dirs+=("$detector_dir")
done <"$WORKERS_FILE"
[[ ${#hosts[@]} -eq 3 ]]

# Freeze all decision streams before stopping any telemetry source.
for host in "${hosts[@]}"; do
  remote_sudo "$host" systemctl stop sentinel-pulse-detector-candidate.service
done
for host in "${hosts[@]}"; do
  remote_sudo "$host" systemctl stop sentinel-pulse-collector-500ms-experiment.service
done

for index in "${!hosts[@]}"; do
  host=${hosts[$index]}
  capture_dir=${capture_paths[$index]}
  detector_dir=${detector_dirs[$index]}
  remote_sudo "$host" env MINIMUM_ROWS_PER_WORKLOAD=100 \
    /home/dat/eBPF-project/sentinel_pulse/finalize_500ms_experiment.sh \
    >"$EVIDENCE_ROOT/workers/$host-node-finalize.json"
  destination="$EVIDENCE_ROOT/workers/$host/raw"
  mkdir -p "$destination"
  printf '%s\n' "$SSHPASS" | sshpass -e ssh \
    -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" \
    "sudo -S -p '' tar -C / -cf - '${capture_dir#/}' '${detector_dir#/}'" | \
    tar -C "$destination" -xf -
  decisions="$destination/${detector_dir#/}/decisions.jsonl"
  alerts="$destination/${detector_dir#/}/alerts.jsonl"
  feature="$destination/${capture_dir#/}/features.jsonl"
  final="$destination/${capture_dir#/}/FINAL.json"
  test -s "$decisions"
  test -f "$alerts"
  test -s "$feature"
  jq -e '.valid == true and .service_ok == true' "$final" >/dev/null
  decision_paths+=("$decisions")
done

(
  cd "$EVIDENCE_ROOT"
  find workers -type f \( -name decisions.jsonl -o -name alerts.jsonl \
    -o -name features.jsonl -o -name FINAL.json \) -print0 | sort -z | \
    xargs -0 sha256sum
) >"$EVIDENCE_ROOT/RAW_SHA256SUMS"
(
  cd "$EVIDENCE_ROOT"
  sha256sum -c RAW_SHA256SUMS
)

evaluate_args=()
for decisions in "${decision_paths[@]}"; do
  evaluate_args+=(--decisions "$decisions")
done
PYTHONPATH="$LOCAL_ROOT" python3 -m sentinel_pulse.evaluate_normal \
  "${evaluate_args[@]}" \
  --output "$EVIDENCE_ROOT/NORMAL_REPORT.json" \
  --maximum-alerts 0 \
  --minimum-scored-windows "$MINIMUM_SCORED_WINDOWS" \
  --minimum-duration-hours 24 \
  --minimum-coverage-ratio 0.95 \
  --soak-marker "$MARKER" \
  --model-manifest "$MODEL_SOURCE/manifest.json"
jq -e '.normal_gate == true and .expected_workload_gate == true' \
  "$EVIDENCE_ROOT/NORMAL_REPORT.json" >/dev/null

kubectl get nodes -o json >"$EVIDENCE_ROOT/finalize-nodes-after.json"
kubectl -n production get pods -o json \
  >"$EVIDENCE_ROOT/finalize-production-pods-after.json"
report_sha=$(sha256sum "$EVIDENCE_ROOT/NORMAL_REPORT.json" | awk '{print $1}')
printf 'passed_at=%s\nnormal_report_sha256=%s\nautomatic_promotion=false\n' \
  "$(date -u +%FT%TZ)" "$report_sha" >"$EVIDENCE_ROOT/NORMAL_PASS"
sha256sum "$MARKER" "$MODEL_SOURCE/manifest.json" "$POLICY_SOURCE" \
  "$EVIDENCE_ROOT/NORMAL_REPORT.json" "$EVIDENCE_ROOT/RAW_SHA256SUMS" \
  >"$EVIDENCE_ROOT/FINAL_SHA256SUMS"
rm -f "$EVIDENCE_ROOT/ACTIVE" "$EVIDENCE_ROOT/FINALIZE_FAILED" "$finalizing"
complete=true
printf 'normal soak passed: run=%s report=%s\n' "$run_id" \
  "$EVIDENCE_ROOT/NORMAL_REPORT.json"
