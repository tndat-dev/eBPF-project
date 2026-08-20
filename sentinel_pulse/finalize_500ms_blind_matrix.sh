#!/usr/bin/env bash
# Freeze three worker streams and evaluate one completed Pulse blind matrix.
set -euo pipefail

EVIDENCE_ROOT=${1:?usage: finalize_500ms_blind_matrix.sh EVIDENCE_ROOT}
LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
REMOTE_ROOT=${REMOTE_ROOT:-/home/dat/eBPF-project-pulse-blind}
ATTACK_CONTRACT=${ATTACK_CONTRACT:-$EVIDENCE_ROOT/protocol/blind-attack-contract.json}
POLICY_SOURCE=${POLICY_SOURCE:-$EVIDENCE_ROOT/protocol/decision-policy.json}
NORMAL_EVIDENCE_ROOT=${NORMAL_EVIDENCE_ROOT:?point to the passed formal normal soak}
PYTHON=${PYTHON:-/home/dat/ml-venv/bin/python}
SSH_USER=${SSH_USER:-dat}
: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
for command in sshpass tar jq sha256sum; do command -v "$command" >/dev/null; done
test -f "$EVIDENCE_ROOT/ACTIVE"
test -f "$EVIDENCE_ROOT/MATRIX_COMPLETE"
test -f "$EVIDENCE_ROOT/REPORT.json"
test -f "$EVIDENCE_ROOT/injections.jsonl"
test -f "$EVIDENCE_ROOT/kernel-events.jsonl"
test -f "$EVIDENCE_ROOT/workers.txt"
test ! -e "$EVIDENCE_ROOT/INFRA_FAILURE.json"
test ! -e "$EVIDENCE_ROOT/BLIND_RESULT.json"
test -f "$NORMAL_EVIDENCE_ROOT/NORMAL_PASS"
test -f "$NORMAL_EVIDENCE_ROOT/NORMAL_REPORT.json"
test -f "$NORMAL_EVIDENCE_ROOT/SOAK_START.json"
test -f "$EVIDENCE_ROOT/model/manifest.json"
test -f "$POLICY_SOURCE"
test -f "$EVIDENCE_ROOT/protocol/attack-implementation-contract.json"
test -f "$EVIDENCE_ROOT/protocol/runtime_attack_blind.c"
test -f "$EVIDENCE_ROOT/runtime_attack_blind"
(cd "$EVIDENCE_ROOT" && sha256sum -c START_SHA256SUMS)
[[ $(sha256sum "$ATTACK_CONTRACT" | awk '{print $1}') == \
   $(jq -er '.blind_attack_contract_sha256' "$EVIDENCE_ROOT/BLIND_START.json") ]]
[[ $(sha256sum "$POLICY_SOURCE" | awk '{print $1}') == \
   $(jq -er '.decision_policy_sha256' "$EVIDENCE_ROOT/BLIND_START.json") ]]
[[ $(sha256sum "$EVIDENCE_ROOT/protocol/attack-implementation-contract.json" | awk '{print $1}') == \
   $(jq -er '.attack_implementation_contract_sha256' "$EVIDENCE_ROOT/BLIND_START.json") ]]
[[ $(sha256sum "$EVIDENCE_ROOT/protocol/runtime_attack_blind.c" | awk '{print $1}') == \
   $(jq -er '.runtime_source_sha256' "$EVIDENCE_ROOT/BLIND_START.json") ]]
[[ $(sha256sum "$EVIDENCE_ROOT/runtime_attack_blind" | awk '{print $1}') == \
   $(jq -er '.runtime_binary_sha256' "$EVIDENCE_ROOT/BLIND_START.json") ]]
jq -e '.matrix_complete == true and .completed_injections == .expected_injections' "$EVIDENCE_ROOT/REPORT.json" >/dev/null

complete=false
on_exit() {
  local rc=$?
  if [[ $complete != true ]]; then
    printf 'failed_at=%s\nexit_code=%s\n' "$(date -u +%FT%TZ)" "$rc" \
      >"$EVIDENCE_ROOT/FINALIZE_FAILED"
  fi
}
trap on_exit EXIT

remote_sudo() {
  local host=$1; shift
  printf '%s\n' "$SSHPASS" | sshpass -e ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=8 "$SSH_USER@$host" "sudo -S -p '' $*"
}

mkdir -p "$EVIDENCE_ROOT/workers"
declare -a hosts decision_paths remote_injection_paths
while read -r host node feature injections; do
  [[ $feature == /var/lib/sentinel-pulse-500ms/runs/*/features.jsonl ]]
  [[ $injections == /var/lib/sentinel-pulse-detector/runs/*/injections.jsonl ]]
  detector_dir=$(dirname "$injections")
  snapshot=$(remote_sudo "$host" bash -c \
    "'printf \"collector=%s\\ndetector=%s\\nrestarts=%s\\nfeature=%s\\ninjections=%s\\n\" \"\$(systemctl is-active sentinel-pulse-collector-500ms-experiment)\" \"\$(systemctl is-active sentinel-pulse-detector-candidate)\" \"\$(systemctl show sentinel-pulse-detector-candidate -p NRestarts --value)\" \"\$(sed -n s/^PULSE_FEATURES=//p /etc/sentinel-pulse-detector-candidate.env)\" \"\$(sed -n s/^PULSE_INJECTIONS=//p /etc/sentinel-pulse-detector-candidate.env)\"'" )
  printf '%s\n' "$snapshot" >"$EVIDENCE_ROOT/workers/$host-pre-finalize.txt"
  [[ $(sed -n 's/^collector=//p' <<<"$snapshot") == active ]]
  [[ $(sed -n 's/^detector=//p' <<<"$snapshot") == active ]]
  [[ $(sed -n 's/^restarts=//p' <<<"$snapshot") == 0 ]]
  [[ $(sed -n 's/^feature=//p' <<<"$snapshot") == "$feature" ]]
  [[ $(sed -n 's/^injections=//p' <<<"$snapshot") == "$injections" ]]
  hosts+=("$host")
done <"$EVIDENCE_ROOT/workers.txt"
[[ ${#hosts[@]} -eq 3 ]]

# Freeze every decision stream before stopping any telemetry source.
for host in "${hosts[@]}"; do remote_sudo "$host" systemctl stop sentinel-pulse-detector-candidate.service; done
for host in "${hosts[@]}"; do remote_sudo "$host" systemctl stop sentinel-pulse-collector-500ms-experiment.service; done

while read -r host node feature injections; do
  capture_dir=$(dirname "$feature")
  detector_dir=$(dirname "$injections")
  remote_sudo "$host" env MINIMUM_ROWS_PER_WORKLOAD=100 \
    "$REMOTE_ROOT/sentinel_pulse/finalize_500ms_experiment.sh" \
    >"$EVIDENCE_ROOT/workers/$host-node-finalize.json"
  destination="$EVIDENCE_ROOT/workers/$host/raw"
  mkdir -p "$destination"
  printf '%s\n' "$SSHPASS" | sshpass -e ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=8 "$SSH_USER@$host" \
    "sudo -S -p '' tar -C / -cf - '${capture_dir#/}' '${detector_dir#/}'" | \
    tar -C "$destination" -xf -
  decisions="$destination/${detector_dir#/}/decisions.jsonl"
  remote_injections="$destination/${detector_dir#/}/injections.jsonl"
  test -s "$decisions"
  test -s "$remote_injections"
  test -f "$destination/${detector_dir#/}/alerts.jsonl"
  test -s "$destination/${capture_dir#/}/features.jsonl"
  decision_paths+=("$decisions")
  remote_injection_paths+=("$remote_injections")
done <"$EVIDENCE_ROOT/workers.txt"

(
  cd "$EVIDENCE_ROOT"
  find workers -type f \( -name decisions.jsonl -o -name alerts.jsonl \
    -o -name features.jsonl -o -name injections.jsonl \
    -o -name FINAL.json -o -name '*-node-finalize.json' \
    -o -name '*-pre-finalize.txt' \) -print0 | sort -z | \
    xargs -0 sha256sum
) >"$EVIDENCE_ROOT/RAW_SHA256SUMS"
(cd "$EVIDENCE_ROOT" && sha256sum -c RAW_SHA256SUMS)

marker_args=()
for path in "${remote_injection_paths[@]}"; do marker_args+=(--detector "$path"); done
PYTHONPATH="$LOCAL_ROOT" "$PYTHON" -m sentinel_pulse.verify_distributed_injections \
  --controller "$EVIDENCE_ROOT/injections.jsonl" \
  "${marker_args[@]}" \
  --output "$EVIDENCE_ROOT/DISTRIBUTED_INJECTIONS.json"

evaluation_args=()
for path in "${decision_paths[@]}"; do evaluation_args+=(--decisions "$path"); done
set +e
PYTHONPATH="$LOCAL_ROOT" "$PYTHON" -m sentinel_pulse.evaluate_latency \
  "${evaluation_args[@]}" \
  --injections "$EVIDENCE_ROOT/injections.jsonl" \
  --kernel-events "$EVIDENCE_ROOT/kernel-events.jsonl" \
  --attack-contract "$ATTACK_CONTRACT" \
  --expected-injections 450 \
  --run-id "$(jq -er '.run_id' "$EVIDENCE_ROOT/BLIND_START.json")" \
  --output "$EVIDENCE_ROOT/LATENCY_REPORT.json"
evaluation_rc=$?
set -e

set +e
PYTHONPATH="$LOCAL_ROOT" "$PYTHON" -m sentinel_pulse.finalize_candidate \
  --model-dir "$EVIDENCE_ROOT/model" \
  --decision-policy "$POLICY_SOURCE" \
  --soak-marker "$NORMAL_EVIDENCE_ROOT/SOAK_START.json" \
  --normal-report "$NORMAL_EVIDENCE_ROOT/NORMAL_REPORT.json" \
  --attack-report "$EVIDENCE_ROOT/LATENCY_REPORT.json" \
  --expected-injections 450 \
  --output "$EVIDENCE_ROOT/CANDIDATE_DECISION.json"
candidate_rc=$?
set -e

"$PYTHON" - "$EVIDENCE_ROOT" "$evaluation_rc" "$candidate_rc" <<'PY'
from datetime import datetime, timezone
import hashlib, json, pathlib, sys
root, rc, candidate_rc = pathlib.Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
report = json.loads((root / "LATENCY_REPORT.json").read_text())
candidate = json.loads((root / "CANDIDATE_DECISION.json").read_text())
result = {
    "schema": "sentinel-pulse-blind-result-v1",
    "completed_at": datetime.now(timezone.utc).isoformat(),
    "evaluation_exit_code": rc,
    "blind_evidence_valid": report.get("blind_evidence_valid") is True,
    "expected_injections": report.get("expected_injections"),
    "detected_injections": report.get("detected_injections"),
    "recall": report.get("recall"),
    "kernel_to_alert_seconds": report.get("kernel_to_alert_seconds"),
    "candidate_decision_exit_code": candidate_rc,
    "candidate_status": candidate.get("status"),
    "candidate_failed_gates": candidate.get("failed_gates"),
    "eligible_for_overhead_evaluation": candidate.get("evidence_complete_for_accuracy_latency") is True,
    "automatic_promotion": False,
    "latency_report_sha256": hashlib.sha256((root / "LATENCY_REPORT.json").read_bytes()).hexdigest(),
}
(root / "BLIND_RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
PY
(
  cd "$EVIDENCE_ROOT"
  sha256sum BLIND_START.json PLAN.json REPORT.json MATRIX_COMPLETE \
    injections.jsonl kernel-events.jsonl LATENCY_REPORT.json \
    DISTRIBUTED_INJECTIONS.json CANDIDATE_DECISION.json BLIND_RESULT.json \
    workers.txt START_SHA256SUMS RAW_SHA256SUMS \
    protocol/decision-policy.json protocol/blind-attack-contract.json \
    protocol/attack-implementation-contract.json \
    protocol/runtime_attack_blind.c runtime_attack_blind
) >"$EVIDENCE_ROOT/FINAL_SHA256SUMS"
(cd "$EVIDENCE_ROOT" && sha256sum -c FINAL_SHA256SUMS)
rm -f "$EVIDENCE_ROOT/ACTIVE"
rm -f "$EVIDENCE_ROOT/FINALIZE_FAILED"
complete=true
printf 'Pulse blind matrix finalized: evidence=%s evaluation_rc=%s\n' "$EVIDENCE_ROOT" "$evaluation_rc"
