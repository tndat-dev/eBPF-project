#!/usr/bin/env bash
# Freeze and evaluate an explicitly non-formal attack-latency pilot.
set -Eeuo pipefail

EVIDENCE_ROOT=${1:?usage: finalize_attack_latency_pilot.sh EVIDENCE_ROOT}
LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
PYTHON=${PYTHON:-/home/dat/ml-venv/bin/python}
SSH_USER=${SSH_USER:-dat}
: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
for command in sshpass tar jq sha256sum; do command -v "$command" >/dev/null; done

test -f "$EVIDENCE_ROOT/ACTIVE"
test -f "$EVIDENCE_ROOT/PILOT_COMPLETE"
test -f "$EVIDENCE_ROOT/REPORT.json"
test -f "$EVIDENCE_ROOT/injections.jsonl"
test -f "$EVIDENCE_ROOT/kernel-events.jsonl"
test -f "$EVIDENCE_ROOT/workers.txt"
test ! -e "$EVIDENCE_ROOT/INFRA_FAILURE.json"
test ! -e "$EVIDENCE_ROOT/PILOT_RESULT.json"
(cd "$EVIDENCE_ROOT" && sha256sum -c START_SHA256SUMS)
jq -e '
  .evidence_class == "nonformal_attack_latency_pilot" and
  .schedule_complete == true and .matrix_complete == false and
  .formal_blind_evidence == false and .accuracy_claim_allowed == false and
  .completed_injections == .expected_injections
' "$EVIDENCE_ROOT/REPORT.json" >/dev/null

run_id=$(jq -er '.run_id' "$EVIDENCE_ROOT/BLIND_START.json")
expected=$(jq -er '.expected_injections' "$EVIDENCE_ROOT/BLIND_START.json")
remote_root=$(jq -er '.remote_source_root' "$EVIDENCE_ROOT/BLIND_START.json")
[[ $remote_root == /home/dat/sentinel-pulse-attack-pilot-* ]]

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
resume_from_frozen_raw=false
if [[ -f $EVIDENCE_ROOT/FINALIZE_FAILED && -f $EVIDENCE_ROOT/RAW_SHA256SUMS ]]; then
  # A post-capture evaluator failure must never force attack reruns or mutate
  # the archived streams.  Resume only after the prior raw archive verifies.
  (cd "$EVIDENCE_ROOT" && sha256sum -c RAW_SHA256SUMS)
  resume_from_frozen_raw=true
fi

if [[ $resume_from_frozen_raw == false ]]; then
  while read -r host node feature injections; do
    [[ $feature == /var/lib/sentinel-pulse-500ms/runs/*/features.jsonl ]]
    [[ $injections == /var/lib/sentinel-pulse-detector/runs/*/injections.jsonl ]]
    detector_dir=$(dirname "$injections")
    snapshot=$(remote_sudo "$host" bash -c \
      "'printf \"collector=%s\\ndetector=%s\\nrestarts=%s\\nfeature=%s\\ninjections=%s\\n\" \"\$(systemctl is-active sentinel-pulse-collector-500ms-experiment || true)\" \"\$(systemctl is-active sentinel-pulse-detector-candidate || true)\" \"\$(systemctl show sentinel-pulse-detector-candidate -p NRestarts --value)\" \"\$(sed -n s/^PULSE_FEATURES=//p /etc/sentinel-pulse-detector-candidate.env)\" \"\$(sed -n s/^PULSE_INJECTIONS=//p /etc/sentinel-pulse-detector-candidate.env)\"'" )
    printf '%s\n' "$snapshot" >"$EVIDENCE_ROOT/workers/$host-pre-finalize.txt"
    [[ $(sed -n 's/^detector=//p' <<<"$snapshot") == active ]]
    [[ $(sed -n 's/^restarts=//p' <<<"$snapshot") == 0 ]]
    [[ $(sed -n 's/^feature=//p' <<<"$snapshot") == "$feature" ]]
    [[ $(sed -n 's/^injections=//p' <<<"$snapshot") == "$injections" ]]
    hosts+=("$host")
  done <"$EVIDENCE_ROOT/workers.txt"
  [[ ${#hosts[@]} -eq 3 ]]

  for host in "${hosts[@]}"; do
    remote_sudo "$host" systemctl stop sentinel-pulse-detector-candidate.service
    remote_sudo "$host" systemctl disable sentinel-pulse-detector-candidate.service >/dev/null
  done
  for host in "${hosts[@]}"; do
    remote_sudo "$host" systemctl stop sentinel-pulse-collector-500ms-experiment.service || true
  done

  while read -r host node feature injections; do
    capture_dir=$(dirname "$feature")
    detector_dir=$(dirname "$injections")
    remote_sudo "$host" env MINIMUM_ROWS_PER_WORKLOAD=20 \
      "$remote_root/sentinel_pulse/finalize_500ms_experiment.sh" \
      >"$EVIDENCE_ROOT/workers/$host-node-finalize.json"
    destination="$EVIDENCE_ROOT/workers/$node/raw"
    mkdir -p "$destination"
    printf '%s\n' "$SSHPASS" | sshpass -e ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=8 "$SSH_USER@$host" \
      "sudo -S -p '' tar -C / -cf - '${capture_dir#/}' '${detector_dir#/}'" | \
      tar -C "$destination" -xf -
  done <"$EVIDENCE_ROOT/workers.txt"

  (
    cd "$EVIDENCE_ROOT"
    find workers -type f -print0 | sort -z | xargs -0 sha256sum
  ) >"$EVIDENCE_ROOT/RAW_SHA256SUMS"
  (cd "$EVIDENCE_ROOT" && sha256sum -c RAW_SHA256SUMS)
fi

# Reconstruct evaluator inputs from the immutable local archive in both the
# first-pass and recovery paths, then validate every required stream.
while read -r host node feature injections; do
  capture_dir=$(dirname "$feature")
  detector_dir=$(dirname "$injections")
  destination="$EVIDENCE_ROOT/workers/$node/raw"
  decisions="$destination/${detector_dir#/}/decisions.jsonl"
  remote_injections="$destination/${detector_dir#/}/injections.jsonl"
  test -s "$decisions"
  test -f "$remote_injections"
  test -f "$destination/${detector_dir#/}/alerts.jsonl"
  test -s "$destination/${capture_dir#/}/features.jsonl"
  decision_paths+=("$decisions")
  remote_injection_paths+=("$remote_injections")
done <"$EVIDENCE_ROOT/workers.txt"

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
  --expected-injections "$expected" \
  --run-id "$run_id" \
  --output "$EVIDENCE_ROOT/LATENCY_REPORT.json"
evaluation_rc=$?
set -e

"$PYTHON" - "$EVIDENCE_ROOT" "$evaluation_rc" <<'PY'
from datetime import datetime, timezone
import hashlib, json, pathlib, sys
root, evaluation_rc = pathlib.Path(sys.argv[1]), int(sys.argv[2])
latency = json.loads((root / "LATENCY_REPORT.json").read_text())
run = json.loads((root / "REPORT.json").read_text())
plan = json.loads((root / "PILOT_PLAN.json").read_text())
expected = int(run["expected_injections"])
detected = int(run["detected_injections"])
prior_trials = plan.get("previous_completed_trials_excluded_without_rerun", [])
prior_expected = len(prior_trials)
prior_detected = sum(bool(item.get("detected")) for item in prior_trials)
lineage_expected = expected + prior_expected
lineage_detected = detected + prior_detected
p99 = latency.get("kernel_to_alert_seconds", {}).get("p99")
identity_valid = bool(
    latency.get("injection_identity_gate")
    and latency.get("kernel_timestamp_gate")
    and latency.get("model_identity_gate")
    and latency.get("decision_policy_identity_gate")
    and latency.get("run_identity_gate")
)
result = {
    "schema": "sentinel-pulse-attack-latency-pilot-result-v1",
    "completed_at": datetime.now(timezone.utc).isoformat(),
    "evidence_class": "nonformal_attack_latency_pilot",
    "accuracy_claim_allowed": False,
    "formal_blind_evidence": False,
    "automatic_promotion": False,
    "evaluation_exit_code": evaluation_rc,
    "evaluation_blind_evidence_valid": latency.get("blind_evidence_valid"),
    "expected_evaluation_invalid_reason": "pilot is not the full frozen 450-row attack matrix",
    "expected_injections": expected,
    "detected_injections": detected,
    "pilot_recall_descriptive_only": detected / expected,
    "previous_completed_injections_excluded_without_rerun": prior_expected,
    "previous_detected_injections_excluded_without_rerun": prior_detected,
    "lineage_expected_injections": lineage_expected,
    "lineage_detected_injections": lineage_detected,
    "lineage_recall_descriptive_only": lineage_detected / lineage_expected,
    "identity_and_kernel_timestamp_gate": identity_valid,
    "kernel_to_alert_seconds": latency.get("kernel_to_alert_seconds"),
    "latency_target_observed_on_detected_subset": p99 is not None and p99 <= 2.0,
    "all_current_run_trials_detected": detected == expected,
    "all_pilot_lineage_trials_detected": lineage_detected == lineage_expected,
    "pilot_engineering_pass": bool(identity_valid and lineage_detected == lineage_expected and p99 is not None and p99 <= 2.0),
    "latency_report_sha256": hashlib.sha256((root / "LATENCY_REPORT.json").read_bytes()).hexdigest(),
}
(root / "PILOT_RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
PY

(
  cd "$EVIDENCE_ROOT"
  sha256sum BLIND_START.json PILOT_PLAN.json PLAN.json REPORT.json PILOT_COMPLETE \
    injections.jsonl kernel-events.jsonl LATENCY_REPORT.json \
    DISTRIBUTED_INJECTIONS.json PILOT_RESULT.json workers.txt \
    START_SHA256SUMS RAW_SHA256SUMS
) >"$EVIDENCE_ROOT/FINAL_SHA256SUMS"
(cd "$EVIDENCE_ROOT" && sha256sum -c FINAL_SHA256SUMS)
rm -f "$EVIDENCE_ROOT/ACTIVE" "$EVIDENCE_ROOT/FINALIZE_FAILED"
chmod 0444 "$EVIDENCE_ROOT"/*.json "$EVIDENCE_ROOT"/*.jsonl \
  "$EVIDENCE_ROOT"/*SHA256SUMS "$EVIDENCE_ROOT/PILOT_COMPLETE"
complete=true
printf 'Attack-latency pilot finalized: evidence=%s evaluation_rc=%s\n' "$EVIDENCE_ROOT" "$evaluation_rc"
