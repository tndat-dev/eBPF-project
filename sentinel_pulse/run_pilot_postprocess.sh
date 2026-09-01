#!/usr/bin/env bash
set -Eeuo pipefail

: "${CAMPAIGN_PID:?CAMPAIGN_PID is required}"
: "${EVIDENCE_ROOT:?EVIDENCE_ROOT is required}"
: "${TRAINING_ROOT:?TRAINING_ROOT is required}"
: "${SOURCE_ROOT:?SOURCE_ROOT is required}"

WAIT_INTERVAL_SECONDS=${WAIT_INTERVAL_SECONDS:-15}
PYTHON=${PYTHON:-/home/dat/ml-venv/bin/python}
BLIND_CONTRACT=${BLIND_CONTRACT:-$SOURCE_ROOT/sentinel_pulse/protocol/blind-attack-contract.json}
BENCHMARK_POLICY=${BENCHMARK_POLICY:-$SOURCE_ROOT/sentinel_pulse/protocol/decision-policy-semantic-v1.json}
CANDIDATE_ID=${CANDIDATE_ID:-sentinel-pulse-500ms-candidate-a2-pilot}
EVIDENCE_CLASS=${EVIDENCE_CLASS:-nonformal_runtime_compatibility_pilot}

[[ $WAIT_INTERVAL_SECONDS =~ ^[1-9][0-9]*$ ]]
[[ $CAMPAIGN_PID =~ ^[1-9][0-9]*$ ]]
[[ ! -e $TRAINING_ROOT ]]
mkdir -p "$TRAINING_ROOT"

failure() {
  local rc=$?
  trap - ERR
  printf 'failed_at=%s\nexit_code=%s\nline=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$rc" "${BASH_LINENO[0]:-unknown}" \
    > "$TRAINING_ROOT/FAILED.txt"
  chmod 0444 "$TRAINING_ROOT/FAILED.txt"
  exit "$rc"
}
trap failure ERR

while kill -0 "$CAMPAIGN_PID" 2>/dev/null; do
  sleep "$WAIT_INTERVAL_SECONDS"
done

test -f "$EVIDENCE_ROOT/COMPLETE"
test ! -e "$EVIDENCE_ROOT/FAILED.txt"
test -f "$EVIDENCE_ROOT/SHA256SUMS"
sha256sum -c "$EVIDENCE_ROOT/SHA256SUMS" \
  > "$TRAINING_ROOT/campaign-checksums.txt"
jq -e '.valid == true' "$EVIDENCE_ROOT/dataset/VALIDATION.json" >/dev/null
jq -e '
  .campaign_mode == "pilot" and
  .evidence_class == "nonformal_runtime_compatibility_pilot" and
  .automatic_model_training == false and
  .automatic_promotion == false
' "$EVIDENCE_ROOT/PROTOCOL.json" >/dev/null

cd "$SOURCE_ROOT"
dataset="$EVIDENCE_ROOT/dataset/features.jsonl"
"$PYTHON" -m sentinel_pulse.audit_calibration_coverage \
  --dataset "$dataset" \
  --history 3 \
  --alpha 0.001 \
  --window-seconds 0.5 \
  --output "$TRAINING_ROOT/calibration-coverage.json"

"$PYTHON" -m sentinel_pulse.freeze_training_contract \
  --dataset "$dataset" \
  --blind-attack-contract "$BLIND_CONTRACT" \
  --candidate-id "$CANDIDATE_ID" \
  --evidence-class "$EVIDENCE_CLASS" \
  --history 3 \
  --alpha 0.001 \
  --window-seconds 0.5 \
  --output "$TRAINING_ROOT/training-contract.json"

LOKY_MAX_CPU_COUNT=8 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
  nice -n 5 ionice -c 2 -n 5 taskset -c 0-7 \
  "$PYTHON" -m sentinel_pulse.train \
    --dataset "$dataset" \
    --blind-attack-contract "$BLIND_CONTRACT" \
    --training-contract "$TRAINING_ROOT/training-contract.json" \
    --history 3 \
    --alpha 0.001 \
    --window-seconds 0.5 \
    --output "$TRAINING_ROOT/model"

"$PYTHON" -m sentinel_pulse.calibrate_semantic_envelope \
  --dataset "$dataset" \
  --output "$TRAINING_ROOT/semantic-envelope-calibration.json"

taskset -c 0-7 "$PYTHON" -m sentinel_pulse.benchmark_inference \
  --model-dir "$TRAINING_ROOT/model" \
  --dataset "$dataset" \
  --decision-policy "$BENCHMARK_POLICY" \
  --per-workload 500 \
  --output "$TRAINING_ROOT/inference-benchmark.json"

(
  cd "$TRAINING_ROOT"
  find . -type f ! -name SHA256SUMS ! -name COMPLETE -print0 \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)
touch "$TRAINING_ROOT/COMPLETE"
chmod -R a-w "$TRAINING_ROOT"
