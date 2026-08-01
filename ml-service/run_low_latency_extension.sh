#!/usr/bin/env bash
# Extend a rejected low-latency candidate with an independent clean-normal soak.
# It never promotes a model; validation still owns every release gate.
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ -z ${PYTHON_BIN:-} ]]; then
  if [[ -x /home/dat/ml-venv/bin/python ]]; then
    PYTHON_BIN=/home/dat/ml-venv/bin/python
  else
    PYTHON_BIN=python3
  fi
fi
BASE_PREFIX=${1:?usage: $0 <existing-low-latency-prefix>}
WINDOW_SECONDS=${LOW_LATENCY_WINDOW_SECONDS:-10}
SOAK_WINDOWS=${LOW_LATENCY_SOAK_WINDOWS:-64}
MIN_EVENTS=${LOW_LATENCY_MIN_EVENTS:-20}
CONFIRMATION_FLOOR_RATIO=${LOW_LATENCY_CONFIRMATION_FLOOR_RATIO:-0.94}
BEHAVIOR_CONFIRMATION_FLOOR=${LOW_LATENCY_BEHAVIOR_CONFIRMATION_FLOOR:-0.45}
FAST_PATH_CONFIRMATION_FLOOR=${LOW_LATENCY_FAST_PATH_CONFIRMATION_FLOOR:-0.20}
POD_STARTUP_GRACE_SECONDS=${LOW_LATENCY_POD_STARTUP_GRACE_SECONDS:-60}
EXTREME_VOLUME_FACTOR=${LOW_LATENCY_EXTREME_VOLUME_FACTOR:-2.0}
STAMP=${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
TARGETS=default/postgres,production/nginx,production/redis
EXTRA_PHASE=${LOW_LATENCY_SOAK_DIR:-"${BASE_PREFIX}-normal-soak-${STAMP}"}
DATASET_DIR=${LOW_LATENCY_EXTENSION_DATASET:-"training_data_low_latency_extended_dataset-${STAMP}"}
CANDIDATE_DIR=${LOW_LATENCY_EXTENSION_CANDIDATE:-"models_low_latency_extended_candidate-${STAMP}"}
VOCAB=${SENTINEL_VOCAB:-models/vocab.pkl}
POLICY=${SENTINEL_POLICY:-tetragon-targeted-policies.yaml}
LOADGEN_MANIFEST=${SENTINEL_LOADGEN_MANIFEST:-production-loadgens.yaml}

cd "$ROOT_DIR"
[[ "$WINDOW_SECONDS" -ge 5 && "$SOAK_WINDOWS" -ge 64 ]] || {
  printf 'window must be >=5 and normal soak >=64 windows\n' >&2; exit 2;
}
for phase in normal-1x in-cluster-burst high-mixed recovery-1x lifecycle; do
  [[ -r "${BASE_PREFIX}-${phase}/collection_manifest.json" ]] || {
    printf 'missing source phase: %s\n' "${BASE_PREFIX}-${phase}" >&2; exit 3;
  }
done

scale_load() {
  kubectl scale deployment/loadgen -n production --replicas=1 >/dev/null
  kubectl scale deployment/redis-loadgen -n production --replicas=1 >/dev/null
  kubectl scale deployment/postgres-loadgen -n default --replicas=1 >/dev/null
  kubectl rollout status deployment/loadgen -n production --timeout=90s >/dev/null
  kubectl rollout status deployment/redis-loadgen -n production --timeout=90s >/dev/null
  kubectl rollout status deployment/postgres-loadgen -n default --timeout=90s >/dev/null
}

scale_load
COLLECT_MINUTES=14 MIN_COLLECT_MINUTES=0 WINDOW_SECONDS="$WINDOW_SECONDS" \
MIN_EVENTS="$MIN_EVENTS" MIN_WINDOWS="$SOAK_WINDOWS" MAX_WINDOWS_PER_TARGET="$SOAK_WINDOWS" \
BASELINE_PHASE=normal-soak BASELINE_TARGETS="$TARGETS" \
TRAINING_OUTPUT_DIR="$EXTRA_PHASE" SENTINEL_VOCAB="$VOCAB" \
SENTINEL_POLICY="$POLICY" SENTINEL_LOADGEN_MANIFEST="$LOADGEN_MANIFEST" \
SENTINEL_REQUIRE_FULL_TETRAGON_COVERAGE=true \
SENTINEL_TETRAGON_DAEMONSET=tetragon \
  "$PYTHON_BIN" collect_real_baseline.py

"$PYTHON_BIN" build_phase_dataset.py \
  "${BASE_PREFIX}-normal-1x" "${BASE_PREFIX}-in-cluster-burst" \
  "${BASE_PREFIX}-high-mixed" "${BASE_PREFIX}-recovery-1x" \
  "${BASE_PREFIX}-lifecycle" "$EXTRA_PHASE" \
  --output "$DATASET_DIR" --minimum-events "$MIN_EVENTS" \
  --minimum-phase-windows 30 --policy "$POLICY" --vocab "$VOCAB" \
  --targets "$TARGETS"

"$PYTHON_BIN" train_candidate.py \
  --training-dir "$DATASET_DIR" --model-dir "$CANDIDATE_DIR" \
  --vocab "$DATASET_DIR/vocab.pkl" --targets "$TARGETS"

LOW_LATENCY_WINDOW_SECONDS="$WINDOW_SECONDS" \
SENTINEL_CONFIRMATION_FLOOR_RATIO="$CONFIRMATION_FLOOR_RATIO" \
SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR="$BEHAVIOR_CONFIRMATION_FLOOR" \
SENTINEL_FAST_PATH_CONFIRMATION_FLOOR="$FAST_PATH_CONFIRMATION_FLOOR" \
SENTINEL_POD_STARTUP_GRACE_SECONDS="$POD_STARTUP_GRACE_SECONDS" \
SENTINEL_EXTREME_VOLUME_FACTOR="$EXTREME_VOLUME_FACTOR" \
PYTHON_BIN="$PYTHON_BIN" \
  ./run_low_latency_validation.sh "$CANDIDATE_DIR"

printf 'extended candidate validated but not promoted: %s\n' "$CANDIDATE_DIR"
