#!/usr/bin/env bash
# Replace the single-trial lifecycle phase of a rejected candidate with an
# independent, repeated lifecycle capture. The script trains an isolated
# candidate and never validates, promotes, or restarts the production detector.
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
LIFECYCLE_WINDOWS=${LOW_LATENCY_LIFECYCLE_WINDOWS:-64}
LIFECYCLE_CYCLES=${LOW_LATENCY_LIFECYCLE_CYCLES:-4}
LIFECYCLE_SPACING_SECONDS=${LOW_LATENCY_LIFECYCLE_SPACING_SECONDS:-20}
MIN_EVENTS=${LOW_LATENCY_MIN_EVENTS:-20}
COLLECT_MINUTES=${LOW_LATENCY_LIFECYCLE_COLLECT_MINUTES:-14}
STAMP=${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
TARGETS=default/postgres,production/nginx,production/redis
LIFECYCLE_DIR=${LOW_LATENCY_LIFECYCLE_DIR:-"${BASE_PREFIX}-lifecycle-repeated-${STAMP}"}
DATASET_DIR=${LOW_LATENCY_DATASET_DIR:-"training_data_low_latency_repaired_dataset-${STAMP}"}
CANDIDATE_DIR=${LOW_LATENCY_CANDIDATE_DIR:-"models_low_latency_repaired_candidate-${STAMP}"}
VOCAB=${SENTINEL_VOCAB:-models/vocab.pkl}
POLICY=${SENTINEL_POLICY:-tetragon-targeted-policies.yaml}
LOADGEN_MANIFEST=${SENTINEL_LOADGEN_MANIFEST:-production-loadgens.yaml}
collector_pid=""

cd "$ROOT_DIR"
[[ "$WINDOW_SECONDS" -ge 5 && "$LIFECYCLE_WINDOWS" -ge 60 ]] || {
  printf 'window must be >=5 seconds and lifecycle capture >=60 windows\n' >&2
  exit 2
}
[[ "$LIFECYCLE_CYCLES" -ge 3 ]] || {
  printf 'need at least three independent lifecycle cycles\n' >&2
  exit 2
}
for phase in normal-1x in-cluster-burst high-mixed recovery-1x; do
  [[ -r "${BASE_PREFIX}-${phase}/collection_manifest.json" ]] || {
    printf 'missing source phase: %s\n' "${BASE_PREFIX}-${phase}" >&2
    exit 3
  }
done
[[ -r "$VOCAB" && -r "$POLICY" && -r "$LOADGEN_MANIFEST" ]] || {
  printf 'missing vocabulary, policy, or load-generator manifest\n' >&2
  exit 3
}

cleanup() {
  if [[ -n "$collector_pid" ]] && kill -0 "$collector_pid" 2>/dev/null; then
    kill -TERM "$collector_pid" 2>/dev/null || true
    wait "$collector_pid" 2>/dev/null || true
  fi
  kubectl scale deployment/loadgen deployment/redis-loadgen -n production \
    --replicas=1 >/dev/null 2>&1 || true
  kubectl scale deployment/postgres-loadgen -n default --replicas=1 \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

coverage=$(kubectl -n kube-system get daemonset tetragon \
  -o jsonpath='{.status.desiredNumberScheduled},{.status.numberReady},{.status.numberAvailable}')
IFS=',' read -r desired ready available <<<"$coverage"
[[ "$desired" =~ ^[0-9]+$ && "$desired" -gt 0 && "$ready" == "$desired" && "$available" == "$desired" ]] || {
  printf 'refusing collection: Tetragon coverage desired=%s ready=%s available=%s\n' \
    "$desired" "$ready" "$available" >&2
  exit 8
}

kubectl scale deployment/loadgen deployment/redis-loadgen -n production --replicas=1 >/dev/null
kubectl scale deployment/postgres-loadgen -n default --replicas=1 >/dev/null

COLLECT_MINUTES="$COLLECT_MINUTES" MIN_COLLECT_MINUTES=0 \
WINDOW_SECONDS="$WINDOW_SECONDS" MIN_EVENTS="$MIN_EVENTS" \
MIN_WINDOWS="$LIFECYCLE_WINDOWS" MAX_WINDOWS_PER_TARGET="$LIFECYCLE_WINDOWS" \
BASELINE_PHASE=lifecycle-repeated BASELINE_TARGETS="$TARGETS" \
TRAINING_OUTPUT_DIR="$LIFECYCLE_DIR" SENTINEL_VOCAB="$VOCAB" \
SENTINEL_POLICY="$POLICY" SENTINEL_LOADGEN_MANIFEST="$LOADGEN_MANIFEST" \
SENTINEL_REQUIRE_FULL_TETRAGON_COVERAGE=true \
SENTINEL_TETRAGON_DAEMONSET=tetragon \
  "$PYTHON_BIN" collect_real_baseline.py &
collector_pid=$!

sleep "$WINDOW_SECONDS"
for cycle in $(seq 1 "$LIFECYCLE_CYCLES"); do
  printf 'repeated lifecycle cycle %s/%s\n' "$cycle" "$LIFECYCLE_CYCLES"
  for target in production/nginx production/redis default/postgres; do
    namespace=${target%%/*}
    deployment=${target##*/}
    kubectl rollout restart "deployment/$deployment" -n "$namespace" >/dev/null
    kubectl rollout status "deployment/$deployment" -n "$namespace" \
      --timeout=180s >/dev/null
    sleep "$LIFECYCLE_SPACING_SECONDS"
  done
done
wait "$collector_pid"
collector_pid=""

"$PYTHON_BIN" build_phase_dataset.py \
  "${BASE_PREFIX}-normal-1x" "${BASE_PREFIX}-in-cluster-burst" \
  "${BASE_PREFIX}-high-mixed" "${BASE_PREFIX}-recovery-1x" \
  "$LIFECYCLE_DIR" --output "$DATASET_DIR" \
  --minimum-events "$MIN_EVENTS" --minimum-phase-windows 30 \
  --policy "$POLICY" --vocab "$VOCAB" --targets "$TARGETS"

"$PYTHON_BIN" train_candidate.py \
  --training-dir "$DATASET_DIR" --model-dir "$CANDIDATE_DIR" \
  --vocab "$DATASET_DIR/vocab.pkl" --targets "$TARGETS"

printf 'repaired_candidate=%s\n' "$CANDIDATE_DIR"
printf 'Not promoted. Run normal and kernel attack matrices first.\n'
