#!/usr/bin/env bash
# Recollect the repeated lifecycle phase with immutable pod-age provenance,
# rebuild the nine-phase candidate, and stop before any validation/promotion.
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE_PREFIX=${1:?usage: $0 <pre-lifecycle-prefix> <post-lifecycle-prefix>}
POST_PREFIX=${2:?usage: $0 <pre-lifecycle-prefix> <post-lifecycle-prefix>}
if [[ -z ${KUBECONFIG:-} && -r /home/dat/.kube/sentinel-ha.conf ]]; then
  export KUBECONFIG=/home/dat/.kube/sentinel-ha.conf
fi
if [[ -z ${PYTHON_BIN:-} ]]; then
  PYTHON_BIN=$([[ -x /home/dat/ml-venv/bin/python ]] \
    && printf /home/dat/ml-venv/bin/python || printf python3)
fi

WINDOW_SECONDS=${LOW_LATENCY_WINDOW_SECONDS:-10}
LIFECYCLE_WINDOWS=${LOW_LATENCY_LIFECYCLE_WINDOWS:-64}
LIFECYCLE_CYCLES=${LOW_LATENCY_LIFECYCLE_CYCLES:-4}
LIFECYCLE_SPACING_SECONDS=${LOW_LATENCY_LIFECYCLE_SPACING_SECONDS:-20}
COLLECT_MINUTES=${LOW_LATENCY_LIFECYCLE_COLLECT_MINUTES:-14}
MIN_EVENTS=${LOW_LATENCY_MIN_EVENTS:-20}
STARTUP_GRACE_SECONDS=${SENTINEL_POD_STARTUP_GRACE_SECONDS:-60}
STAMP=${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
TARGETS=default/postgres,production/nginx,production/redis
LIFECYCLE_DIR=${LOW_LATENCY_LIFECYCLE_DIR:-"training_data_lifecycle_provenance-${STAMP}"}
DATASET_DIR=${LOW_LATENCY_DATASET_DIR:-"training_data_startup_aligned_dataset-${STAMP}"}
CANDIDATE_DIR=${LOW_LATENCY_CANDIDATE_DIR:-"models_startup_aligned_candidate-${STAMP}"}
VOCAB=${SENTINEL_VOCAB:-models/vocab.pkl}
POLICY=${SENTINEL_POLICY:-tetragon-targeted-policies.yaml}
LOADGEN_MANIFEST=${SENTINEL_LOADGEN_MANIFEST:-production-loadgens.yaml}
collector_pid=""

cd "$ROOT_DIR"
[[ "$WINDOW_SECONDS" -ge 5 && "$LIFECYCLE_WINDOWS" -ge 60 ]] || exit 2
[[ "$LIFECYCLE_CYCLES" -ge 3 ]] || exit 2
kubectl get validatingadmissionpolicy sentinel-experiment-resource-lock >/dev/null
kubectl get validatingadmissionpolicybinding sentinel-experiment-resource-lock >/dev/null
kubectl get --raw=/readyz >/dev/null
coverage=$(kubectl -n kube-system get daemonset tetragon \
  -o jsonpath='{.status.desiredNumberScheduled},{.status.numberReady},{.status.numberAvailable}')
[[ "$coverage" == "6,6,6" ]] || {
  printf 'Tetragon coverage is not 6/6/6: %s\n' "$coverage" >&2
  exit 8
}
for prefix in "$BASE_PREFIX" "$POST_PREFIX"; do
  for phase in normal-1x in-cluster-burst high-mixed recovery-1x; do
    [[ -r "${prefix}-${phase}/collection_manifest.json" ]] || {
      printf 'missing source phase: %s\n' "${prefix}-${phase}" >&2
      exit 3
    }
  done
done
for artifact in "$VOCAB" "$POLICY" "$LOADGEN_MANIFEST"; do
  [[ -r "$artifact" ]] || { printf 'missing artifact: %s\n' "$artifact" >&2; exit 3; }
done

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

kubectl scale deployment/loadgen deployment/redis-loadgen -n production --replicas=1 >/dev/null
kubectl scale deployment/postgres-loadgen -n default --replicas=1 >/dev/null

COLLECT_MINUTES="$COLLECT_MINUTES" MIN_COLLECT_MINUTES=0 \
WINDOW_SECONDS="$WINDOW_SECONDS" MIN_EVENTS="$MIN_EVENTS" \
MIN_WINDOWS="$LIFECYCLE_WINDOWS" MAX_WINDOWS_PER_TARGET="$LIFECYCLE_WINDOWS" \
BASELINE_PHASE=lifecycle-repeated-startup-provenance BASELINE_TARGETS="$TARGETS" \
TRAINING_OUTPUT_DIR="$LIFECYCLE_DIR" SENTINEL_VOCAB="$VOCAB" \
SENTINEL_POLICY="$POLICY" SENTINEL_LOADGEN_MANIFEST="$LOADGEN_MANIFEST" \
SENTINEL_POD_STARTUP_GRACE_SECONDS="$STARTUP_GRACE_SECONDS" \
SENTINEL_REQUIRE_FULL_TETRAGON_COVERAGE=true SENTINEL_TETRAGON_DAEMONSET=tetragon \
  "$PYTHON_BIN" collect_real_baseline.py &
collector_pid=$!

sleep "$WINDOW_SECONDS"
for cycle in $(seq 1 "$LIFECYCLE_CYCLES"); do
  printf 'lifecycle provenance cycle %s/%s\n' "$cycle" "$LIFECYCLE_CYCLES"
  for target in production/nginx production/redis default/postgres; do
    namespace=${target%%/*}
    deployment=${target##*/}
    kubectl rollout restart "deployment/$deployment" -n "$namespace" >/dev/null
    kubectl rollout status "deployment/$deployment" -n "$namespace" --timeout=180s >/dev/null
    sleep "$LIFECYCLE_SPACING_SECONDS"
  done
done
wait "$collector_pid"
collector_pid=""

"$PYTHON_BIN" build_phase_dataset.py \
  "${BASE_PREFIX}-normal-1x" "${BASE_PREFIX}-in-cluster-burst" \
  "${BASE_PREFIX}-high-mixed" "${BASE_PREFIX}-recovery-1x" \
  "$LIFECYCLE_DIR" \
  "${POST_PREFIX}-normal-1x" "${POST_PREFIX}-in-cluster-burst" \
  "${POST_PREFIX}-high-mixed" "${POST_PREFIX}-recovery-1x" \
  --output "$DATASET_DIR" --minimum-events "$MIN_EVENTS" \
  --minimum-phase-windows 30 --policy "$POLICY" --vocab "$VOCAB" \
  --targets "$TARGETS" --startup-grace-seconds "$STARTUP_GRACE_SECONDS"

"$PYTHON_BIN" - "$DATASET_DIR/phase_dataset_manifest.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
redis = manifest["targets"]["production/redis"]["startup_grace"]
if redis["train_count"] < 1 or redis["validation_count"] < 1:
    raise SystemExit("Redis startup provenance did not reach both dataset splits")
PY

set +e
"$PYTHON_BIN" train_candidate.py \
  --training-dir "$DATASET_DIR" --model-dir "$CANDIDATE_DIR" \
  --vocab "$DATASET_DIR/vocab.pkl" --targets "$TARGETS"
train_rc=$?
set -e
printf 'lifecycle_dir=%s\ndataset=%s\ncandidate=%s\ntrain_exit=%s\n' \
  "$LIFECYCLE_DIR" "$DATASET_DIR" "$CANDIDATE_DIR" "$train_rc"
exit "$train_rc"
