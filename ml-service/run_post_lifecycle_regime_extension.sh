#!/usr/bin/env bash
# Extend a rejected low-latency candidate with an independent post-lifecycle
# replication of every steady/load regime. This isolates temporal drift from
# threshold tuning and never promotes or restarts the production detector.
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ -z ${KUBECONFIG:-} && -r /home/dat/.kube/sentinel-ha.conf ]]; then
  export KUBECONFIG=/home/dat/.kube/sentinel-ha.conf
fi
if [[ -z ${PYTHON_BIN:-} ]]; then
  if [[ -x /home/dat/ml-venv/bin/python ]]; then
    PYTHON_BIN=/home/dat/ml-venv/bin/python
  else
    PYTHON_BIN=python3
  fi
fi
BASE_PREFIX=${1:?usage: $0 <existing-low-latency-prefix> <repeated-lifecycle-dir>}
LIFECYCLE_DIR=${2:?usage: $0 <existing-low-latency-prefix> <repeated-lifecycle-dir>}
WINDOW_SECONDS=${LOW_LATENCY_WINDOW_SECONDS:-10}
WINDOWS_PER_PHASE=${LOW_LATENCY_WINDOWS_PER_PHASE:-48}
MINIMUM_PHASE_WINDOWS=${LOW_LATENCY_MINIMUM_PHASE_WINDOWS:-40}
MIN_EVENTS=${LOW_LATENCY_MIN_EVENTS:-20}
COLLECT_MINUTES=${LOW_LATENCY_COLLECT_MINUTES:-10}
STAMP=${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
TARGETS=default/postgres,production/nginx,production/redis
PREFIX=${LOW_LATENCY_PREFIX:-"training_data_post_lifecycle-${STAMP}"}
DATASET_DIR=${LOW_LATENCY_DATASET_DIR:-"training_data_post_lifecycle_dataset-${STAMP}"}
CANDIDATE_DIR=${LOW_LATENCY_CANDIDATE_DIR:-"models_post_lifecycle_candidate-${STAMP}"}
VOCAB=${SENTINEL_VOCAB:-models/vocab.pkl}
POLICY=${SENTINEL_POLICY:-tetragon-targeted-policies.yaml}
LOADGEN_MANIFEST=${SENTINEL_LOADGEN_MANIFEST:-production-loadgens.yaml}
NGINX_URL=${LOW_LATENCY_NGINX_URL:-http://nginx.production.svc.cluster.local/}
traffic_pid=""
collector_pid=""

cd "$ROOT_DIR"
[[ "$WINDOW_SECONDS" -ge 5 && "$WINDOWS_PER_PHASE" -ge 40 \
   && "$MINIMUM_PHASE_WINDOWS" -ge 30 \
   && "$MINIMUM_PHASE_WINDOWS" -le "$WINDOWS_PER_PHASE" ]] || {
  printf 'window must be >=5 seconds and each replicated phase >=40 windows\n' >&2
  exit 2
}
for phase in normal-1x in-cluster-burst high-mixed recovery-1x; do
  [[ -r "${BASE_PREFIX}-${phase}/collection_manifest.json" ]] || {
    printf 'missing source phase: %s\n' "${BASE_PREFIX}-${phase}" >&2
    exit 3
  }
done
[[ -r "$LIFECYCLE_DIR/collection_manifest.json" ]] || {
  printf 'missing repeated lifecycle phase: %s\n' "$LIFECYCLE_DIR" >&2
  exit 3
}
[[ -r "$VOCAB" && -r "$POLICY" && -r "$LOADGEN_MANIFEST" ]] || {
  printf 'missing vocabulary, policy, or load-generator manifest\n' >&2
  exit 3
}

scale_load() {
  kubectl scale deployment/loadgen -n production --replicas="$1" >/dev/null
  kubectl scale deployment/redis-loadgen -n production --replicas="$2" >/dev/null
  kubectl scale deployment/postgres-loadgen -n default --replicas="$3" >/dev/null
  kubectl rollout status deployment/loadgen -n production --timeout=90s >/dev/null
  kubectl rollout status deployment/redis-loadgen -n production --timeout=90s >/dev/null
  kubectl rollout status deployment/postgres-loadgen -n default --timeout=90s >/dev/null
}

stop_burst() {
  if [[ -n "$traffic_pid" ]]; then
    kill "$traffic_pid" >/dev/null 2>&1 || true
    wait "$traffic_pid" >/dev/null 2>&1 || true
    traffic_pid=""
  fi
}

start_burst() {
  local duration_seconds="$1" pod remote_script
  pod=$(kubectl -n production get pod -l app=loadgen \
    -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}' \
    | awk '{print $1}')
  [[ -n "$pod" ]] || { printf 'no running production/loadgen pod\n' >&2; return 1; }
  kubectl -n production exec "$pod" -- wget -q -O /dev/null "$NGINX_URL"
  printf -v remote_script 'end=$(( $(date +%%s) + %q )); url=%q; worker() { while [ "$(date +%%s)" -lt "$end" ]; do wget -q -O /dev/null "$url" || exit 1; done; }; worker & worker & worker & worker & wait' \
    "$duration_seconds" "$NGINX_URL"
  kubectl -n production exec "$pod" -- sh -c "$remote_script" \
    >"/tmp/sentinel-post-lifecycle-burst-${STAMP}.log" 2>&1 &
  traffic_pid=$!
}

cleanup() {
  if [[ -n "$collector_pid" ]]; then
    kill "$collector_pid" >/dev/null 2>&1 || true
    wait "$collector_pid" >/dev/null 2>&1 || true
    collector_pid=""
  fi
  stop_burst
  scale_load 1 1 1 || true
}
trap cleanup EXIT INT TERM

require_runtime_targets() {
  local namespace_deployment namespace deployment ready desired
  for namespace_deployment in \
    production/nginx production/redis production/loadgen \
    production/redis-loadgen default/postgres default/postgres-loadgen; do
    namespace=${namespace_deployment%%/*}
    deployment=${namespace_deployment#*/}
    ready=$(kubectl -n "$namespace" get deployment "$deployment" \
      -o jsonpath='{.status.readyReplicas}')
    desired=$(kubectl -n "$namespace" get deployment "$deployment" \
      -o jsonpath='{.spec.replicas}')
    [[ -n "$ready" && "$ready" == "$desired" ]] || {
      printf 'runtime target %s ready=%s desired=%s\n' \
        "$namespace_deployment" "${ready:-0}" "$desired" >&2
      exit 9
    }
  done
}

require_coverage() {
  local coverage desired ready available
  coverage=$(kubectl -n kube-system get daemonset tetragon \
    -o jsonpath='{.status.desiredNumberScheduled},{.status.numberReady},{.status.numberAvailable}')
  IFS=',' read -r desired ready available <<<"$coverage"
  [[ "$desired" =~ ^[0-9]+$ && "$desired" -gt 0 && "$ready" == "$desired" && "$available" == "$desired" ]] || {
    printf 'Tetragon coverage desired=%s ready=%s available=%s\n' \
      "$desired" "$ready" "$available" >&2
    exit 8
  }
}

collect_phase() {
  local phase="$1" rc=0
  local output="${PREFIX}-${phase}"
  require_runtime_targets
  require_coverage
  printf 'collecting post-lifecycle %s -> %s\n' "$phase" "$output"
  COLLECT_MINUTES="$COLLECT_MINUTES" MIN_COLLECT_MINUTES=0 \
  WINDOW_SECONDS="$WINDOW_SECONDS" MIN_EVENTS="$MIN_EVENTS" \
  MIN_WINDOWS="$WINDOWS_PER_PHASE" MAX_WINDOWS_PER_TARGET="$WINDOWS_PER_PHASE" \
  BASELINE_PHASE="post-lifecycle-${phase}" BASELINE_TARGETS="$TARGETS" \
  TRAINING_OUTPUT_DIR="$output" SENTINEL_VOCAB="$VOCAB" \
  SENTINEL_POLICY="$POLICY" SENTINEL_LOADGEN_MANIFEST="$LOADGEN_MANIFEST" \
  SENTINEL_REQUIRE_FULL_TETRAGON_COVERAGE=true \
  SENTINEL_TETRAGON_DAEMONSET=tetragon \
    "$PYTHON_BIN" collect_real_baseline.py &
  collector_pid=$!
  wait "$collector_pid" || rc=$?
  collector_pid=""
  return "$rc"
}

scale_load 1 1 1
collect_phase normal-1x

start_burst "$((COLLECT_MINUTES * 60 + 30))"
collect_phase in-cluster-burst
stop_burst

scale_load 4 2 3
collect_phase high-mixed

scale_load 1 1 1
collect_phase recovery-1x

"$PYTHON_BIN" build_phase_dataset.py \
  "${BASE_PREFIX}-normal-1x" "${BASE_PREFIX}-in-cluster-burst" \
  "${BASE_PREFIX}-high-mixed" "${BASE_PREFIX}-recovery-1x" \
  "$LIFECYCLE_DIR" \
  "${PREFIX}-normal-1x" "${PREFIX}-in-cluster-burst" \
  "${PREFIX}-high-mixed" "${PREFIX}-recovery-1x" \
  --output "$DATASET_DIR" --minimum-events "$MIN_EVENTS" \
  --minimum-phase-windows "$MINIMUM_PHASE_WINDOWS" \
  --policy "$POLICY" --vocab "$VOCAB" \
  --targets "$TARGETS"

"$PYTHON_BIN" train_candidate.py \
  --training-dir "$DATASET_DIR" --model-dir "$CANDIDATE_DIR" \
  --vocab "$DATASET_DIR/vocab.pkl" --targets "$TARGETS"

printf 'post_lifecycle_candidate=%s\n' "$CANDIDATE_DIR"
printf 'Not promoted. Run independent normal and kernel matrices first.\n'
