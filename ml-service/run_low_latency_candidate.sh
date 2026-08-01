#!/usr/bin/env bash
# Build a 10-second-window candidate from real, multi-regime traffic.
# This script never promotes the candidate or changes sentinel-detector.service.
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ -z ${PYTHON_BIN:-} ]]; then
  if [[ -x /home/dat/ml-venv/bin/python ]]; then
    PYTHON_BIN=/home/dat/ml-venv/bin/python
  else
    PYTHON_BIN=python3
  fi
fi
WINDOW_SECONDS=${LOW_LATENCY_WINDOW_SECONDS:-10}
WINDOWS_PER_PHASE=${LOW_LATENCY_WINDOWS_PER_PHASE:-32}
MIN_EVENTS=${LOW_LATENCY_MIN_EVENTS:-20}
COLLECT_MINUTES=${LOW_LATENCY_COLLECT_MINUTES:-8}
INCLUDE_LIFECYCLE_PHASE=${LOW_LATENCY_INCLUDE_LIFECYCLE:-1}
LIFECYCLE_CYCLES=${LOW_LATENCY_LIFECYCLE_CYCLES:-3}
LIFECYCLE_SPACING_SECONDS=${LOW_LATENCY_LIFECYCLE_SPACING_SECONDS:-15}
# The API host cannot reliably route to a ClusterIP.  Generate the burst from
# a workload pod so this phase always measures the same in-cluster data path.
NGINX_URL=${LOW_LATENCY_NGINX_URL:-http://nginx.production.svc.cluster.local/}
STAMP=${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
TARGETS=default/postgres,production/nginx,production/redis
PREFIX=${LOW_LATENCY_PREFIX:-"training_data_low_latency-${STAMP}"}
DATASET_DIR=${LOW_LATENCY_DATASET_DIR:-"training_data_low_latency_dataset-${STAMP}"}
CANDIDATE_DIR=${LOW_LATENCY_CANDIDATE_DIR:-"models_low_latency_candidate-${STAMP}"}
VOCAB=${SENTINEL_VOCAB:-models/vocab.pkl}
POLICY=${SENTINEL_POLICY:-tetragon-targeted-policies.yaml}
LOADGEN_MANIFEST=${SENTINEL_LOADGEN_MANIFEST:-production-loadgens.yaml}
traffic_pid=""

cd "$ROOT_DIR"
[[ "$WINDOW_SECONDS" -ge 5 ]] || { printf 'window must be >= 5 seconds\n' >&2; exit 2; }
[[ "$WINDOWS_PER_PHASE" -ge 30 ]] || { printf 'need >= 30 windows per phase\n' >&2; exit 2; }
[[ "$LIFECYCLE_CYCLES" -ge 2 ]] || { printf 'need >= 2 lifecycle cycles\n' >&2; exit 2; }
[[ -r "$VOCAB" && -r "$POLICY" && -r "$LOADGEN_MANIFEST" ]] || {
  printf 'missing vocabulary, policy, or load-generator manifest\n' >&2; exit 3;
}

require_tetragon_coverage() {
  local coverage desired ready available
  coverage=$(kubectl -n kube-system get daemonset tetragon \
    -o jsonpath='{.status.desiredNumberScheduled},{.status.numberReady},{.status.numberAvailable}') || {
    printf 'refusing collection: cannot read Tetragon DaemonSet status\n' >&2
    exit 8
  }
  IFS=',' read -r desired ready available <<<"$coverage"
  [[ "$desired" =~ ^[0-9]+$ && "$desired" -gt 0 && "$ready" == "$desired" && "$available" == "$desired" ]] || {
    printf 'refusing collection: Tetragon coverage is desired=%s ready=%s available=%s\n' \
      "$desired" "$ready" "$available" >&2
    exit 8
  }
}

require_tetragon_coverage

scale_load() {
  kubectl scale deployment/loadgen -n production --replicas="$1" >/dev/null
  kubectl scale deployment/redis-loadgen -n production --replicas="$2" >/dev/null
  kubectl scale deployment/postgres-loadgen -n default --replicas="$3" >/dev/null
  kubectl rollout status deployment/loadgen -n production --timeout=90s >/dev/null
  kubectl rollout status deployment/redis-loadgen -n production --timeout=90s >/dev/null
  kubectl rollout status deployment/postgres-loadgen -n default --timeout=90s >/dev/null
}

stop_in_cluster_burst() {
  if [[ -n "$traffic_pid" ]]; then
    kill "$traffic_pid" >/dev/null 2>&1 || true
    wait "$traffic_pid" >/dev/null 2>&1 || true
    traffic_pid=""
  fi
}

start_in_cluster_burst() {
  local duration_seconds="$1" pod remote_script
  pod=$(kubectl -n production get pod -l app=loadgen \
    -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}' \
    | awk '{print $1}')
  [[ -n "$pod" ]] || { printf 'no running production/loadgen pod\n' >&2; return 1; }
  printf -v remote_script 'end=$(( $(date +%%s) + %q )); url=%q; worker() { while [ "$(date +%%s)" -lt "$end" ]; do wget -q -O /dev/null "$url" || true; done; }; worker & worker & worker & worker & wait' \
    "$duration_seconds" "$NGINX_URL"
  kubectl -n production exec "$pod" -- sh -c "$remote_script" \
    >"/tmp/sentinel-low-latency-burst-${STAMP}.log" 2>&1 &
  traffic_pid=$!
}

cleanup() {
  stop_in_cluster_burst
  scale_load 1 1 1 || true
}
trap cleanup EXIT INT TERM

collect_phase() {
  local phase="$1"
  local output="${PREFIX}-${phase}"
  printf 'collecting %s (%ss windows) -> %s\n' "$phase" "$WINDOW_SECONDS" "$output"
  COLLECT_MINUTES="$COLLECT_MINUTES" \
  MIN_COLLECT_MINUTES=0 \
  WINDOW_SECONDS="$WINDOW_SECONDS" \
  MIN_EVENTS="$MIN_EVENTS" \
  MIN_WINDOWS=30 \
  MAX_WINDOWS_PER_TARGET="$WINDOWS_PER_PHASE" \
  BASELINE_PHASE="$phase" \
  BASELINE_TARGETS="$TARGETS" \
  TRAINING_OUTPUT_DIR="$output" \
  SENTINEL_VOCAB="$VOCAB" \
  SENTINEL_POLICY="$POLICY" \
  SENTINEL_LOADGEN_MANIFEST="$LOADGEN_MANIFEST" \
  SENTINEL_REQUIRE_FULL_TETRAGON_COVERAGE=true \
  SENTINEL_TETRAGON_DAEMONSET=tetragon \
    "$PYTHON_BIN" collect_real_baseline.py
}

collect_lifecycle_phase() {
  # A production baseline must include benign pod lifecycle activity. A
  # steady-state-only model can otherwise score a normal entrypoint/restart as
  # anomalous. Roll each disposable evaluation workload serially.
  collect_phase lifecycle &
  local collector_pid=$!
  sleep "$WINDOW_SECONDS"
  local cycle
  for cycle in $(seq 1 "$LIFECYCLE_CYCLES"); do
    printf 'lifecycle cycle %s/%s\n' "$cycle" "$LIFECYCLE_CYCLES"
    kubectl rollout restart deployment/nginx -n production >/dev/null
    kubectl rollout status deployment/nginx -n production --timeout=180s >/dev/null
    sleep "$LIFECYCLE_SPACING_SECONDS"
    kubectl rollout restart deployment/redis -n production >/dev/null
    kubectl rollout status deployment/redis -n production --timeout=180s >/dev/null
    sleep "$LIFECYCLE_SPACING_SECONDS"
    kubectl rollout restart deployment/postgres -n default >/dev/null
    kubectl rollout status deployment/postgres -n default --timeout=180s >/dev/null
    sleep "$LIFECYCLE_SPACING_SECONDS"
  done
  wait "$collector_pid"
}

scale_load 1 1 1
collect_phase normal-1x

start_in_cluster_burst "$((COLLECT_MINUTES * 60 + 30))"
collect_phase in-cluster-burst
stop_in_cluster_burst

scale_load 4 2 3
collect_phase high-mixed

scale_load 1 1 1
collect_phase recovery-1x

if [[ "$INCLUDE_LIFECYCLE_PHASE" == "1" ]]; then
  scale_load 1 1 1
  collect_lifecycle_phase
fi

PHASES=("${PREFIX}-normal-1x" "${PREFIX}-in-cluster-burst" \
  "${PREFIX}-high-mixed" "${PREFIX}-recovery-1x")
if [[ "$INCLUDE_LIFECYCLE_PHASE" == "1" ]]; then
  PHASES+=("${PREFIX}-lifecycle")
fi

"$PYTHON_BIN" build_phase_dataset.py "${PHASES[@]}" \
  --output "$DATASET_DIR" \
  --minimum-events "$MIN_EVENTS" \
  --minimum-phase-windows 30 \
  --policy "$POLICY" --vocab "$VOCAB" --targets "$TARGETS"

"$PYTHON_BIN" train_candidate.py \
  --training-dir "$DATASET_DIR" --model-dir "$CANDIDATE_DIR" \
  --vocab "$DATASET_DIR/vocab.pkl" --targets "$TARGETS"

printf 'candidate=%s\n' "$CANDIDATE_DIR"
printf 'Not promoted. Run normal matrix and kernel attack matrix with --window %s first.\n' "$WINDOW_SECONDS"
