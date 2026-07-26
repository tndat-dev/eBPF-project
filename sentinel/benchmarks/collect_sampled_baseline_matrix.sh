#!/usr/bin/env bash
# Collect balanced normal windows after applying the rate-limited policy.
set -Eeuo pipefail

cd /home/dat/ml-service
export KUBECONFIG=/home/dat/.kube/config

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
prefix="training_data_sampled-${stamp}"
wrk_pid=""
collector_pid=""
vocab_path="${SAMPLED_VOCAB_PATH:-models/vocab.pkl}"
windows_per_phase="${SAMPLED_WINDOWS_PER_PHASE:-25}"
collect_minutes="$((windows_per_phase / 2 + 4))"
wrk_seconds="$((windows_per_phase * 30 + 90))"

if (( windows_per_phase < 10 )); then
  echo "SAMPLED_WINDOWS_PER_PHASE must be >= 10" >&2
  exit 2
fi
[[ -f "$vocab_path" ]] || {
  echo "sampling vocabulary not found: $vocab_path" >&2
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

stop_wrk() {
  if [[ -n "$wrk_pid" ]]; then
    kill "$wrk_pid" >/dev/null 2>&1 || true
    wait "$wrk_pid" >/dev/null 2>&1 || true
    wrk_pid=""
  fi
}

cleanup() {
  if [[ -n "$collector_pid" ]]; then
    kill -TERM "$collector_pid" >/dev/null 2>&1 || true
    wait "$collector_pid" >/dev/null 2>&1 || true
    collector_pid=""
  fi
  stop_wrk
  scale_load 1 1 1 || true
  chown -R dat:dat "${prefix}"-* >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

collect_phase() {
  local phase="$1"
  local output="${prefix}-${phase}"
  echo "COLLECT_PHASE ${phase} -> ${output}"
  COLLECT_MINUTES="$collect_minutes" \
  WINDOW_SECONDS=30 \
  MIN_EVENTS=20 \
  MIN_WINDOWS="$windows_per_phase" \
  MAX_WINDOWS_PER_TARGET="$windows_per_phase" \
  MIN_COLLECT_MINUTES=0 \
  SENTINEL_VOCAB="$vocab_path" \
  SENTINEL_POLICY="$PWD/tetragon-targeted-policies.yaml" \
  SENTINEL_LOADGEN_MANIFEST="$PWD/production-loadgens.yaml" \
  BASELINE_PHASE="$phase" \
  TRAINING_OUTPUT_DIR="$output" \
    /home/dat/ml-venv/bin/python collect_real_baseline.py &
  collector_pid=$!
  wait "$collector_pid"
  collector_pid=""
}

if systemctl is-active --quiet sentinel-detector.service; then
  echo "sentinel-detector must be stopped during baseline collection" >&2
  exit 4
fi

scale_load 1 1 1
collect_phase normal-1x

wrk -t4 -c50 -d"${wrk_seconds}s" --latency http://10.103.40.121/ \
  >"/tmp/sentinel-sampled-wrk-${stamp}.log" 2>&1 &
wrk_pid=$!
collect_phase wrk-c50
stop_wrk

scale_load 4 2 3
collect_phase high-mixed

scale_load 1 1 1
collect_phase recovery-1x

cleanup
trap - EXIT INT TERM
echo "SAMPLED_BASELINE_COMPLETE ${prefix}"
