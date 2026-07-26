#!/usr/bin/env bash
# Capture an immutable high-concurrency normal phase for model retraining.
set -Eeuo pipefail

cd /home/dat/ml-service
export KUBECONFIG=/home/dat/.kube/config

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
output="training_data_wrk-${stamp}"
wrk_pid=""

cleanup() {
  if [[ -n "$wrk_pid" ]]; then
    kill "$wrk_pid" >/dev/null 2>&1 || true
    wait "$wrk_pid" >/dev/null 2>&1 || true
  fi
  chown -R dat:dat "$output" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Keep the existing low-rate load generators active and add the paper's c50
# HTTP regime. No attack generator runs during this collection.
wrk -t4 -c50 -d420s --latency http://10.103.40.121/ \
  >"/tmp/sentinel-wrk-baseline-${stamp}.log" 2>&1 &
wrk_pid=$!

COLLECT_MINUTES=7 \
WINDOW_SECONDS=30 \
MIN_EVENTS=100 \
MIN_WINDOWS=10 \
MAX_WINDOWS_PER_TARGET=10 \
MIN_COLLECT_MINUTES=0 \
BASELINE_PHASE=wrk-c50 \
BASELINE_TARGETS=production/nginx \
TRAINING_OUTPUT_DIR="$output" \
  /home/dat/ml-venv/bin/python collect_real_baseline.py

cleanup
trap - EXIT INT TERM
echo "$output"
