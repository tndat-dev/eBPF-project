#!/usr/bin/env bash
# Capture a long real normal soak so periodic database/Redis modes enter train.
set -Eeuo pipefail

cd /home/dat/ml-service
export KUBECONFIG=/home/dat/.kube/config

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
output="training_data_soak-${stamp}"

cleanup() {
  chown -R dat:dat "$output" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

COLLECT_MINUTES=35 \
WINDOW_SECONDS=30 \
MIN_EVENTS=100 \
MIN_WINDOWS=60 \
MAX_WINDOWS_PER_TARGET=60 \
MIN_COLLECT_MINUTES=0 \
BASELINE_PHASE=normal-long-soak \
BASELINE_TARGETS=default/postgres,production/redis \
TRAINING_OUTPUT_DIR="$output" \
  /home/dat/ml-venv/bin/python collect_real_baseline.py

cleanup
trap - EXIT INT TERM
echo "$output"
