#!/usr/bin/env bash
# Collect/train an isolated AIMS syscall candidate. This script never promotes.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ACTION=${1:-help}
shift || true
PYTHON_BIN=${PYTHON_BIN:-/home/dat/ml-venv/bin/python}
[[ -x "$PYTHON_BIN" ]] || PYTHON_BIN=${PYTHON_BIN_FALLBACK:-python3}
CONTRACT=${AIMS_CONTRACT:-"$ROOT_DIR/aims_release_contract.json"}
SPLIT_CONTRACT=${AIMS_SPLIT_CONTRACT:-"$ROOT_DIR/aims_candidate_split_contract.json"}
DEFAULT_POLICY="$ROOT_DIR/tetragon-aims-policies.yaml"
[[ -r "$DEFAULT_POLICY" ]] || DEFAULT_POLICY="$ROOT_DIR/../sentinel/k8s/tetragon-aims-policies.yaml"
DEFAULT_LOADGEN="$ROOT_DIR/aims-sentinel-loadgen.yaml"
[[ -r "$DEFAULT_LOADGEN" ]] || DEFAULT_LOADGEN="$ROOT_DIR/../sentinel/k8s/aims-sentinel-loadgen.yaml"
POLICY=${SENTINEL_POLICY:-"$DEFAULT_POLICY"}
LOADGEN_MANIFEST=${SENTINEL_LOADGEN_MANIFEST:-"$DEFAULT_LOADGEN"}
VOCAB=${SENTINEL_VOCAB:-"$ROOT_DIR/models/vocab.pkl"}

read_contract() {
  "$PYTHON_BIN" - "$CONTRACT" "$1" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if sys.argv[2] == "targets":
    print(",".join(doc["eligible_targets"]))
elif sys.argv[2] == "minimum_events":
    print(doc["minimum_events_per_window"])
elif sys.argv[2] == "window_seconds":
    print(doc["window_seconds"])
PY
}

TARGETS=${AIMS_TARGETS:-$(read_contract targets)}
MIN_EVENTS=${MIN_EVENTS:-$(read_contract minimum_events)}
WINDOW_SECONDS=${WINDOW_SECONDS:-$(read_contract window_seconds)}

require_artifacts() {
  local path
  for path in "$CONTRACT" "$SPLIT_CONTRACT" "$POLICY" "$LOADGEN_MANIFEST" "$VOCAB"; do
    [[ -r "$path" ]] || { printf 'missing experiment artifact: %s\n' "$path" >&2; exit 2; }
  done
}

case "$ACTION" in
  collect)
    require_artifacts
    phase=${1:?usage: run_aims_candidate.sh collect PHASE [MINUTES] [OUTPUT_DIR]}
    minutes=${2:-72}
    output=${3:-"$ROOT_DIR/training_data_aims_${phase}-$(date -u +%Y%m%dT%H%M%SZ)"}
    BASELINE_TARGETS="$TARGETS" BASELINE_PHASE="$phase" \
      COLLECT_MINUTES="$minutes" MIN_COLLECT_MINUTES="$minutes" \
      WINDOW_SECONDS="$WINDOW_SECONDS" MIN_EVENTS="$MIN_EVENTS" \
      MIN_WINDOWS=${MIN_WINDOWS:-30} MAX_WINDOWS_PER_TARGET=${MAX_WINDOWS_PER_TARGET:-0} \
      TRAINING_OUTPUT_DIR="$output" SENTINEL_VOCAB="$VOCAB" \
      SENTINEL_POLICY="$POLICY" SENTINEL_LOADGEN_MANIFEST="$LOADGEN_MANIFEST" \
      SENTINEL_REQUIRE_FULL_TETRAGON_COVERAGE=true \
      SENTINEL_TETRAGON_DAEMONSET=tetragon \
      "$PYTHON_BIN" "$ROOT_DIR/collect_real_baseline.py"
    ;;
  build)
    require_artifacts
    output=${AIMS_DATASET_DIR:-"$ROOT_DIR/training_data_aims_candidate-$(date -u +%Y%m%dT%H%M%SZ)"}
    (( $# >= 4 )) || { printf 'build requires at least four independent phase directories\n' >&2; exit 2; }
    "$PYTHON_BIN" "$ROOT_DIR/build_phase_dataset.py" "$@" \
      --output "$output" --minimum-events "$MIN_EVENTS" \
      --minimum-phase-windows ${MIN_PHASE_WINDOWS:-30} \
      --policy "$POLICY" --vocab "$VOCAB" --targets "$TARGETS" \
      --experiment-contract "$SPLIT_CONTRACT" --dataset-role candidate_fit \
      --parent-release-contract "$CONTRACT"
    printf 'immutable AIMS dataset: %s\n' "$output"
    ;;
  train)
    dataset=${1:?usage: run_aims_candidate.sh train DATASET_DIR [CANDIDATE_DIR]}
    candidate=${2:-"$ROOT_DIR/models_aims_candidate-$(date -u +%Y%m%dT%H%M%SZ)"}
    "$PYTHON_BIN" "$ROOT_DIR/train_candidate.py" \
      --training-dir "$dataset" --model-dir "$candidate" \
      --vocab "$dataset/vocab.pkl" --targets "$TARGETS"
    printf 'candidate created but NOT promoted: %s\n' "$candidate"
    ;;
  *)
    printf '%s\n' \
      'usage:' \
      '  run_aims_candidate.sh collect PHASE [MINUTES] [OUTPUT_DIR]' \
      '  run_aims_candidate.sh build PHASE_DIR PHASE_DIR PHASE_DIR PHASE_DIR [...]' \
      '  run_aims_candidate.sh train DATASET_DIR [CANDIDATE_DIR]'
    ;;
esac
