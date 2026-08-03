#!/usr/bin/env bash
# Merge balanced sampled-policy phases and train an isolated V7 candidate.
set -Eeuo pipefail

cd /home/dat/ml-service

prefix="${1:?usage: $0 training_data_sampled-TIMESTAMP [extra-phase-dir ...]}"
shift
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
stratified="${prefix}-stratified-v7-${stamp}"
candidate="models_candidate_v7-${stamp}"
source_vocab="${SAMPLED_SOURCE_VOCAB:-models/vocab.pkl}"
phases=(normal-1x wrk-c50 high-mixed recovery-1x)
inputs=()

[[ -f "$source_vocab" ]] || {
  echo "source vocabulary not found: $source_vocab" >&2
  exit 2
}

for phase in "${phases[@]}"; do
  directory="${prefix}-${phase}"
  [[ -f "${directory}/collection_manifest.json" ]] || {
    echo "missing phase manifest: ${directory}" >&2
    exit 3
  }
  inputs+=("$directory")
done
for directory in "$@"; do
  [[ -f "${directory}/collection_manifest.json" ]] || {
    echo "missing extra phase manifest: ${directory}" >&2
    exit 4
  }
  inputs+=("$directory")
done

# Build the phase-balanced train/holdout directly from row-aligned metadata.
# This rejects low-volume partial windows and records policy/source hashes.
/home/dat/ml-venv/bin/python build_phase_dataset.py \
  "${inputs[@]}" --output "$stratified" \
  --minimum-events 100 --minimum-phase-windows 20 \
  --validation-fraction 0.20 --policy tetragon-targeted-policies.yaml \
  --vocab "$source_vocab"
/home/dat/ml-venv/bin/python train_candidate.py \
  --training-dir "$stratified" --model-dir "$candidate" --epochs 200 \
  --model-version 7 --vocab "$stratified/vocab.pkl"

chown -R dat:dat "$stratified" "$candidate"
echo "SAMPLED_CANDIDATE_COMPLETE candidate=${candidate} data=${stratified}"
