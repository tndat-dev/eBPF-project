#!/usr/bin/env bash
# Run/resume all six AIMS overhead phase orders and aggregate paired blocks.
set -Eeuo pipefail

ROOT_DIR=/home/dat/ml-service
CAMPAIGN_ID=${AIMS_OVERHEAD_CAMPAIGN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
OUTPUT_ROOT=${AIMS_OVERHEAD_OUTPUT_ROOT:-$ROOT_DIR/aims-overhead-final}
orders=(
  no_tracing,tetragon_only,full_pipeline
  no_tracing,full_pipeline,tetragon_only
  tetragon_only,no_tracing,full_pipeline
  tetragon_only,full_pipeline,no_tracing
  full_pipeline,no_tracing,tetragon_only
  full_pipeline,tetragon_only,no_tracing
)

for index in "${!orders[@]}"; do
  ordinal=$(printf '%02d' "$((index + 1))")
  experiment_id="$CAMPAIGN_ID-p$ordinal"
  comparison="$OUTPUT_ROOT/comparison-wrk-$experiment_id.json"
  if [[ -s "$comparison" ]]; then
    printf 'OVERHEAD_RESUME experiment=%s status=complete\n' "$experiment_id"
    continue
  fi
  SENTINEL_EXPERIMENT_ID="$experiment_id" \
    AIMS_PHASE_ORDER="${orders[$index]}" \
    "$ROOT_DIR/sentinel/benchmarks/run_aims_overhead_matrix.sh"
done

/home/dat/ml-venv/bin/python \
  "$ROOT_DIR/sentinel/benchmarks/aggregate_counterbalanced_overhead.py" \
  --root "$OUTPUT_ROOT" --campaign-prefix "$CAMPAIGN_ID" \
  --output "$OUTPUT_ROOT/counterbalanced-$CAMPAIGN_ID.json"
printf 'AIMS_OVERHEAD_COUNTERBALANCED_COMPLETE campaign=%s\n' "$CAMPAIGN_ID"
