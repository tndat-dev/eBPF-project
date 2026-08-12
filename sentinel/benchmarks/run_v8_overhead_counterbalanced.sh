#!/usr/bin/env bash
# Run V8 overhead only after every frozen terminal detection artifact exists.
set -Eeuo pipefail

ROOT_DIR=/home/dat/ml-service
OUTPUT_ROOT=$ROOT_DIR/aims-overhead-v8-final
CAMPAIGN_ID=v8-paired-replay-20260811
ENV_FILE=$ROOT_DIR/sentinel/systemd/aims-v8-overhead.env
MARKER=$OUTPUT_ROOT/V8_OVERHEAD_COMPLETE

[[ -r "$ENV_FILE" ]] || { printf 'missing V8 overhead environment\n' >&2; exit 4; }
[[ -r "$ROOT_DIR/aims-v8-derived-v8-paired-replay-20260811/NORMAL_ABLATION_REPLAY_COMPLETE" ]] || {
  printf 'WAITING: V8 terminal syscall matrix is incomplete\n'
  exit 75
}
[[ ! -e "$MARKER" ]] || { printf 'V8 overhead is already complete\n'; exit 0; }

export AIMS_EVALUATION_ENV=$ENV_FILE
export AIMS_OVERHEAD_OUTPUT_ROOT=$OUTPUT_ROOT
export AIMS_OVERHEAD_CAMPAIGN_ID=$CAMPAIGN_ID
"$ROOT_DIR/sentinel/benchmarks/run_aims_overhead_counterbalanced.sh"

aggregate=$OUTPUT_ROOT/counterbalanced-$CAMPAIGN_ID.json
/home/dat/ml-venv/bin/python - "$aggregate" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if (
    doc.get("evidence_release") != "v8"
    or len(doc.get("experiments", [])) != 6
    or any(row.get("prerequisite") is None for row in doc["experiments"])
):
    raise SystemExit("V8 counterbalanced aggregate is incomplete")
PY
temporary=$OUTPUT_ROOT/.SHA256SUMS.tmp
find "$OUTPUT_ROOT" -type f ! -name SHA256SUMS ! -name V8_OVERHEAD_COMPLETE \
  -print0 | sort -z | xargs -0 sha256sum >"$temporary"
mv "$temporary" "$OUTPUT_ROOT/SHA256SUMS"
touch "$MARKER"
printf 'V8_OVERHEAD_COMPLETE campaign=%s\n' "$CAMPAIGN_ID"
