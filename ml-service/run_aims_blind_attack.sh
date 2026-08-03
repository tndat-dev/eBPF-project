#!/usr/bin/env bash
# Disconnect-safe wrapper for the frozen AIMS blind attack matrix. No promote.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ENV_FILE=${AIMS_EVALUATION_ENV:-"$ROOT_DIR/aims-evaluation.env"}
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
PYTHON_BIN=${PYTHON_BIN:-/home/dat/ml-venv/bin/python}
: "${AIMS_CANDIDATE:?}"
: "${AIMS_CALIBRATION:?}"
: "${AIMS_BLIND_REPORT:?}"
EXPERIMENT_ID=${AIMS_BLIND_ATTACK_EXPERIMENT_ID:-"aims-blind-$(basename "$AIMS_CANDIDATE")"}
OUTPUT_ROOT=${AIMS_BLIND_ATTACK_OUTPUT_ROOT:-"$ROOT_DIR/aims-blind-matrix"}

for unit in aims-normal-matrix.service \
  aims-split-evaluation@independent_validation.service \
  aims-split-evaluation@blind_normal_test.service; do
  if systemctl is-active --quiet "$unit"; then
    printf 'WAITING: %s is active\n' "$unit"
    exit 0
  fi
done
if [[ ! -r "$AIMS_BLIND_REPORT" ]] || ! "$PYTHON_BIN" - "$AIMS_BLIND_REPORT" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
raise SystemExit(0 if doc.get("role") == "blind_normal_test" and
                 doc.get("status") == "complete" and doc.get("passed") is True else 1)
PY
then
  printf 'WAITING: passed blind-normal report is unavailable\n'
  exit 0
fi

exec "$PYTHON_BIN" "$ROOT_DIR/run_aims_blind_matrix.py" \
  --model-dir "$AIMS_CANDIDATE" \
  --normal-calibration "$AIMS_CALIBRATION" \
  --normal-prerequisite "$AIMS_BLIND_REPORT" \
  --split-contract "$ROOT_DIR/aims_candidate_split_contract.json" \
  --aims-contract "$ROOT_DIR/aims_release_contract.json" \
  --attack-contract "$ROOT_DIR/aims_blind_attack_contract.json" \
  --runtime-source "$ROOT_DIR/runtime_attack_blind.c" \
  --runtime-binary "$ROOT_DIR/runtime_attack_blind" \
  --output-root "$OUTPUT_ROOT" --experiment-id "$EXPERIMENT_ID"
