#!/usr/bin/env bash
# Periodic fail-closed AIMS holdout evaluator. Never trains or promotes.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROLE=${1:?usage: run_aims_split_evaluation.sh independent_validation|blind_normal_test}
case "$ROLE" in
  independent_validation|blind_normal_test) ;;
  *) printf 'unsupported AIMS evaluation role: %s\n' "$ROLE" >&2; exit 2 ;;
esac

: "${AIMS_EVIDENCE_ROOT:?AIMS_EVIDENCE_ROOT is required}"
: "${AIMS_CANDIDATE:?AIMS_CANDIDATE is required}"
: "${AIMS_CALIBRATION:?AIMS_CALIBRATION is required}"
PYTHON_BIN=${PYTHON_BIN:-/home/dat/ml-venv/bin/python}
SPLIT_CONTRACT=${AIMS_SPLIT_CONTRACT:-"$ROOT_DIR/aims_candidate_split_contract.json"}
RELEASE_CONTRACT=${AIMS_RELEASE_CONTRACT:-"$ROOT_DIR/aims_release_contract.json"}
VALIDATION_REPORT=${AIMS_VALIDATION_REPORT:-"$ROOT_DIR/aims-independent-validation.json"}
BLIND_REPORT=${AIMS_BLIND_REPORT:-"$ROOT_DIR/aims-blind-normal-test.json"}
CALIBRATION_REPORT=${AIMS_CALIBRATION_REPORT:-"${AIMS_CALIBRATION}.report.json"}

if [[ ! -r "$AIMS_CALIBRATION" ]]; then
  if [[ ! -r "$AIMS_CANDIDATE/training_report.json" ]]; then
    printf 'WAITING: frozen candidate training is incomplete\n'
    exit 0
  fi
  "$PYTHON_BIN" "$ROOT_DIR/build_aims_fit_calibration.py" \
    --candidate "$AIMS_CANDIDATE" --output "$AIMS_CALIBRATION" \
    --report "$CALIBRATION_REPORT"
fi

if [[ "$ROLE" == independent_validation ]]; then
  output=$VALIDATION_REPORT
else
  output=$BLIND_REPORT
  if [[ ! -r "$VALIDATION_REPORT" ]] || ! "$PYTHON_BIN" - "$VALIDATION_REPORT" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
raise SystemExit(0 if doc.get("status") == "complete" and doc.get("passed") is True else 1)
PY
  then
    printf 'WAITING: blind normal test requires passed independent validation\n'
    exit 0
  fi
fi

if [[ -r "$output" ]] && "$PYTHON_BIN" - "$output" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
raise SystemExit(0 if doc.get("status") == "complete" else 1)
PY
then
  printf 'KEEPING: completed immutable evaluation %s\n' "$output"
  exit 0
fi

command=(
  "$PYTHON_BIN" "$ROOT_DIR/evaluate_aims_normal_split.py"
  --evidence-root "$AIMS_EVIDENCE_ROOT"
  --candidate "$AIMS_CANDIDATE"
  --role "$ROLE"
  --split-contract "$SPLIT_CONTRACT"
  --release-contract "$RELEASE_CONTRACT"
  --initial-calibration "$AIMS_CALIBRATION"
  --output "$output"
)
if [[ "$ROLE" == blind_normal_test ]]; then
  command+=(--prerequisite-report "$VALIDATION_REPORT")
fi

rc=0
"${command[@]}" || rc=$?
if (( rc == 4 )); then
  printf 'WAITING: required %s phases are incomplete\n' "$ROLE"
  exit 0
fi
exit "$rc"
