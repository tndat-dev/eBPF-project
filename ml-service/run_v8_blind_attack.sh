#!/usr/bin/env bash
# Run the pre-registered V8 blind attack matrix after terminal normal replay.
# This path never trains, tunes, promotes, or changes the production model.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PYTHON_BIN=${PYTHON_BIN:-/home/dat/ml-venv/bin/python}
EVIDENCE_ROOT=${V8_EVIDENCE_ROOT:-/home/dat/ml-service/aims-v8-capture-v8-paired-replay-20260811}
DERIVED_ROOT=${V8_DERIVED_ROOT:-/home/dat/ml-service/aims-v8-derived-v8-paired-replay-20260811}
FALCO_ROOT=${V8_FALCO_EVIDENCE_ROOT:-/home/dat/ml-service/aims-v8-falco-evidence-v8-paired-replay-20260811}
ATTACK_ROOT=${V8_ATTACK_ROOT:-/home/dat/ml-service/aims-v8-blind-attack-v8-paired-replay-20260811}
EXPERIMENT_ID=${V8_ATTACK_EXPERIMENT_ID:-v8-blind-attack-20260811}
CANDIDATE=$DERIVED_ROOT/models-v8-candidate
CALIBRATION=$DERIVED_ROOT/v8-fit-calibration.json
PREREQUISITE=$DERIVED_ROOT/v8-independent-evaluation.json

if systemctl is-active --quiet aims-v8-capture.service \
  || systemctl is-active --quiet aims-v8-post-capture.service; then
  printf 'WAITING: V8 capture/post-capture is active\n'
  exit 75
fi
[[ -r "$DERIVED_ROOT/POST_CAPTURE_COMPLETE" ]] || {
  printf 'WAITING: V8 terminal normal evaluation is incomplete\n'
  exit 75
}
systemctl is-active --quiet aims-v8-falco-evidence.service || {
  printf 'REFUSING: Falco paired evidence collector is inactive\n' >&2
  exit 4
}
for path in "$CANDIDATE/training_report.json" "$CALIBRATION" "$PREREQUISITE" \
  "$EVIDENCE_ROOT/v8_capture_split_contract.json" \
  "$EVIDENCE_ROOT/evaluation_matrix_contract.json" \
  "$ROOT_DIR/v8_blind_attack_contract.json" \
  "$ROOT_DIR/runtime_attack_blind.c" "$ROOT_DIR/runtime_attack_blind"; do
  [[ -r "$path" ]] || { printf 'REFUSING: missing %s\n' "$path" >&2; exit 4; }
done
"$PYTHON_BIN" - "$PREREQUISITE" "$FALCO_ROOT/collector-state.json" <<'PY'
from datetime import datetime, timezone
import json, sys
normal = json.load(open(sys.argv[1]))
falco = json.load(open(sys.argv[2]))
if not (
    normal.get("role") == "independent_evaluation"
    and normal.get("status") == "complete"
    and normal.get("passed") is True
):
    raise SystemExit("terminal independent normal gate did not pass")
if not (
    falco.get("coverage_healthy") is True
    and falco.get("release_id") == "v8-paired-replay-20260811"
    and falco.get("stream_failures") == 0
    and len(falco.get("active_readers", [])) == falco.get("expected_readers") == 6
):
    raise SystemExit("Falco paired baseline collector is not healthy")
updated = datetime.fromisoformat(falco["updated_at"].replace("Z", "+00:00"))
if (datetime.now(timezone.utc) - updated).total_seconds() > 120:
    raise SystemExit("Falco paired baseline collector state is stale")
PY

set +e
"$PYTHON_BIN" "$ROOT_DIR/run_aims_blind_matrix.py" \
  --model-dir "$CANDIDATE" \
  --normal-calibration "$CALIBRATION" \
  --normal-prerequisite "$PREREQUISITE" \
  --split-contract "$EVIDENCE_ROOT/v8_capture_split_contract.json" \
  --evaluation-contract "$EVIDENCE_ROOT/evaluation_matrix_contract.json" \
  --aims-contract "$EVIDENCE_ROOT/aims_release_contract.json" \
  --attack-contract "$ROOT_DIR/v8_blind_attack_contract.json" \
  --runtime-source "$ROOT_DIR/runtime_attack_blind.c" \
  --runtime-binary "$ROOT_DIR/runtime_attack_blind" \
  --feature-capture-mode sequence \
  --capture-release-id v8-paired-replay-20260811 \
  --output-root "$ATTACK_ROOT" --experiment-id "$EXPERIMENT_ID"
matrix_rc=$?
set -e
if [[ $matrix_rc != 0 && $matrix_rc != 8 ]]; then
  exit "$matrix_rc"
fi

EXPERIMENT_ROOT=$ATTACK_ROOT/$EXPERIMENT_ID
"$PYTHON_BIN" "$ROOT_DIR/falco_attack_evidence_finalizer.py" \
  --attack-capture "$EXPERIMENT_ROOT/frozen-attack-feature-capture.jsonl" \
  --falco-root "$FALCO_ROOT" \
  --collection-contract "$FALCO_ROOT/collection-contract.json" \
  --output-root "$EXPERIMENT_ROOT/falco-rule-only-attack" \
  --expected-trials 200 --post-attack-horizon 30
touch "$EXPERIMENT_ROOT/FALCO_ATTACK_EVIDENCE_COMPLETE"
exit "$matrix_rc"
