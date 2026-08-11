#!/usr/bin/env bash
# Atomically deploy the frozen V8 post-capture code, test it, then derive evidence.
set -euo pipefail

STAGING_ROOT=${V8_STAGING_ROOT:-/home/dat/v8-post-capture-staging/v8-paired-replay-20260811}
RUNTIME_ROOT=${V8_RUNTIME_ROOT:-/home/dat/ml-service}
PYTHON_BIN=${PYTHON_BIN:-/home/dat/ml-venv/bin/python}
MANIFEST=$STAGING_ROOT/STAGING_SHA256SUMS
EVIDENCE_ROOT=${V8_EVIDENCE_ROOT:-$RUNTIME_ROOT/aims-v8-capture-v8-paired-replay-20260811}

[[ -r "$MANIFEST" ]] || { printf 'missing staging checksum manifest\n' >&2; exit 4; }
(cd "$STAGING_ROOT" && sha256sum -c STAGING_SHA256SUMS)
for unit in aims-v8-post-capture.service aims-v8-post-capture.timer \
  aims-v8-blind-attack.service aims-v8-blind-attack.timer; do
  cmp -s "$STAGING_ROOT/sentinel/systemd/$unit" "/etc/systemd/system/$unit" || {
    printf 'REFUSING: installed systemd unit differs from staging: %s\n' \
      "$unit" >&2
    exit 4
  }
done
if systemctl is-active --quiet aims-v8-capture.service; then
  printf 'WAITING: aims-v8-capture.service is active\n'
  exit 75
fi
if [[ $(systemctl show aims-v8-capture.service -p Result --value) != success ]]; then
  printf 'REFUSING: capture service did not reach Result=success\n' >&2
  exit 4
fi
"$PYTHON_BIN" - "$STAGING_ROOT/ml-service/v8_blind_attack_contract.json" \
  "$RUNTIME_ROOT/runtime_attack_blind.c" "$RUNTIME_ROOT/runtime_attack_blind" <<'PY'
import hashlib, json, pathlib, sys
contract_path, source, binary = map(pathlib.Path, sys.argv[1:])
contract = json.loads(contract_path.read_text())
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
if not source.is_file() or digest(source) != contract["source"]["sha256"]:
    raise SystemExit("V8 blind attack source digest mismatch")
if not binary.is_file() or digest(binary) != contract["binary"]["sha256"]:
    raise SystemExit("V8 blind attack binary digest mismatch")
PY

for name in build_feature_replay_dataset.py build_phase_dataset.py \
  evaluate_aims_normal_split.py falco_evidence_finalizer.py \
  merge_feature_captures.py run_aims_blind_matrix.py \
  run_aims_split_evaluation.sh run_v8_blind_attack.sh \
  run_v8_post_capture.sh v8_blind_attack_contract.json; do
  source=$STAGING_ROOT/ml-service/$name
  temporary=$RUNTIME_ROOT/.$name.v8-staging
  cp "$source" "$temporary"
  chmod --reference="$source" "$temporary"
  mv "$temporary" "$RUNTIME_ROOT/$name"
done

bash -n "$RUNTIME_ROOT/run_aims_split_evaluation.sh" \
  "$RUNTIME_ROOT/run_v8_post_capture.sh"
cd "$STAGING_ROOT"
PYTHONPATH="$RUNTIME_ROOT" "$PYTHON_BIN" -m pytest -q \
  tests/test_phase_dataset.py \
  tests/test_aims_normal_split_evaluator.py \
  tests/test_falco_evidence_finalizer.py \
  tests/test_aims_blind_matrix.py \
  tests/test_v8_blind_attack.py \
  tests/test_v8_capture_contract.py \
  tests/test_v8_post_capture_runner.py

exec env SENTINEL_V8_POST_CAPTURE_LOCK_HELD=1 \
  "$RUNTIME_ROOT/run_v8_post_capture.sh" "$EVIDENCE_ROOT"
