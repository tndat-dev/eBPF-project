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
  aims-v8-blind-attack.service aims-v8-blind-attack.timer \
  aims-v8-normal-ablation.service aims-v8-normal-ablation.timer \
  aims-v8-falco-evidence.service; do
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

DERIVED_ROOT=${V8_DERIVED_ROOT:-$RUNTIME_ROOT/aims-v8-derived-v8-paired-replay-20260811}
FAST_PATH_DERIVED=$DERIVED_ROOT/fast-path-live-normal
FAST_PATH_EXCLUSION=$DERIVED_ROOT/fast-path-live-normal.exclusion.json
if [[ -d "$FAST_PATH_DERIVED" && -e "$FAST_PATH_EXCLUSION" ]]; then
  printf 'REFUSING: both accepted and excluded fast-path evidence exist\n' >&2
  exit 4
elif [[ -e "$FAST_PATH_EXCLUSION" ]]; then
  fast_path_status=4
else
  set +e
  "$PYTHON_BIN" "$STAGING_ROOT/ml-service/fast_path_normal_evidence_finalizer.py" \
    --capture-root "$EVIDENCE_ROOT" \
    --metrics "$RUNTIME_ROOT/metrics.jsonl" \
    --split-contract "$EVIDENCE_ROOT/v8_capture_split_contract.json" \
    --release-contract "$EVIDENCE_ROOT/aims_release_contract.json" \
    --contract "$STAGING_ROOT/ml-service/v8_fast_path_normal_contract.json" \
    --detector-source "$RUNTIME_ROOT/anomaly_detector2.py" \
    --fast-path-source "$RUNTIME_ROOT/sentinel/fast_path.py" \
    --service-unit /etc/systemd/system/sentinel-detector.service \
    --output-root "$FAST_PATH_DERIVED" \
    --exclusion-report "$FAST_PATH_EXCLUSION"
  fast_path_status=$?
  set -e
fi
case $fast_path_status in
  0)
    [[ -d "$FAST_PATH_DERIVED" && ! -e "$FAST_PATH_EXCLUSION" ]] || {
      printf 'REFUSING: ambiguous fast-path normal evidence state\n' >&2
      exit 4
    }
    ;;
  4)
    "$PYTHON_BIN" - "$FAST_PATH_EXCLUSION" \
      "$STAGING_ROOT/ml-service/v8_fast_path_normal_contract.json" <<'PY'
import hashlib, json, pathlib, sys
path, contract_path = map(pathlib.Path, sys.argv[1:])
doc = json.loads(path.read_text()) if path.is_file() else {}
digest = hashlib.sha256(contract_path.read_bytes()).hexdigest()
if not (
    doc.get("schema") == "sentinel-fast-path-normal-exclusion/v1"
    and doc.get("valid") is False
    and doc.get("status") == "excluded"
    and doc.get("claim_available") is False
    and doc.get("automatic_promotion") is False
    and doc.get("provenance_sha256", {}).get("contract") == digest
):
    raise SystemExit("fast-path exclusion report is missing or invalid")
print(f"EXCLUDED: retrospective fast-path normal track: {doc.get('reason')}")
PY
    ;;
  75) exit 75 ;;
  *) exit "$fast_path_status" ;;
esac

for name in anomaly_detector2.py analyze_syscall_evaluation_matrix.py \
  audit_attack_observability.py \
  assemble_syscall_evaluation_matrix.py \
  build_aims_fit_calibration.py \
  build_feature_replay_dataset.py build_phase_dataset.py \
  evaluate_aims_attack_replay.py evaluate_aims_normal_split.py \
  evaluate_tetragon_rule_replay.py \
  evaluation_matrix_validation.py \
  fast_path_normal_evidence_finalizer.py \
  falco_evidence_collector.py \
  falco_attack_evidence_finalizer.py \
  falco_evidence_finalizer.py \
  merge_feature_captures.py run_aims_blind_matrix.py \
  render_syscall_paper_results.py \
  run_aims_split_evaluation.sh run_v8_blind_attack.sh \
  run_v8_normal_ablation_matrix.sh train_candidate.py \
  train_shared_workload_candidate.py ml_models.py \
  run_v8_post_capture.sh syscall_evaluation_protocol.json \
  v8_blind_attack_contract.json v8_fast_path_normal_contract.json; do
  source=$STAGING_ROOT/ml-service/$name
  temporary=$RUNTIME_ROOT/.$name.v8-staging
  cp "$source" "$temporary"
  chmod --reference="$source" "$temporary"
  mv "$temporary" "$RUNTIME_ROOT/$name"
done

bash -n "$RUNTIME_ROOT/run_aims_split_evaluation.sh" \
  "$RUNTIME_ROOT/run_v8_post_capture.sh"
cd "$RUNTIME_ROOT"
PYTHONPATH="$RUNTIME_ROOT" "$PYTHON_BIN" -m pytest -q -p no:cacheprovider \
  "$STAGING_ROOT/tests/test_sentinel.py" \
  "$STAGING_ROOT/tests/test_evaluation_matrix_validation.py" \
  "$STAGING_ROOT/tests/test_syscall_evaluation_protocol.py" \
  "$STAGING_ROOT/tests/test_tetragon_rule_replay.py" \
  "$STAGING_ROOT/tests/test_phase_dataset.py" \
  "$STAGING_ROOT/tests/test_render_syscall_paper_results.py" \
  "$STAGING_ROOT/tests/test_aims_attack_replay.py" \
  "$STAGING_ROOT/tests/test_attack_observability_audit.py" \
  "$STAGING_ROOT/tests/test_syscall_matrix_assembler.py" \
  "$STAGING_ROOT/tests/test_syscall_paired_statistics.py" \
  "$STAGING_ROOT/tests/test_aims_normal_split_evaluator.py" \
  "$STAGING_ROOT/tests/test_shared_workload_model.py" \
  "$STAGING_ROOT/tests/test_falco_evidence_collector.py" \
  "$STAGING_ROOT/tests/test_falco_evidence_finalizer.py" \
  "$STAGING_ROOT/tests/test_fast_path_normal_evidence_finalizer.py" \
  "$STAGING_ROOT/tests/test_falco_attack_evidence_finalizer.py" \
  "$STAGING_ROOT/tests/test_aims_blind_matrix.py" \
  "$STAGING_ROOT/tests/test_v8_blind_attack.py" \
  "$STAGING_ROOT/tests/test_v8_normal_ablation_runner.py" \
  "$STAGING_ROOT/tests/test_v8_capture_contract.py" \
  "$STAGING_ROOT/tests/test_v8_post_capture_runner.py"

exec env SENTINEL_V8_POST_CAPTURE_LOCK_HELD=1 \
  "$RUNTIME_ROOT/run_v8_post_capture.sh" "$EVIDENCE_ROOT"
