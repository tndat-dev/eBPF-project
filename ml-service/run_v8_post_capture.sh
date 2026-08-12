#!/usr/bin/env bash
# Fail-closed V8 fit and one-shot terminal normal evaluation. Never promotes.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
EVIDENCE_ROOT=${1:-/home/dat/ml-service/aims-v8-capture-v8-paired-replay-20260811}
PYTHON_BIN=${PYTHON_BIN:-/home/dat/ml-venv/bin/python}
DERIVED_ROOT=${V8_DERIVED_ROOT:-/home/dat/ml-service/aims-v8-derived-v8-paired-replay-20260811}
FIT_DATASET=$DERIVED_ROOT/fit-dataset
CANDIDATE=$DERIVED_ROOT/models-v8-candidate
CALIBRATION=$DERIVED_ROOT/v8-fit-calibration.json
CALIBRATION_REPORT=$DERIVED_ROOT/v8-fit-calibration.report.json
EVALUATION_REPORT=$DERIVED_ROOT/v8-independent-evaluation.json
FALCO_EVIDENCE_ROOT=${V8_FALCO_EVIDENCE_ROOT:-/home/dat/ml-service/aims-v8-falco-evidence-v8-paired-replay-20260811}
FALCO_DERIVED=$DERIVED_ROOT/falco-rule-only-normal
FAST_PATH_DERIVED=$DERIVED_ROOT/fast-path-live-normal
FAST_PATH_EXCLUSION=$DERIVED_ROOT/fast-path-live-normal.exclusion.json
FAST_PATH_CONTRACT=$ROOT_DIR/v8_fast_path_normal_contract.json
EVALUATION_PROTOCOL=$ROOT_DIR/syscall_evaluation_protocol.json

if [[ ${SENTINEL_V8_POST_CAPTURE_LOCK_HELD:-0} != 1 ]]; then
  exec /usr/bin/flock -n -E 75 /home/dat/ml-service/.aims-normal-matrix.lock \
    env SENTINEL_V8_POST_CAPTURE_LOCK_HELD=1 \
    "$ROOT_DIR/run_v8_post_capture.sh" "$EVIDENCE_ROOT"
fi

if systemctl is-active --quiet aims-v8-capture.service; then
  printf 'WAITING: aims-v8-capture.service is active\n'
  exit 75
fi
if [[ $(systemctl show aims-v8-capture.service -p Result --value) != success ]]; then
  printf 'REFUSING: capture service did not reach Result=success\n' >&2
  exit 4
fi
for required in \
  SHA256SUMS matrix_manifest.json frozen-normal-feature-capture.jsonl \
  frozen-normal-feature-capture.manifest.json v8_capture_split_contract.json \
  evaluation_matrix_contract.json aims_release_contract.json vocab.pkl; do
  [[ -r "$EVIDENCE_ROOT/$required" ]] || {
    printf 'REFUSING: missing terminal capture artifact %s\n' "$required" >&2
    exit 4
  }
done
[[ -r "$EVALUATION_PROTOCOL" ]] || {
  printf 'REFUSING: missing syscall evaluation protocol\n' >&2
  exit 4
}
[[ -r "$FAST_PATH_CONTRACT" ]] || {
  printf 'REFUSING: missing retrospective fast-path normal contract\n' >&2
  exit 4
}

(cd "$EVIDENCE_ROOT" && sha256sum -c SHA256SUMS)
"$PYTHON_BIN" "$ROOT_DIR/validate_v8_capture_contract.py" \
  --contract "$EVIDENCE_ROOT/v8_capture_split_contract.json" \
  --evaluation-contract "$EVIDENCE_ROOT/evaluation_matrix_contract.json" \
  --vocab "$EVIDENCE_ROOT/vocab.pkl"
"$PYTHON_BIN" - "$EVIDENCE_ROOT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
matrix = json.loads((root / "matrix_manifest.json").read_text())
merged = json.loads(
    (root / "frozen-normal-feature-capture.manifest.json").read_text()
)
if not matrix.get("valid") or matrix.get("completed_phases") != 24:
    raise SystemExit("terminal matrix is not valid and complete")
if matrix.get("errors"):
    raise SystemExit("terminal matrix contains validation errors")
if (
    merged.get("source_count") != 24
    or not merged.get("validation", {}).get("valid")
    or merged.get("labels_used_for_training") is not False
):
    raise SystemExit("canonical normal merge is invalid")
PY

mkdir -p "$DERIVED_ROOT"
"$PYTHON_BIN" - "$EVALUATION_PROTOCOL" \
  "$EVIDENCE_ROOT/evaluation_matrix_contract.json" <<'PY'
import json, sys
protocol = json.load(open(sys.argv[1]))
matrix = json.load(open(sys.argv[2]))
expected = set(matrix["tracks"]["syscall"]["baselines"])
expected.update(matrix["tracks"]["syscall"]["ablations"])
if protocol.get("release_id") != matrix.get("release_id"):
    raise SystemExit("syscall evaluation protocol release mismatch")
if set(protocol.get("methods", {})) != expected:
    raise SystemExit("syscall evaluation protocol method mismatch")
if protocol.get("automatic_promotion") is not False:
    raise SystemExit("syscall evaluation protocol permits promotion")
PY
if [[ -e "$DERIVED_ROOT/syscall_evaluation_protocol.json" ]]; then
  cmp -s "$EVALUATION_PROTOCOL" \
    "$DERIVED_ROOT/syscall_evaluation_protocol.json" || {
      printf 'REFUSING: derived evaluation protocol drift\n' >&2
      exit 4
    }
else
  cp "$EVALUATION_PROTOCOL" "$DERIVED_ROOT/syscall_evaluation_protocol.json"
fi
if [[ -d "$FAST_PATH_DERIVED" && -e "$FAST_PATH_EXCLUSION" ]]; then
  printf 'REFUSING: both accepted and excluded fast-path evidence exist\n' >&2
  exit 4
elif [[ -d "$FAST_PATH_DERIVED" ]]; then
  (cd "$FAST_PATH_DERIVED" && sha256sum -c SHA256SUMS)
  "$PYTHON_BIN" - "$FAST_PATH_DERIVED/fast-path-normal-evidence.report.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if doc.get("valid") is not True or doc.get("phase_count") != 20:
    raise SystemExit("existing live fast-path normal derivative is invalid")
if doc.get("evidence_class") != "retrospective_operational_normal_evidence":
    raise SystemExit("live fast-path claim scope is missing")
PY
elif [[ -e "$FAST_PATH_EXCLUSION" ]]; then
  "$PYTHON_BIN" - "$FAST_PATH_EXCLUSION" "$FAST_PATH_CONTRACT" <<'PY'
import hashlib, json, sys
doc = json.load(open(sys.argv[1]))
digest = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
if not (
    doc.get("schema") == "sentinel-fast-path-normal-exclusion/v1"
    and doc.get("valid") is False
    and doc.get("status") == "excluded"
    and doc.get("claim_available") is False
    and doc.get("automatic_promotion") is False
    and doc.get("provenance_sha256", {}).get("contract") == digest
):
    raise SystemExit("existing fast-path exclusion report is invalid")
print(f"EXCLUDED: retrospective fast-path normal track: {doc.get('reason')}")
PY
else
  set +e
  "$PYTHON_BIN" "$ROOT_DIR/fast_path_normal_evidence_finalizer.py" \
    --capture-root "$EVIDENCE_ROOT" \
    --metrics /home/dat/ml-service/metrics.jsonl \
    --split-contract "$EVIDENCE_ROOT/v8_capture_split_contract.json" \
    --release-contract "$EVIDENCE_ROOT/aims_release_contract.json" \
    --contract "$FAST_PATH_CONTRACT" \
    --detector-source /home/dat/ml-service/anomaly_detector2.py \
    --fast-path-source /home/dat/ml-service/sentinel/fast_path.py \
    --service-unit /etc/systemd/system/sentinel-detector.service \
    --output-root "$FAST_PATH_DERIVED" \
    --exclusion-report "$FAST_PATH_EXCLUSION"
  fast_path_status=$?
  set -e
  case $fast_path_status in
    0) ;;
    4)
      "$PYTHON_BIN" - "$FAST_PATH_EXCLUSION" "$FAST_PATH_CONTRACT" <<'PY'
import hashlib, json, sys
doc = json.load(open(sys.argv[1]))
digest = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
if not (
    doc.get("schema") == "sentinel-fast-path-normal-exclusion/v1"
    and doc.get("valid") is False
    and doc.get("status") == "excluded"
    and doc.get("claim_available") is False
    and doc.get("provenance_sha256", {}).get("contract") == digest
):
    raise SystemExit("fast-path exclusion report is missing or invalid")
print(f"EXCLUDED: retrospective fast-path normal track: {doc.get('reason')}")
PY
      ;;
    75) exit 75 ;;
    *) exit "$fast_path_status" ;;
  esac
fi
if [[ -d "$FALCO_DERIVED" ]]; then
  (cd "$FALCO_DERIVED" && sha256sum -c SHA256SUMS)
  "$PYTHON_BIN" - "$FALCO_DERIVED/falco-normal-evidence.report.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if doc.get("valid") is not True or doc.get("phase_count") != 20:
    raise SystemExit("existing Falco normal derivative is invalid")
PY
else
  "$PYTHON_BIN" "$ROOT_DIR/falco_evidence_finalizer.py" \
    --capture-root "$EVIDENCE_ROOT" \
    --falco-root "$FALCO_EVIDENCE_ROOT" \
    --split-contract "$EVIDENCE_ROOT/v8_capture_split_contract.json" \
    --output-root "$FALCO_DERIVED"
fi
TARGETS=$("$PYTHON_BIN" - "$EVIDENCE_ROOT/aims_release_contract.json" <<'PY'
import json, sys
print(",".join(json.load(open(sys.argv[1]))["eligible_targets"]))
PY
)

if [[ ! -e "$FIT_DATASET" ]]; then
  "$PYTHON_BIN" "$ROOT_DIR/build_phase_dataset.py" \
    "$EVIDENCE_ROOT"/aims-{steady,burst,recovery,toolmix}-run-01 \
    --output "$FIT_DATASET" --minimum-events 10 \
    --minimum-phase-windows 30 --vocab "$EVIDENCE_ROOT/vocab.pkl" \
    --policy "$EVIDENCE_ROOT/tetragon-aims-policies.yaml" --targets "$TARGETS" \
    --experiment-contract "$EVIDENCE_ROOT/v8_capture_split_contract.json" \
    --dataset-role candidate_fit \
    --parent-release-contract "$EVIDENCE_ROOT/aims_release_contract.json"
fi
"$PYTHON_BIN" - "$FIT_DATASET/phase_dataset_manifest.json" \
  "$EVIDENCE_ROOT/v8_capture_split_contract.json" \
  "$EVIDENCE_ROOT/aims_release_contract.json" <<'PY'
import hashlib, json, pathlib, sys
manifest_path, split_path, release_path = map(pathlib.Path, sys.argv[1:])
doc = json.loads(manifest_path.read_text())
experiment = doc.get("experiment_contract") or {}
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
if doc.get("dataset_role") != "candidate_fit":
    raise SystemExit("fit dataset has the wrong role")
if experiment.get("sha256") != digest(split_path):
    raise SystemExit("fit dataset split digest mismatch")
if experiment.get("parent_release_contract_sha256") != digest(release_path):
    raise SystemExit("fit dataset release digest mismatch")
if experiment.get("holdout_training_forbidden") is not True:
    raise SystemExit("fit dataset does not forbid evaluation leakage")
PY

if [[ -d "$CANDIDATE" && ! -r "$CANDIDATE/training_report.json" ]]; then
  printf 'REFUSING: incomplete candidate directory exists: %s\n' "$CANDIDATE" >&2
  exit 4
fi
if [[ ! -r "$CANDIDATE/training_report.json" ]]; then
  "$PYTHON_BIN" "$ROOT_DIR/train_candidate.py" \
    --training-dir "$FIT_DATASET" --model-dir "$CANDIDATE" \
    --vocab "$FIT_DATASET/vocab.pkl" --targets "$TARGETS"
fi
"$PYTHON_BIN" - "$CANDIDATE/training_report.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if doc.get("accepted_offline") is not True or doc.get("dataset_role") != "candidate_fit":
    raise SystemExit("candidate did not pass the frozen fit-only gate")
PY

if [[ -e "$CALIBRATION" && ! -r "$CALIBRATION_REPORT" ]]; then
  printf 'REFUSING: calibration exists without its report\n' >&2
  exit 4
fi
if [[ -r "$CALIBRATION_REPORT" && ! -r "$CALIBRATION" ]]; then
  printf 'REFUSING: calibration report exists without calibration\n' >&2
  exit 4
fi
if [[ ! -r "$CALIBRATION_REPORT" ]]; then
  "$PYTHON_BIN" "$ROOT_DIR/build_aims_fit_calibration.py" \
    --candidate "$CANDIDATE" --output "$CALIBRATION" \
    --report "$CALIBRATION_REPORT"
fi

if [[ -r "$EVALUATION_REPORT" ]] && "$PYTHON_BIN" - "$EVALUATION_REPORT" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
raise SystemExit(0 if doc.get("status") == "complete" else 1)
PY
then
  "$PYTHON_BIN" - "$EVALUATION_REPORT" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
raise SystemExit(0 if doc.get("passed") is True else 3)
PY
else
  "$PYTHON_BIN" "$ROOT_DIR/evaluate_aims_normal_split.py" \
    --evidence-root "$EVIDENCE_ROOT" --candidate "$CANDIDATE" \
    --role independent_evaluation \
    --split-contract "$EVIDENCE_ROOT/v8_capture_split_contract.json" \
    --release-contract "$EVIDENCE_ROOT/aims_release_contract.json" \
    --initial-calibration "$CALIBRATION" \
    --initial-calibration-report "$CALIBRATION_REPORT" \
    --output "$EVALUATION_REPORT"
fi

find "$DERIVED_ROOT" -type f ! -name SHA256SUMS -print0 \
  | sort -z | xargs -0 sha256sum >"$DERIVED_ROOT/SHA256SUMS"
touch "$DERIVED_ROOT/POST_CAPTURE_COMPLETE"
printf 'COMPLETE: V8 candidate and terminal normal evaluation are frozen at %s\n' \
  "$DERIVED_ROOT"
