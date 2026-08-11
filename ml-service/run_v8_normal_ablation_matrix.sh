#!/usr/bin/env bash
# Replay fit-frozen V8 candidate components/policies on the same 20 normal phases.
# Baseline false alerts are evidence, not a process failure; evaluator exit 3 is
# therefore retained as a completed experiment. This script never promotes.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PYTHON_BIN=${PYTHON_BIN:-/home/dat/ml-venv/bin/python}
EVIDENCE_ROOT=${V8_EVIDENCE_ROOT:-/home/dat/ml-service/aims-v8-capture-v8-paired-replay-20260811}
DERIVED_ROOT=${V8_DERIVED_ROOT:-/home/dat/ml-service/aims-v8-derived-v8-paired-replay-20260811}
CANDIDATE=$DERIVED_ROOT/models-v8-candidate
CALIBRATION=$DERIVED_ROOT/v8-fit-calibration.json
CALIBRATION_REPORT=$DERIVED_ROOT/v8-fit-calibration.report.json
OUTPUT_ROOT=${V8_NORMAL_ABLATION_ROOT:-$DERIVED_ROOT/normal-ablation-replay}
ATTACK_CAPTURE=${V8_ATTACK_CAPTURE:-/home/dat/ml-service/aims-v8-blind-attack-v8-paired-replay-20260811/v8-blind-attack-20260811/frozen-attack-feature-capture.jsonl}
NORMAL_CAPTURE=$EVIDENCE_ROOT/frozen-normal-feature-capture.jsonl
TETRAGON_OUTPUT=$DERIVED_ROOT/tetragon-rule-only-replay
ATTACK_CONTRACT=$ROOT_DIR/v8_blind_attack_contract.json
EVALUATION_PROTOCOL=$ROOT_DIR/syscall_evaluation_protocol.json
SHARED_CANDIDATE=$DERIVED_ROOT/models-v8-shared-workload
SHARED_CALIBRATION=$DERIVED_ROOT/v8-shared-workload-calibration.json
SHARED_CALIBRATION_REPORT=$DERIVED_ROOT/v8-shared-workload-calibration.report.json
ATTACK_EXPERIMENT_ROOT=$(dirname "$ATTACK_CAPTURE")
FALCO_ROOT=${V8_FALCO_EVIDENCE_ROOT:-/home/dat/ml-service/aims-v8-falco-evidence-v8-paired-replay-20260811}
PAPER_MATRIX_ROOT=${V8_PAPER_MATRIX_ROOT:-$DERIVED_ROOT/paper-evaluation-results}

[[ -r "$DERIVED_ROOT/POST_CAPTURE_COMPLETE" ]] || {
  printf 'WAITING: terminal V8 normal candidate is incomplete\n'
  exit 75
}
for path in "$CANDIDATE/training_report.json" "$CALIBRATION" \
  "$CALIBRATION_REPORT" "$EVIDENCE_ROOT/v8_capture_split_contract.json" \
  "$EVIDENCE_ROOT/aims_release_contract.json" \
  "$NORMAL_CAPTURE" "$ATTACK_CAPTURE" \
  "$EVALUATION_PROTOCOL" "$ATTACK_CONTRACT"; do
  [[ -r "$path" ]] || { printf 'REFUSING: missing %s\n' "$path" >&2; exit 4; }
done

mkdir -p "$OUTPUT_ROOT"

if [[ ! -r "$SHARED_CANDIDATE/training_report.json" ]]; then
  set +e
  "$PYTHON_BIN" "$ROOT_DIR/train_shared_workload_candidate.py" \
    --fit-dataset "$DERIVED_ROOT/fit-dataset" \
    --reference-candidate "$CANDIDATE" --output "$SHARED_CANDIDATE"
  shared_rc=$?
  set -e
  [[ $shared_rc == 0 || $shared_rc == 3 ]] || exit "$shared_rc"
fi
"$PYTHON_BIN" - "$SHARED_CANDIDATE/training_report.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if doc.get("model_routing") != "shared_workload":
    raise SystemExit("shared-workload training provenance mismatch")
if doc.get("labels_used_for_training_or_tuning") is not False:
    raise SystemExit("shared-workload model does not exclude labels")
PY
if [[ ! -r "$SHARED_CALIBRATION_REPORT" ]]; then
  [[ ! -e "$SHARED_CALIBRATION" ]] || {
    printf 'REFUSING: shared calibration exists without report\n' >&2
    exit 4
  }
  "$PYTHON_BIN" "$ROOT_DIR/build_aims_fit_calibration.py" \
    --candidate "$SHARED_CANDIDATE" --output "$SHARED_CALIBRATION" \
    --report "$SHARED_CALIBRATION_REPORT"
fi

"$PYTHON_BIN" "$ROOT_DIR/evaluate_tetragon_rule_replay.py" \
  --normal-capture "$NORMAL_CAPTURE" --attack-capture "$ATTACK_CAPTURE" \
  --protocol "$ROOT_DIR/syscall_evaluation_protocol.json" \
  --output-root "$TETRAGON_OUTPUT" --expected-trials 200 \
  --post-attack-horizon 30

run_experiment() {
  local experiment_id=$1
  shift
  local output=$OUTPUT_ROOT/$experiment_id.json
  if [[ -r "$output" ]] && "$PYTHON_BIN" - "$output" "$experiment_id" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
raise SystemExit(0 if (
    doc.get("status") == "complete"
    and doc.get("experiment_id") == sys.argv[2]
) else 1)
PY
  then
    printf 'VERIFIED: %s already complete\n' "$experiment_id"
    return
  fi

  set +e
  "$PYTHON_BIN" "$ROOT_DIR/evaluate_aims_normal_split.py" \
    --evidence-root "$EVIDENCE_ROOT" --candidate "$CANDIDATE" \
    --role independent_evaluation \
    --split-contract "$EVIDENCE_ROOT/v8_capture_split_contract.json" \
    --release-contract "$EVIDENCE_ROOT/aims_release_contract.json" \
    --initial-calibration "$CALIBRATION" \
    --initial-calibration-report "$CALIBRATION_REPORT" \
    --output "$output" "$@"
  local rc=$?
  set -e
  if [[ $rc != 0 && $rc != 3 ]]; then
    return "$rc"
  fi
  "$PYTHON_BIN" - "$output" "$experiment_id" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text())
if doc.get("status") != "complete":
    raise SystemExit("evaluator did not produce a terminal report")
doc["experiment_id"] = sys.argv[2]
temporary = path.with_suffix(path.suffix + ".tmp")
temporary.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
temporary.replace(path)
PY
}

run_attack_experiment() {
  local experiment_id=$1
  shift
  local output=$OUTPUT_ROOT/$experiment_id.attack.json
  if [[ -r "$output" ]] && "$PYTHON_BIN" - "$output" "$experiment_id" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
raise SystemExit(0 if (
    doc.get("status") == "complete"
    and doc.get("experiment_id") == sys.argv[2]
    and doc.get("completed_trials") == 200
) else 1)
PY
  then
    printf 'VERIFIED: %s attack replay already complete\n' "$experiment_id"
    return
  fi
  "$PYTHON_BIN" "$ROOT_DIR/evaluate_aims_attack_replay.py" \
    --attack-capture "$ATTACK_CAPTURE" --candidate "$CANDIDATE" \
    --initial-calibration "$CALIBRATION" \
    --initial-calibration-report "$CALIBRATION_REPORT" \
    --release-contract "$EVIDENCE_ROOT/aims_release_contract.json" \
    --split-contract "$EVIDENCE_ROOT/v8_capture_split_contract.json" \
    --attack-contract "$ATTACK_CONTRACT" --protocol "$EVALUATION_PROTOCOL" \
    --experiment-id "$experiment_id" --expected-trials 200 \
    --post-attack-horizon 30 --output "$output" "$@"
}

run_experiment syscall__isolation_forest \
  --score-component isolation_forest --disable-adaptive-threshold \
  --disable-behavior-gate --disable-extreme-volume-gate \
  --confirmation-windows 1
run_attack_experiment syscall__isolation_forest \
  --score-component isolation_forest --disable-adaptive-threshold \
  --disable-behavior-gate --disable-extreme-volume-gate \
  --confirmation-windows 1
run_experiment syscall__lstm_only \
  --score-component lstm --disable-adaptive-threshold \
  --disable-behavior-gate --disable-extreme-volume-gate \
  --confirmation-windows 1
run_attack_experiment syscall__lstm_only \
  --score-component lstm --disable-adaptive-threshold \
  --disable-behavior-gate --disable-extreme-volume-gate \
  --confirmation-windows 1
run_experiment syscall__evt_pot \
  --score-component lstm --disable-behavior-gate \
  --disable-extreme-volume-gate --confirmation-windows 1
run_attack_experiment syscall__evt_pot \
  --score-component lstm --disable-behavior-gate \
  --disable-extreme-volume-gate --confirmation-windows 1
run_experiment syscall__full_v7
run_attack_experiment syscall__full_v7
run_experiment syscall__without_fast_path
run_attack_experiment syscall__without_fast_path
run_experiment syscall__without_behavior_gate --disable-behavior-gate
run_attack_experiment syscall__without_behavior_gate --disable-behavior-gate
run_experiment syscall__without_extreme_volume_gate \
  --disable-extreme-volume-gate
run_attack_experiment syscall__without_extreme_volume_gate \
  --disable-extreme-volume-gate
run_experiment syscall__without_two_window_confirmation \
  --confirmation-windows 1
run_attack_experiment syscall__without_two_window_confirmation \
  --confirmation-windows 1

# This method has a separately fitted pooled model and fit-only calibration.
# It still reuses the exact evaluator and immutable run-02--06 holdouts.
CANDIDATE=$SHARED_CANDIDATE
CALIBRATION=$SHARED_CALIBRATION
CALIBRATION_REPORT=$SHARED_CALIBRATION_REPORT
run_experiment syscall__shared_workload_model --model-routing shared_workload
run_attack_experiment syscall__shared_workload_model \
  --model-routing shared_workload

"$PYTHON_BIN" "$ROOT_DIR/assemble_syscall_evaluation_matrix.py" \
  --evidence-root "$EVIDENCE_ROOT" --derived-root "$DERIVED_ROOT" \
  --attack-root "$ATTACK_EXPERIMENT_ROOT" --falco-root "$FALCO_ROOT" \
  --contract "$EVIDENCE_ROOT/evaluation_matrix_contract.json" \
  --protocol "$EVALUATION_PROTOCOL" --attack-contract "$ATTACK_CONTRACT" \
  --output-root "$PAPER_MATRIX_ROOT"
(cd "$PAPER_MATRIX_ROOT" && sha256sum -c SHA256SUMS)
"$PYTHON_BIN" - "$PAPER_MATRIX_ROOT/evaluation_matrix_manifest.json" \
  "$PAPER_MATRIX_ROOT/paired_statistics.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if doc.get("valid") is not True or doc.get("completed_experiments") != 11:
    raise SystemExit("terminal syscall evaluation matrix is incomplete")
statistics = json.load(open(sys.argv[2]))
if statistics.get("methods") != 11 or statistics.get("pairwise_comparisons") != 55:
    raise SystemExit("terminal paired statistics are incomplete")
PY

find "$OUTPUT_ROOT" -maxdepth 1 -type f -name 'syscall__*.json' -print0 \
  | sort -z | xargs -0 sha256sum >"$OUTPUT_ROOT/SHA256SUMS"
touch "$DERIVED_ROOT/NORMAL_ABLATION_REPLAY_COMPLETE"
printf 'COMPLETE: 11-method paired syscall matrix assembled from %s\n' \
  "$OUTPUT_ROOT"
