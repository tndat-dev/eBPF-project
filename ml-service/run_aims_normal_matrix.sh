#!/usr/bin/env bash
# Long-running independent normal matrix for the AIMS syscall candidate.
# Default: 4 regimes x 5 runs x 72 minutes = 24 hours of capture.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RUNS_PER_REGIME=${RUNS_PER_REGIME:-5}
MINUTES_PER_RUN=${MINUTES_PER_RUN:-72}
SETTLE_SECONDS=${SETTLE_SECONDS:-30}
STAMP=${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
FEATURE_CAPTURE_MODE=${AIMS_FEATURE_CAPTURE_MODE:-off}
CAPTURE_RELEASE_ID=${AIMS_CAPTURE_RELEASE_ID:-}
ACTIVE_ROOT_FILE=${AIMS_ACTIVE_ROOT_FILE:-"$ROOT_DIR/.aims-normal-matrix-active"}
if [[ -n "${EVIDENCE_ROOT:-}" ]]; then
  EVIDENCE_ROOT=$EVIDENCE_ROOT
elif [[ -s "$ACTIVE_ROOT_FILE" ]]; then
  EVIDENCE_ROOT=$(<"$ACTIVE_ROOT_FILE")
else
  EVIDENCE_ROOT="$ROOT_DIR/aims-normal-matrix-$STAMP"
  temporary_active="$ACTIVE_ROOT_FILE.tmp.$$"
  printf '%s\n' "$EVIDENCE_ROOT" >"$temporary_active"
  mv "$temporary_active" "$ACTIVE_ROOT_FILE"
fi
if [[ "$FEATURE_CAPTURE_MODE" == "off" ]]; then
  case "$EVIDENCE_ROOT" in
    "$ROOT_DIR"/aims-normal-matrix-*) ;;
    *) printf 'unsafe AIMS evidence root: %s\n' "$EVIDENCE_ROOT" >&2; exit 2 ;;
  esac
elif [[ "$EVIDENCE_ROOT" != "$ROOT_DIR/aims-v8-capture-$CAPTURE_RELEASE_ID" ]]; then
  printf 'V8 evidence root must bind the release ID: %s\n' "$EVIDENCE_ROOT" >&2
  exit 2
fi
REGIMES=(steady burst recovery toolmix)
POLICY=${SENTINEL_POLICY:-"$ROOT_DIR/tetragon-aims-policies.yaml"}
[[ -r "$POLICY" ]] || POLICY="$ROOT_DIR/../sentinel/k8s/tetragon-aims-policies.yaml"
LOADGEN=${SENTINEL_LOADGEN_MANIFEST:-"$ROOT_DIR/aims-sentinel-loadgen.yaml"}
[[ -r "$LOADGEN" ]] || LOADGEN="$ROOT_DIR/../sentinel/k8s/aims-sentinel-loadgen.yaml"
PYTHON_BIN=${PYTHON_BIN:-/home/dat/ml-venv/bin/python}
[[ -x "$PYTHON_BIN" ]] || PYTHON_BIN=${PYTHON_BIN_FALLBACK:-python3}
CAPTURE_SPLIT_CONTRACT=${AIMS_CAPTURE_SPLIT_CONTRACT:-"$ROOT_DIR/v8_capture_split_contract.json"}
EVALUATION_CONTRACT=${AIMS_EVALUATION_CONTRACT:-"$ROOT_DIR/evaluation_matrix_contract.json"}
VOCAB=${SENTINEL_VOCAB:-"$ROOT_DIR/models/vocab.pkl"}
if [[ "$FEATURE_CAPTURE_MODE" != "off" && -z "$CAPTURE_RELEASE_ID" ]]; then
  printf 'AIMS_CAPTURE_RELEASE_ID is required when feature capture is enabled\n' >&2
  exit 2
fi
if [[ "$FEATURE_CAPTURE_MODE" != "off" ]]; then
  "$PYTHON_BIN" "$ROOT_DIR/validate_v8_capture_contract.py" \
    --contract "$CAPTURE_SPLIT_CONTRACT" \
    --evaluation-contract "$EVALUATION_CONTRACT" --vocab "$VOCAB"
  read -r contract_runs contract_minutes < <(
    "$PYTHON_BIN" - "$CAPTURE_SPLIT_CONTRACT" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
print(len(doc["normal"]["runs"]), doc["normal"]["minutes_per_phase"])
PY
  )
  if (( RUNS_PER_REGIME != contract_runs || MINUTES_PER_RUN != contract_minutes )); then
    printf 'capture runtime differs from frozen split: runs=%s/%s minutes=%s/%s\n' \
      "$RUNS_PER_REGIME" "$contract_runs" "$MINUTES_PER_RUN" "$contract_minutes" >&2
    exit 2
  fi
fi

mkdir -p "$EVIDENCE_ROOT"

snapshot_file() {
  local source=$1 destination=$2
  if [[ -e "$destination" ]]; then
    cmp -s "$source" "$destination" || {
      printf 'experiment artifact changed during resume: %s\n' "$destination" >&2
      return 3
    }
  else
    cp "$source" "$destination"
  fi
}

snapshot_file "$ROOT_DIR/aims_release_contract.json" \
  "$EVIDENCE_ROOT/aims_release_contract.json"
snapshot_file "$POLICY" "$EVIDENCE_ROOT/tetragon-aims-policies.yaml"
snapshot_file "$LOADGEN" "$EVIDENCE_ROOT/aims-sentinel-loadgen.yaml"
if [[ "$FEATURE_CAPTURE_MODE" != "off" ]]; then
  snapshot_file "$CAPTURE_SPLIT_CONTRACT" \
    "$EVIDENCE_ROOT/v8_capture_split_contract.json"
  snapshot_file "$EVALUATION_CONTRACT" \
    "$EVIDENCE_ROOT/evaluation_matrix_contract.json"
fi
[[ -e "$EVIDENCE_ROOT/nodes-before.txt" ]] || \
  kubectl get nodes -o wide >"$EVIDENCE_ROOT/nodes-before.txt"
[[ -e "$EVIDENCE_ROOT/pods-before.txt" ]] || \
  kubectl -n production get pods -o wide >"$EVIDENCE_ROOT/pods-before.txt"
[[ -e "$EVIDENCE_ROOT/tetragon-policy-live.yaml" ]] || \
  kubectl -n production get tracingpolicynamespaced sentinel-aims-syscalls -o yaml \
    >"$EVIDENCE_ROOT/tetragon-policy-live.yaml"

phase_is_valid() {
  local phase=$1
  "$PYTHON_BIN" - "$ROOT_DIR" "$EVIDENCE_ROOT" \
    "$RUNS_PER_REGIME" "$MINUTES_PER_RUN" "$phase" \
    "$FEATURE_CAPTURE_MODE" "$CAPTURE_RELEASE_ID" <<'PY'
import hashlib, json, pathlib, re, sys
sys.path.insert(0, sys.argv[1])
from aims_matrix_validation import validate_matrix
from validate_feature_capture import validate_capture

root = pathlib.Path(sys.argv[2])
contract = json.loads((pathlib.Path(sys.argv[1]) / "aims_release_contract.json").read_text())
report = validate_matrix(
    root, contract,
    runs_per_regime=int(sys.argv[3]),
    minutes_per_run=int(sys.argv[4]),
)
phase = sys.argv[5]
capture_mode, release_id = sys.argv[6:8]
capture = next((row for row in report["captures"] if row["phase"] == phase), None)
stable_artifacts = all(
    len(values) <= 1 for values in report["artifact_digests"].values()
)
capture_valid = True
if capture_mode != "off":
    phase_root = (root / phase).resolve()
    try:
        manifest = json.loads((phase_root / "collection_manifest.json").read_text())
        feature = manifest["paired_feature_capture"]
        capture_path = pathlib.Path(feature["path"]).resolve()
        match = re.fullmatch(r"aims-([a-z]+)-run-([0-9]+)", phase)
        context = feature["context"]
        validation = validate_capture(capture_path)
        capture_valid = bool(
            match
            and capture_path.is_relative_to(phase_root)
            and feature["mode"] == capture_mode
            and not feature["append_failures"]
            and feature["sha256"] == hashlib.sha256(capture_path.read_bytes()).hexdigest()
            and feature["validation"].get("valid") is True
            and validation["valid"]
            and context == {
                "release_id": release_id,
                "run_id": f"normal-run-{int(match.group(2)):02d}",
                "phase_id": phase,
                "traffic_regime": match.group(1),
            }
        )
    except (KeyError, OSError, ValueError, json.JSONDecodeError):
        capture_valid = False
raise SystemExit(
    0 if capture and capture["valid"] and stable_artifacts and capture_valid else 1
)
PY
}

restore_steady() {
  "$ROOT_DIR/set_aims_traffic_regime.sh" steady >/dev/null 2>&1 || true
}
trap restore_steady EXIT INT TERM

for run in $(seq 1 "$RUNS_PER_REGIME"); do
  for regime in "${REGIMES[@]}"; do
    phase=$(printf 'aims-%s-run-%02d' "$regime" "$run")
    output="$EVIDENCE_ROOT/$phase"
    if [[ -d "$output" ]] && phase_is_valid "$phase"; then
      printf 'RESUME: keeping valid phase %s\n' "$phase"
      continue
    fi
    if [[ -e "$output" ]]; then
      rejected="$EVIDENCE_ROOT/rejected/${phase}-$(date -u +%Y%m%dT%H%M%SZ)"
      mkdir -p "$(dirname "$rejected")"
      mv "$output" "$rejected"
      printf 'RESUME: moved invalid phase to %s\n' "$rejected" >&2
    fi
    "$ROOT_DIR/set_aims_traffic_regime.sh" "$regime"
    sleep "$SETTLE_SECONDS"
    capture_environment=(
      "SENTINEL_FEATURE_CAPTURE=$FEATURE_CAPTURE_MODE"
    )
    if [[ "$FEATURE_CAPTURE_MODE" != "off" ]]; then
      capture_environment+=(
        "SENTINEL_FEATURE_CAPTURE_PATH=$output/feature-capture.jsonl"
        "SENTINEL_CAPTURE_RELEASE_ID=$CAPTURE_RELEASE_ID"
        "SENTINEL_CAPTURE_RUN_ID=normal-run-$(printf '%02d' "$run")"
        "SENTINEL_CAPTURE_PHASE_ID=$phase"
        "SENTINEL_CAPTURE_TRAFFIC_REGIME=$regime"
      )
    fi
    env "${capture_environment[@]}" MIN_WINDOWS=30 MAX_WINDOWS_PER_TARGET=0 \
      "$ROOT_DIR/run_aims_candidate.sh" collect "$phase" \
      "$MINUTES_PER_RUN" "$output"
  done
done

restore_steady
trap - EXIT INT TERM
kubectl -n production get pods -o wide >"$EVIDENCE_ROOT/pods-after.txt"
validation_rc=0
"$PYTHON_BIN" "$ROOT_DIR/aims_matrix_validation.py" "$EVIDENCE_ROOT" \
  --contract "$ROOT_DIR/aims_release_contract.json" \
  --runs-per-regime "$RUNS_PER_REGIME" \
  --minutes-per-run "$MINUTES_PER_RUN" || validation_rc=$?

if (( validation_rc == 0 )) && [[ "$FEATURE_CAPTURE_MODE" != "off" ]]; then
  mapfile -t captures < <(
    find "$EVIDENCE_ROOT" -mindepth 2 -maxdepth 2 -type f \
      -name feature-capture.jsonl -print | sort
  )
  expected_capture_count=$(( RUNS_PER_REGIME * ${#REGIMES[@]} ))
  if (( ${#captures[@]} != expected_capture_count )); then
    printf 'expected %d feature captures, found %d\n' \
      "$expected_capture_count" "${#captures[@]}" >&2
    validation_rc=8
  else
    "$PYTHON_BIN" "$ROOT_DIR/merge_feature_captures.py" "${captures[@]}" \
      --output "$EVIDENCE_ROOT/frozen-normal-feature-capture.jsonl" \
      || validation_rc=$?
  fi
fi

find "$EVIDENCE_ROOT" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum \
  >"$EVIDENCE_ROOT/SHA256SUMS"
if (( validation_rc == 0 )) && [[ -s "$ACTIVE_ROOT_FILE" ]] \
    && [[ "$(<"$ACTIVE_ROOT_FILE")" == "$EVIDENCE_ROOT" ]]; then
  mv "$ACTIVE_ROOT_FILE" "$ACTIVE_ROOT_FILE.completed-$STAMP"
fi
exit "$validation_rc"
