#!/usr/bin/env bash
# Long-running independent normal matrix for the AIMS syscall candidate.
# Default: 4 regimes x 5 runs x 72 minutes = 24 hours of capture.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RUNS_PER_REGIME=${RUNS_PER_REGIME:-5}
MINUTES_PER_RUN=${MINUTES_PER_RUN:-72}
SETTLE_SECONDS=${SETTLE_SECONDS:-30}
STAMP=${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
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
case "$EVIDENCE_ROOT" in
  "$ROOT_DIR"/aims-normal-matrix-*) ;;
  *) printf 'unsafe AIMS evidence root: %s\n' "$EVIDENCE_ROOT" >&2; exit 2 ;;
esac
REGIMES=(steady burst recovery toolmix)
POLICY=${SENTINEL_POLICY:-"$ROOT_DIR/tetragon-aims-policies.yaml"}
[[ -r "$POLICY" ]] || POLICY="$ROOT_DIR/../sentinel/k8s/tetragon-aims-policies.yaml"
LOADGEN=${SENTINEL_LOADGEN_MANIFEST:-"$ROOT_DIR/aims-sentinel-loadgen.yaml"}
[[ -r "$LOADGEN" ]] || LOADGEN="$ROOT_DIR/../sentinel/k8s/aims-sentinel-loadgen.yaml"
PYTHON_BIN=${PYTHON_BIN:-/home/dat/ml-venv/bin/python}
[[ -x "$PYTHON_BIN" ]] || PYTHON_BIN=${PYTHON_BIN_FALLBACK:-python3}

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
    "$RUNS_PER_REGIME" "$MINUTES_PER_RUN" "$phase" <<'PY'
import json, pathlib, sys
sys.path.insert(0, sys.argv[1])
from aims_matrix_validation import validate_matrix

root = pathlib.Path(sys.argv[2])
contract = json.loads((pathlib.Path(sys.argv[1]) / "aims_release_contract.json").read_text())
report = validate_matrix(
    root, contract,
    runs_per_regime=int(sys.argv[3]),
    minutes_per_run=int(sys.argv[4]),
)
phase = sys.argv[5]
capture = next((row for row in report["captures"] if row["phase"] == phase), None)
stable_artifacts = all(
    len(values) <= 1 for values in report["artifact_digests"].values()
)
raise SystemExit(0 if capture and capture["valid"] and stable_artifacts else 1)
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
    MIN_WINDOWS=30 MAX_WINDOWS_PER_TARGET=0 \
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

find "$EVIDENCE_ROOT" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum \
  >"$EVIDENCE_ROOT/SHA256SUMS"
if (( validation_rc == 0 )) && [[ -s "$ACTIVE_ROOT_FILE" ]] \
    && [[ "$(<"$ACTIVE_ROOT_FILE")" == "$EVIDENCE_ROOT" ]]; then
  mv "$ACTIVE_ROOT_FILE" "$ACTIVE_ROOT_FILE.completed-$STAMP"
fi
exit "$validation_rc"
