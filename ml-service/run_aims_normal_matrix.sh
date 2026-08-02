#!/usr/bin/env bash
# Long-running independent normal matrix for the AIMS syscall candidate.
# Default: 4 regimes x 5 runs x 72 minutes = 24 hours of capture.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RUNS_PER_REGIME=${RUNS_PER_REGIME:-5}
MINUTES_PER_RUN=${MINUTES_PER_RUN:-72}
SETTLE_SECONDS=${SETTLE_SECONDS:-30}
STAMP=${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-"$ROOT_DIR/aims-normal-matrix-$STAMP"}
REGIMES=(steady burst recovery toolmix)
POLICY=${SENTINEL_POLICY:-"$ROOT_DIR/tetragon-aims-policies.yaml"}
[[ -r "$POLICY" ]] || POLICY="$ROOT_DIR/../sentinel/k8s/tetragon-aims-policies.yaml"
LOADGEN=${SENTINEL_LOADGEN_MANIFEST:-"$ROOT_DIR/aims-sentinel-loadgen.yaml"}
[[ -r "$LOADGEN" ]] || LOADGEN="$ROOT_DIR/../sentinel/k8s/aims-sentinel-loadgen.yaml"
PYTHON_BIN=${PYTHON_BIN:-/home/dat/ml-venv/bin/python}
[[ -x "$PYTHON_BIN" ]] || PYTHON_BIN=${PYTHON_BIN_FALLBACK:-python3}

mkdir -p "$EVIDENCE_ROOT"
cp "$ROOT_DIR/aims_release_contract.json" "$EVIDENCE_ROOT/"
cp "$POLICY" "$EVIDENCE_ROOT/tetragon-aims-policies.yaml"
cp "$LOADGEN" "$EVIDENCE_ROOT/aims-sentinel-loadgen.yaml"
kubectl get nodes -o wide >"$EVIDENCE_ROOT/nodes-before.txt"
kubectl -n production get pods -o wide >"$EVIDENCE_ROOT/pods-before.txt"
kubectl -n production get tracingpolicynamespaced sentinel-aims-syscalls -o yaml \
  >"$EVIDENCE_ROOT/tetragon-policy-live.yaml"

restore_steady() {
  "$ROOT_DIR/set_aims_traffic_regime.sh" steady >/dev/null 2>&1 || true
}
trap restore_steady EXIT INT TERM

for run in $(seq 1 "$RUNS_PER_REGIME"); do
  for regime in "${REGIMES[@]}"; do
    phase=$(printf 'aims-%s-run-%02d' "$regime" "$run")
    output="$EVIDENCE_ROOT/$phase"
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
exit "$validation_rc"
