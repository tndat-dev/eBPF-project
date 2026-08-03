#!/usr/bin/env bash
# Controlled AIMS no-tracing/Tetragon/full-candidate overhead experiment.
# This intentionally refuses to run while collection/evaluation is active.
set -Eeuo pipefail

ROOT_DIR=/home/dat/ml-service
PYTHON_BIN=${PYTHON_BIN:-/home/dat/ml-venv/bin/python}
export KUBECONFIG=${KUBECONFIG:-/home/dat/.kube/sentinel-ha.conf}
ENV_FILE=${AIMS_EVALUATION_ENV:-$ROOT_DIR/aims-evaluation.env}
[[ -r "$ENV_FILE" ]] || { printf 'missing AIMS environment: %s\n' "$ENV_FILE" >&2; exit 2; }
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
: "${AIMS_CANDIDATE:?}"
: "${AIMS_CALIBRATION:?}"
: "${AIMS_VALIDATION_REPORT:?}"
: "${AIMS_BLIND_REPORT:?}"

for unit in aims-normal-matrix.service aims-candidate-fit-v1.service \
  aims-split-evaluation@independent_validation.service \
  aims-split-evaluation@blind_normal_test.service; do
  if systemctl is-active --quiet "$unit"; then
    printf 'refusing overhead mutation while %s is active\n' "$unit" >&2
    exit 3
  fi
done

"$PYTHON_BIN" - "$AIMS_VALIDATION_REPORT" "$AIMS_BLIND_REPORT" <<'PY'
import json, sys
for path, role in zip(sys.argv[1:], ("independent_validation", "blind_normal_test")):
    doc = json.load(open(path))
    if doc.get("role") != role or doc.get("status") != "complete" or doc.get("passed") is not True:
        raise SystemExit(f"required AIMS gate did not pass: {path}")
PY

cd "$ROOT_DIR"
experiment_id=${SENTINEL_EXPERIMENT_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
output_root="$ROOT_DIR/aims-overhead-final"
runtime_unit=aims-candidate-runtime-benchmark.service
policy="$ROOT_DIR/tetragon-aims-policies.yaml"
url=${AIMS_BENCHMARK_URL:-http://10.103.205.176/api/products/}
phase_order_raw=${AIMS_PHASE_ORDER:-no_tracing,tetragon_only,full_pipeline}
case "$phase_order_raw" in
  no_tracing,tetragon_only,full_pipeline|no_tracing,full_pipeline,tetragon_only|\
  tetragon_only,no_tracing,full_pipeline|tetragon_only,full_pipeline,no_tracing|\
  full_pipeline,no_tracing,tetragon_only|full_pipeline,tetragon_only,no_tracing) ;;
  *) printf 'AIMS_PHASE_ORDER must be one permutation of the three phases\n' >&2; exit 4 ;;
esac
IFS=',' read -r -a phase_order <<<"$phase_order_raw"
runtime_calibration="$output_root/calibration-$experiment_id.json"
mkdir -p "$output_root"
cp "$AIMS_CALIBRATION" "$runtime_calibration"

restore_runtime() {
  systemctl stop "$runtime_unit" >/dev/null 2>&1 || true
  kubectl apply -f "$policy" >/dev/null 2>&1 || true
  systemctl start sentinel-detector.service >/dev/null 2>&1 || true
}
trap restore_runtime EXIT INT TERM

systemctl stop sentinel-detector.service
"$ROOT_DIR/sentinel/benchmarks/capture_environment.sh" \
  "$output_root/environment-$experiment_id.txt"
"$PYTHON_BIN" - "$output_root/protocol-$experiment_id.json" \
  "$experiment_id" "$phase_order_raw" "$url" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema": "sentinel-aims-overhead/v1",
    "experiment_id": sys.argv[2],
    "phase_order": sys.argv[3].split(","),
    "url": sys.argv[4],
    "counterbalancing": "run all six permutations with distinct experiment IDs",
    "repetitions_per_phase": 10,
    "duration_seconds_per_repetition": 30,
}, indent=2, sort_keys=True) + "\n")
PY

common=(
  --url "$url" --tool wrk --threads 4 --concurrency 50 --duration 30
  --repeats 10 --output-root "$output_root" --experiment-id "$experiment_id"
  --detector-unit "$runtime_unit" --workload-namespace production
)
for prefix in aims-frontend- api-gateway- auth-service- cart-service- \
  catalog-service- inventory-service- order-service- security-telemetry-service-; do
  common+=(--workload-prefix "$prefix")
done

configure_phase() {
  local phase=$1
  systemctl stop "$runtime_unit" >/dev/null 2>&1 || true
  case "$phase" in
    no_tracing)
      kubectl -n production delete tracingpolicynamespaced \
        sentinel-aims-syscalls --ignore-not-found
      ;;
    tetragon_only)
      kubectl apply -f "$policy"
      ;;
    full_pipeline)
      kubectl apply -f "$policy"
      cp "$AIMS_CALIBRATION" "$runtime_calibration"
      systemd-run --unit="$runtime_unit" --property=User=dat \
        --property=WorkingDirectory="$ROOT_DIR" --property=Nice=10 \
        --property=CPUQuota=200% --property=MemoryMax=8G \
        --setenv=KUBECONFIG="$KUBECONFIG" \
        --setenv=SENTINEL_CALIBRATION="$runtime_calibration" \
        --setenv=SENTINEL_MIN_EVENTS=10 --setenv=SENTINEL_WINDOW_SECONDS=10 \
        --setenv=SENTINEL_POD_STARTUP_GRACE_SECONDS=60 \
        "$PYTHON_BIN" -u anomaly_detector2.py --mode kubectl \
        --model-dir "$AIMS_CANDIDATE" --vocab "$AIMS_CANDIDATE/vocab.pkl" \
        --window 10 --threshold 0.80 --dry-run
      ;;
  esac
  sleep 60
  if [[ "$phase" == full_pipeline ]]; then
    systemctl is-active --quiet "$runtime_unit"
  fi
}

for phase in "${phase_order[@]}"; do
  configure_phase "$phase"
  "$PYTHON_BIN" sentinel/benchmarks/measure_phase.py \
    --phase "$phase" "${common[@]}"
done

restore_runtime
trap - EXIT INT TERM
"$PYTHON_BIN" sentinel/benchmarks/compare_overhead.py \
  --root "$output_root" --tool wrk --experiment-id "$experiment_id" \
  --environment "$output_root/environment-$experiment_id.txt" \
  --protocol "$output_root/protocol-$experiment_id.json" \
  --output "$output_root/comparison-wrk-$experiment_id.json"
printf 'AIMS_OVERHEAD_COMPLETE experiment_id=%s\n' "$experiment_id"
