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
: "${AIMS_EVIDENCE_RELEASE:=v7}"
: "${AIMS_OVERHEAD_OUTPUT_ROOT:=$ROOT_DIR/aims-overhead-final}"
: "${SENTINEL_CONFIRMATION_FLOOR_RATIO:=0.94}"
: "${SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR:=0.45}"
: "${SENTINEL_FAST_PATH_CONFIRMATION_FLOOR:=0.20}"
: "${SENTINEL_EXTREME_VOLUME_FACTOR:=2.0}"
export AIMS_OVERHEAD_OUTPUT_ROOT SENTINEL_CONFIRMATION_FLOOR_RATIO \
  SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR \
  SENTINEL_FAST_PATH_CONFIRMATION_FLOOR SENTINEL_EXTREME_VOLUME_FACTOR
experiment_id=${SENTINEL_EXPERIMENT_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
output_root=$AIMS_OVERHEAD_OUTPUT_ROOT

for unit in aims-normal-matrix.service \
  aims-split-evaluation@independent_validation.service \
  aims-split-evaluation@blind_normal_test.service \
  aims-v8-capture.service aims-v8-post-capture.service \
  aims-v8-blind-attack.service aims-v8-normal-ablation.service; do
  if systemctl is-active --quiet "$unit"; then
    printf 'refusing overhead mutation while %s is active\n' "$unit" >&2
    exit 3
  fi
done

if [[ "$AIMS_EVIDENCE_RELEASE" == v8 ]]; then
  : "${AIMS_COMPLETION_MARKER:?}"
  mkdir -p "$output_root"
  prerequisite="$output_root/prerequisite-$experiment_id.json"
  "$PYTHON_BIN" "$ROOT_DIR/validate_v8_overhead_prerequisites.py" \
    --candidate "$AIMS_CANDIDATE" --calibration "$AIMS_CALIBRATION" \
    --normal-report "$AIMS_VALIDATION_REPORT" \
    --blind-report "$AIMS_BLIND_REPORT" \
    --completion-marker "$AIMS_COMPLETION_MARKER" --output "$prerequisite"
elif [[ "$AIMS_EVIDENCE_RELEASE" == v7 ]]; then
  "$PYTHON_BIN" - "$AIMS_VALIDATION_REPORT" "$AIMS_BLIND_REPORT" <<'PY'
import json, sys
for path, role in zip(sys.argv[1:], ("independent_validation", "blind_normal_test")):
    doc = json.load(open(path))
    if doc.get("role") != role or doc.get("status") != "complete" or doc.get("passed") is not True:
        raise SystemExit(f"required AIMS gate did not pass: {path}")
PY
  prerequisite=""
else
  printf 'unsupported AIMS_EVIDENCE_RELEASE=%s\n' "$AIMS_EVIDENCE_RELEASE" >&2
  exit 4
fi

cd "$ROOT_DIR"
runtime_unit=aims-candidate-runtime-benchmark.service
policy="$ROOT_DIR/tetragon-aims-policies.yaml"
url=${AIMS_BENCHMARK_URL:-http://10.103.205.176/api/products/}
wrk_threads=${AIMS_WRK_THREADS:-2}
wrk_concurrency=${AIMS_WRK_CONCURRENCY:-8}
wrk_duration=${AIMS_WRK_DURATION_SECONDS:-30}
wrk_repeats=${AIMS_WRK_REPEATS:-10}
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
  "$experiment_id" "$phase_order_raw" "$url" "$wrk_threads" \
  "$wrk_concurrency" "$wrk_duration" "$wrk_repeats" \
  "$prerequisite" "$AIMS_EVIDENCE_RELEASE" <<'PY'
import hashlib, json, os, sys
from pathlib import Path
prerequisite = Path(sys.argv[9]) if sys.argv[9] else None
candidate = Path(os.environ["AIMS_CANDIDATE"])
runtime_calibration = Path(
    os.environ["AIMS_OVERHEAD_OUTPUT_ROOT"]
) / f"calibration-{sys.argv[2]}.json"
candidate_hashes = {
    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(candidate.iterdir()) if path.is_file()
}
if not candidate_hashes:
    raise SystemExit("empty overhead candidate")
Path(sys.argv[1]).write_text(json.dumps({
    "schema": "sentinel-aims-overhead/v1",
    "experiment_id": sys.argv[2],
    "phase_order": sys.argv[3].split(","),
    "url": sys.argv[4],
    "wrk_threads": int(sys.argv[5]),
    "wrk_concurrency": int(sys.argv[6]),
    "duration_seconds_per_repetition": int(sys.argv[7]),
    "repetitions_per_phase": int(sys.argv[8]),
    "counterbalancing": "run all six permutations with distinct experiment IDs",
    "quality_gate": "zero socket errors and zero non-2xx/3xx responses",
    "evidence_release": sys.argv[10],
    "candidate": {
        "path": str(candidate.resolve()),
        "sha256": candidate_hashes,
    },
    "runtime_calibration": {
        "path": str(runtime_calibration.resolve()),
        "sha256": hashlib.sha256(runtime_calibration.read_bytes()).hexdigest(),
    },
    "detector_source_sha256": hashlib.sha256(
        Path("anomaly_detector2.py").read_bytes()
    ).hexdigest(),
    "confirmation_policy": {
        "confirmation_floor_ratio": float(
            os.environ["SENTINEL_CONFIRMATION_FLOOR_RATIO"]
        ),
        "behavior_confirmation_floor": float(
            os.environ["SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR"]
        ),
        "fast_path_confirmation_floor": float(
            os.environ["SENTINEL_FAST_PATH_CONFIRMATION_FLOOR"]
        ),
        "extreme_volume_factor": float(
            os.environ["SENTINEL_EXTREME_VOLUME_FACTOR"]
        ),
    },
    "prerequisite": ({
        "path": str(prerequisite.resolve()),
        "sha256": hashlib.sha256(prerequisite.read_bytes()).hexdigest(),
    } if prerequisite else None),
}, indent=2, sort_keys=True) + "\n")
PY

common=(
  --url "$url" --tool wrk --threads "$wrk_threads"
  --concurrency "$wrk_concurrency" --duration "$wrk_duration"
  --repeats "$wrk_repeats" --max-failed-requests 0
  --output-root "$output_root" --experiment-id "$experiment_id"
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
        --setenv=SENTINEL_CONFIRMATION_FLOOR_RATIO="$SENTINEL_CONFIRMATION_FLOOR_RATIO" \
        --setenv=SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR="$SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR" \
        --setenv=SENTINEL_FAST_PATH_CONFIRMATION_FLOOR="$SENTINEL_FAST_PATH_CONFIRMATION_FLOOR" \
        --setenv=SENTINEL_EXTREME_VOLUME_FACTOR="$SENTINEL_EXTREME_VOLUME_FACTOR" \
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
