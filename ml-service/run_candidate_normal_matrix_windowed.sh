#!/usr/bin/env bash
# Independent multi-regime false-positive gate for any window length.
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ -z ${KUBECONFIG:-} && -r /home/dat/.kube/sentinel-ha.conf ]]; then
  export KUBECONFIG=/home/dat/.kube/sentinel-ha.conf
fi
if [[ -z ${PYTHON_BIN:-} ]]; then
  if [[ -x /home/dat/ml-venv/bin/python ]]; then
    PYTHON_BIN=/home/dat/ml-venv/bin/python
  else
    PYTHON_BIN=python3
  fi
fi
CANDIDATE=${1:?usage: $0 <candidate-model-directory>}
WINDOW_SECONDS=${CANDIDATE_WINDOW_SECONDS:-10}
PHASE_SECONDS=${CANDIDATE_PHASE_SECONDS:-180}
SETTLE_SECONDS=${CANDIDATE_SETTLE_SECONDS:-20}
MIN_WINDOWS=${CANDIDATE_MIN_WINDOWS_PER_PHASE:-12}
NGINX_URL=${CANDIDATE_NGINX_URL:-http://nginx.production.svc.cluster.local/}
STAMP=${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
: "${SENTINEL_CONFIRMATION_FLOOR_RATIO:=0.94}"
: "${SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR:=0.45}"
: "${SENTINEL_FAST_PATH_CONFIRMATION_FLOOR:=0.20}"
: "${SENTINEL_POD_STARTUP_GRACE_SECONDS:=60}"
: "${SENTINEL_EXTREME_VOLUME_FACTOR:=2.0}"
export SENTINEL_CONFIRMATION_FLOOR_RATIO SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR
export SENTINEL_FAST_PATH_CONFIRMATION_FLOOR SENTINEL_POD_STARTUP_GRACE_SECONDS
export SENTINEL_EXTREME_VOLUME_FACTOR

cd "$ROOT_DIR"
candidate=$(realpath "$CANDIDATE")
vocab="$candidate/vocab.pkl"
(( WINDOW_SECONDS >= 5 )) || { printf 'window must be >= 5 seconds\n' >&2; exit 2; }
(( PHASE_SECONDS >= WINDOW_SECONDS * MIN_WINDOWS )) || {
  printf 'phase duration does not yield enough windows\n' >&2; exit 3;
}
[[ -r "$vocab" ]] || { printf 'candidate vocabulary missing\n' >&2; exit 4; }

require_tetragon_coverage() {
  local coverage desired ready available
  coverage=$(kubectl -n kube-system get daemonset tetragon \
    -o jsonpath='{.status.desiredNumberScheduled},{.status.numberReady},{.status.numberAvailable}') || {
    printf 'refusing validation: cannot read Tetragon DaemonSet status\n' >&2
    exit 8
  }
  IFS=',' read -r desired ready available <<<"$coverage"
  [[ "$desired" =~ ^[0-9]+$ && "$desired" -gt 0 && "$ready" == "$desired" && "$available" == "$desired" ]] || {
    printf 'refusing validation: Tetragon coverage is desired=%s ready=%s available=%s\n' \
      "$desired" "$ready" "$available" >&2
    exit 8
  }
}

require_tetragon_coverage

metrics="candidate-window${WINDOW_SECONDS}-normal-${STAMP}.jsonl"
calibration="candidate-window${WINDOW_SECONDS}-normal-calibration-${STAMP}.json"
report="candidate-window${WINDOW_SECONDS}-normal-report-${STAMP}.json"
detector_log="candidate-window${WINDOW_SECONDS}-normal-${STAMP}.log"
timing="candidate-window${WINDOW_SECONDS}-normal-phases-${STAMP}.tsv"
prefix="candidate-window${WINDOW_SECONDS}-normal-phase-${STAMP}"
detector_pid=""
traffic_pid=""

scale_load() {
  kubectl scale deployment/loadgen -n production --replicas="$1" >/dev/null
  kubectl scale deployment/redis-loadgen -n production --replicas="$2" >/dev/null
  kubectl scale deployment/postgres-loadgen -n default --replicas="$3" >/dev/null
  kubectl rollout status deployment/loadgen -n production --timeout=120s >/dev/null
  kubectl rollout status deployment/redis-loadgen -n production --timeout=120s >/dev/null
  kubectl rollout status deployment/postgres-loadgen -n default --timeout=120s >/dev/null
}

cleanup() {
  [[ -z "$traffic_pid" ]] || { kill "$traffic_pid" >/dev/null 2>&1 || true; wait "$traffic_pid" >/dev/null 2>&1 || true; }
  [[ -z "$detector_pid" ]] || { kill -TERM "$detector_pid" >/dev/null 2>&1 || true; wait "$detector_pid" >/dev/null 2>&1 || true; }
  scale_load 1 1 1 || true
}
trap cleanup EXIT INT TERM

start_in_cluster_burst() {
  local duration_seconds="$1" pod remote_script
  pod=$(kubectl -n production get pod -l app=loadgen \
    -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}' \
    | awk '{print $1}')
  [[ -n "$pod" ]] || { printf 'no running production/loadgen pod\n' >&2; return 1; }
  kubectl -n production exec "$pod" -- \
    wget -q -O /dev/null "$NGINX_URL"
  printf -v remote_script 'end=$(( $(date +%%s) + %q )); url=%q; worker() { while [ "$(date +%%s)" -lt "$end" ]; do wget -q -O /dev/null "$url" || exit 1; done; }; worker & worker & worker & worker & wait' \
    "$duration_seconds" "$NGINX_URL"
  kubectl -n production exec "$pod" -- sh -c "$remote_script" \
    >"/tmp/sentinel-window${WINDOW_SECONDS}-in-cluster-burst-${STAMP}.log" 2>&1 &
  traffic_pid=$!
}

measure() {
  local name="$1" started ended
  require_tetragon_coverage
  sleep "$SETTLE_SECONDS"
  started=$(date +%s.%N)
  sleep "$PHASE_SECONDS"
  ended=$(date +%s.%N)
  printf '%s\t%s\t%s\n' "$name" "$started" "$ended" >>"$timing"
}

SENTINEL_METRICS="$ROOT_DIR/$metrics" \
SENTINEL_CALIBRATION="$ROOT_DIR/$calibration" \
SENTINEL_WARMUP_WINDOWS=10 SENTINEL_MIN_EVENTS=20 \
SENTINEL_QUEUE_SIZE=100000 SENTINEL_CONSUMER_LOG_INTERVAL=100000 \
SENTINEL_REQUIRE_FULL_TETRAGON_COVERAGE=true SENTINEL_TETRAGON_DAEMONSET=tetragon \
  "$PYTHON_BIN" -u anomaly_detector2.py --mode kubectl --model-dir "$candidate" \
  --vocab "$vocab" --window "$WINDOW_SECONDS" --threshold 0.80 --dry-run \
  >"$detector_log" 2>&1 &
detector_pid=$!

for _ in $(seq 1 30); do
  grep -q 'Anomaly Detector khởi động' "$detector_log" 2>/dev/null && break
  kill -0 "$detector_pid" 2>/dev/null || { tail -100 "$detector_log" >&2; exit 5; }
  sleep 1
done
grep -q 'Anomaly Detector khởi động' "$detector_log" || exit 6

scale_load 1 1 1
measure normal-1x
start_in_cluster_burst "$((PHASE_SECONDS + SETTLE_SECONDS + 5))"
measure in-cluster-burst
wait "$traffic_pid" || {
  printf 'in-cluster burst failed; see /tmp/sentinel-window%s-in-cluster-burst-%s.log\n' \
    "$WINDOW_SECONDS" "$STAMP" >&2
  exit 9
}
traffic_pid=""
scale_load 4 2 3
measure high-mixed
scale_load 1 1 1
measure recovery-1x

kill -TERM "$detector_pid"; wait "$detector_pid" || true; detector_pid=""

"$PYTHON_BIN" analyze_normal_run.py "$metrics" \
  --minimum-windows "$((MIN_WINDOWS * 4))" --minimum-events 20 \
  --threshold 0.80 --max-score-exceedances 0 --require-healthy-sensors \
  --output "$report" || true
while IFS=$'\t' read -r name started ended; do
  "$PYTHON_BIN" analyze_normal_run.py "$metrics" --minimum-windows "$MIN_WINDOWS" \
    --minimum-events 20 --threshold 0.80 --max-score-exceedances 0 \
    --require-healthy-sensors \
    --since-ts "$started" --until-ts "$ended" --output "${prefix}-${name}.json" || true
done <"$timing"

"$PYTHON_BIN" - "$report" "$timing" "$prefix" "$candidate" "$vocab" "$calibration" "$WINDOW_SECONDS" <<'PY'
import hashlib, json, os, sys
from pathlib import Path
from artifact_integrity import model_release_hashes

report_path, timing_path, prefix, candidate, vocab, calibration = map(Path, sys.argv[1:7])
window = int(sys.argv[7])
runtime_files = (
    "adaptive_threshold.py", "anomaly_detector2.py", "feature_engineering.py",
    "graph_signals.py", "ml_models.py", "tetragon_consumer.py",
    "sentinel/fast_path.py", "sentinel/telemetry.py",
)
runtime_hashes = {
    name: hashlib.sha256(Path(name).read_bytes()).hexdigest()
    for name in runtime_files
}
report = json.loads(report_path.read_text())
regimes = {}
for line in timing_path.read_text().splitlines():
    name, started, ended = line.split("\t")
    phase = json.loads(Path(f"{prefix}-{name}.json").read_text())
    phase.update(measurement_start=float(started), measurement_end=float(ended))
    regimes[name] = phase
digest = hashlib.sha256(vocab.read_bytes()).hexdigest()
report.update(candidate=str(candidate.resolve()), vocab=str(vocab.resolve()),
              vocab_sha256=digest, calibration=str(calibration.resolve()),
              calibration_sha256=hashlib.sha256(calibration.read_bytes()).hexdigest(),
              window_seconds=window, regimes=regimes,
              confirmation_policy={
                  "hysteresis_ratio": float(os.environ.get("SENTINEL_CONFIRMATION_FLOOR_RATIO", "1.0")),
                  "behavior_confirmation_floor": float(os.environ.get("SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR", ".8")),
                  "fast_path_confirmation_floor": float(os.environ.get("SENTINEL_FAST_PATH_CONFIRMATION_FLOOR", ".8")),
                  "pod_startup_grace_seconds": float(os.environ.get("SENTINEL_POD_STARTUP_GRACE_SECONDS", "0")),
                  "extreme_volume_factor": float(os.environ.get("SENTINEL_EXTREME_VOLUME_FACTOR", "2.0")),
              },
              runtime_code_sha256=runtime_hashes,
              model_release_sha256=model_release_hashes(candidate))
report["passed"] = bool(report.get("passed") and len(regimes) == 4 and
                        all(item.get("passed") for item in regimes.values()))
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps({"passed": report["passed"], "report": str(report_path)}))
raise SystemExit(0 if report["passed"] else 7)
PY
