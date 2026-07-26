#!/usr/bin/env bash
# Validate a candidate against independent normal operating regimes.
set -Eeuo pipefail

cd /home/dat/ml-service
export KUBECONFIG=/home/dat/.kube/config

candidate="${1:?usage: $0 models_candidate_v7-TIMESTAMP}"
candidate_vocab="${candidate}/vocab.pkl"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
metrics="candidate-v7-normal-${stamp}.jsonl"
calibration="candidate-v7-normal-calibration-${stamp}.json"
report="candidate-v7-normal-report-${stamp}.json"
detector_log="candidate-v7-normal-${stamp}.log"
timing="candidate-v7-normal-phases-${stamp}.tsv"
phase_report_prefix="candidate-v7-normal-phase-${stamp}"
detector_pid=""
wrk_pid=""
phase_seconds="${CANDIDATE_PHASE_SECONDS:-300}"
settle_seconds="${CANDIDATE_SETTLE_SECONDS:-35}"
minimum_phase_windows="${CANDIDATE_MIN_WINDOWS_PER_PHASE:-8}"

if (( phase_seconds < minimum_phase_windows * 30 )); then
  echo "phase duration is too short for requested minimum windows" >&2
  exit 2
fi
[[ -f "$candidate_vocab" ]] || {
  echo "candidate vocabulary not found: $candidate_vocab" >&2
  exit 3
}

scale_load() {
  kubectl scale deployment/loadgen -n production --replicas="$1" >/dev/null
  kubectl scale deployment/redis-loadgen -n production --replicas="$2" >/dev/null
  kubectl scale deployment/postgres-loadgen -n default --replicas="$3" >/dev/null
}

stop_wrk() {
  if [[ -n "$wrk_pid" ]]; then
    kill "$wrk_pid" >/dev/null 2>&1 || true
    wait "$wrk_pid" >/dev/null 2>&1 || true
    wrk_pid=""
  fi
}

cleanup() {
  stop_wrk
  if [[ -n "$detector_pid" ]]; then
    kill -TERM "$detector_pid" >/dev/null 2>&1 || true
    wait "$detector_pid" >/dev/null 2>&1 || true
  fi
  scale_load 1 1 1 || true
  chown dat:dat "$metrics" "$calibration" "$report" "$detector_log" "$timing" \
    "${phase_report_prefix}"-*.json \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

measure_regime() {
  local name="$1"
  echo "NORMAL_REGIME_SETTLE name=${name} seconds=${settle_seconds}"
  sleep "$settle_seconds"
  local started ended
  started="$(date +%s.%N)"
  echo "NORMAL_REGIME_MEASURE name=${name} seconds=${phase_seconds} start=${started}"
  sleep "$phase_seconds"
  ended="$(date +%s.%N)"
  printf '%s\t%s\t%s\n' "$name" "$started" "$ended" >>"$timing"
}

SENTINEL_METRICS="$PWD/$metrics" \
SENTINEL_CALIBRATION="$PWD/$calibration" \
SENTINEL_WARMUP_WINDOWS=10 \
SENTINEL_MIN_EVENTS=20 \
SENTINEL_QUEUE_SIZE=100000 \
  /home/dat/ml-venv/bin/python -u anomaly_detector2.py \
    --mode kubectl --model-dir "$candidate" --window 30 \
    --vocab "$candidate_vocab" --threshold 0.80 --dry-run \
    >"$detector_log" 2>&1 &
detector_pid=$!

for _ in $(seq 1 30); do
  grep -q 'Anomaly Detector khởi động' "$detector_log" 2>/dev/null && break
  kill -0 "$detector_pid" 2>/dev/null || {
    tail -n 80 "$detector_log" >&2
    exit 4
  }
  sleep 1
done
grep -q 'Anomaly Detector khởi động' "$detector_log" || {
  tail -n 80 "$detector_log" >&2
  exit 5
}

scale_load 1 1 1
measure_regime normal-1x

wrk -t4 -c50 -d"$((phase_seconds + settle_seconds + 30))s" \
  --latency http://10.103.40.121/ \
  >"/tmp/sentinel-candidate-normal-wrk-${stamp}.log" 2>&1 &
wrk_pid=$!
measure_regime wrk-c50
stop_wrk

scale_load 4 2 3
measure_regime high-mixed

scale_load 1 1 1
measure_regime recovery-1x

kill -TERM "$detector_pid"
wait "$detector_pid" || true
detector_pid=""

aggregate_failed=0
if ! /home/dat/ml-venv/bin/python analyze_normal_run.py "$metrics" \
  --minimum-windows "$((minimum_phase_windows * 4))" \
  --minimum-events 20 --threshold 0.80 \
  --max-score-exceedances 0 --output "$report"; then
  aggregate_failed=1
fi

phase_failed=0
while IFS=$'\t' read -r name started ended; do
  if ! /home/dat/ml-venv/bin/python analyze_normal_run.py "$metrics" \
    --minimum-windows "$minimum_phase_windows" --minimum-events 20 \
    --threshold 0.80 --max-score-exceedances 0 \
    --since-ts "$started" --until-ts "$ended" \
    --output "${phase_report_prefix}-${name}.json"; then
    phase_failed=1
  fi
done <"$timing"

/home/dat/ml-venv/bin/python - "$report" "$timing" "$phase_report_prefix" \
  "$aggregate_failed" "$phase_failed" "$candidate" "$candidate_vocab" \
  "$calibration" "$metrics" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

from artifact_integrity import model_release_hashes

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

report_path = Path(sys.argv[1])
timing_path = Path(sys.argv[2])
prefix = sys.argv[3]
aggregate_failed = bool(int(sys.argv[4]))
phase_failed = bool(int(sys.argv[5]))
candidate = Path(sys.argv[6]).resolve()
vocab = Path(sys.argv[7]).resolve()
calibration = Path(sys.argv[8]).resolve()
metrics = Path(sys.argv[9]).resolve()
report = json.loads(report_path.read_text())
regimes = {}
for line in timing_path.read_text().splitlines():
    name, started, ended = line.split("\t")
    phase = json.loads(Path(f"{prefix}-{name}.json").read_text())
    phase["measurement_start"] = float(started)
    phase["measurement_end"] = float(ended)
    regimes[name] = phase
report["regimes"] = regimes
report["candidate"] = str(candidate)
report["model_release_sha256"] = model_release_hashes(candidate)
report["vocab"] = str(vocab)
report["vocab_sha256"] = sha256(vocab)
report["calibration"] = str(calibration)
report["calibration_sha256"] = sha256(calibration)
report["metrics_sha256"] = sha256(metrics)
runtime_files = (
    "adaptive_threshold.py", "anomaly_detector2.py", "feature_engineering.py",
    "graph_signals.py", "ml_models.py", "tetragon_consumer.py",
    "sentinel/telemetry.py",
)
report["runtime_code_sha256"] = {
    name: sha256(Path(name).resolve()) for name in runtime_files
}
report["validation_harness_sha256"] = sha256(
    Path("run_candidate_normal_matrix.sh").resolve()
)
report["passed"] = bool(
    report.get("passed")
    and not aggregate_failed
    and not phase_failed
    and len(regimes) == 4
    and all(item.get("passed") for item in regimes.values())
)
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps({
    "normal_matrix_passed": report["passed"],
    "regimes": {key: value.get("passed") for key, value in regimes.items()},
}, sort_keys=True))
raise SystemExit(0 if report["passed"] else 7)
PY

cleanup
trap - EXIT INT TERM
echo "CANDIDATE_NORMAL_COMPLETE candidate=${candidate} report=${report} calibration=${calibration}"
