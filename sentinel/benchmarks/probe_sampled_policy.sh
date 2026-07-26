#!/usr/bin/env bash
# Fail-fast load probe for the Tetragon sampling policy before long collection.
set -Eeuo pipefail

cd /home/dat/ml-service
export KUBECONFIG=/home/dat/.kube/config

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
output="sampled-policy-probe-${stamp}"
wrk_log="/tmp/sentinel-policy-probe-wrk-${stamp}.log"
wrk_pid=""

cleanup() {
  if [[ -n "$wrk_pid" ]]; then
    kill "$wrk_pid" >/dev/null 2>&1 || true
    wait "$wrk_pid" >/dev/null 2>&1 || true
  fi
  chown -R dat:dat "$output" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

wrk -t4 -c50 -d150s --latency http://10.103.40.121/ >"$wrk_log" 2>&1 &
wrk_pid=$!

COLLECT_MINUTES=3 \
WINDOW_SECONDS=30 \
MIN_EVENTS=20 \
MIN_WINDOWS=3 \
MAX_WINDOWS_PER_TARGET=3 \
MIN_COLLECT_MINUTES=0 \
BASELINE_PHASE=sampled-policy-probe-wrk-c50 \
TRAINING_OUTPUT_DIR="$output" \
  /home/dat/ml-venv/bin/python collect_real_baseline.py

/home/dat/ml-venv/bin/python - "$output" <<'PY'
import json
import statistics
import sys
from collections import Counter
from pathlib import Path

directory = Path(sys.argv[1])
manifest = json.loads((directory / "collection_manifest.json").read_text())
report = {
    "dataset": str(directory.resolve()),
    "sensor_health": manifest.get("sensor_health", {}),
    "targets": {},
}
passed = report["sensor_health"].get("backpressure_events", 0) == 0
for pod_key, target in sorted(manifest["targets"].items()):
    metadata = directory / f"{pod_key.replace('/', '__')}_metadata.jsonl"
    rows = [json.loads(line) for line in metadata.read_text().splitlines()]
    counts = [int(row["event_count"]) for row in rows]
    syscalls = Counter()
    for row in rows:
        syscalls.update(row["syscall_counts"])
    ceiling = 2000 if pod_key == "production/nginx" else 5000
    target_passed = len(rows) == 3 and max(counts) <= ceiling
    passed = passed and target_passed
    report["targets"][pod_key] = {
        "windows": len(rows),
        "event_count_min": min(counts),
        "event_count_median": statistics.median(counts),
        "event_count_max": max(counts),
        "event_count_ceiling": ceiling,
        "syscall_totals": dict(syscalls.most_common()),
        "passed": target_passed,
    }
report["passed"] = passed
path = directory / "policy_probe_report.json"
path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps(report, indent=2, sort_keys=True))
raise SystemExit(0 if passed else 6)
PY

cleanup
trap - EXIT INT TERM
echo "SAMPLED_POLICY_PROBE_COMPLETE output=${output}"
