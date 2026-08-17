#!/usr/bin/env bash
# Validate and freeze one completed 500 ms collect-only experiment.
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "finalize_500ms_experiment.sh must run as root" >&2
  exit 2
fi

SERVICE=sentinel-pulse-collector-500ms-experiment.service
ENV_FILE=/etc/sentinel-pulse/500ms-experiment.env
MINIMUM_ROWS_PER_WORKLOAD=${MINIMUM_ROWS_PER_WORKLOAD:-20}

test -f "$ENV_FILE"
# The file is root-owned and generated from validated values by the installer.
# shellcheck disable=SC1090
source "$ENV_FILE"
: "${PULSE_500MS_OUTPUT:?missing PULSE_500MS_OUTPUT}"
: "${PULSE_500MS_RUN_ID:?missing PULSE_500MS_RUN_ID}"

RUN_DIR=$(dirname "$PULSE_500MS_OUTPUT")
EXPECTED_DIR="/var/lib/sentinel-pulse-500ms/runs/$PULSE_500MS_RUN_ID"
if [[ $RUN_DIR != "$EXPECTED_DIR" ]] || [[ ! -d $RUN_DIR ]]; then
  echo "unsafe or mismatched experiment run directory: $RUN_DIR" >&2
  exit 2
fi
if systemctl is-active --quiet "$SERVICE"; then
  echo "$SERVICE is still active; wait for its registered duration" >&2
  exit 3
fi
test -s "$PULSE_500MS_OUTPUT"
test -s "$RUN_DIR/START.json"
test -s "$RUN_DIR/experiment-cgroup-final.txt"
test -s "$RUN_DIR/control-collector-at-experiment-end.systemd"
cd /opt/sentinel-pulse

systemctl show "$SERVICE" \
  -p Result -p ExecMainStatus -p CPUUsageNSec -p MemoryCurrent -p MemoryPeak \
  -p TasksCurrent -p ActiveEnterTimestamp -p InactiveEnterTimestamp \
  >"$RUN_DIR/experiment-final.systemd"
systemctl show sentinel-pulse-collector.service \
  -p CPUUsageNSec -p MemoryCurrent -p MemoryPeak -p TasksCurrent \
  >"$RUN_DIR/control-collector-final.systemd"
cat /proc/loadavg >"$RUN_DIR/loadavg-final.txt"

set +e
/opt/sentinel-pulse/venv/bin/python -m sentinel_pulse.validate_capture \
  --capture "$PULSE_500MS_OUTPUT" \
  --minimum-rows-per-workload "$MINIMUM_ROWS_PER_WORKLOAD" \
  --interval-min-seconds 0.35 \
  --interval-max-seconds 0.80 \
  --output "$RUN_DIR/validation.json"
VALIDATION_RC=$?
set -e

/opt/sentinel-pulse/venv/bin/python - \
  "$RUN_DIR" "$VALIDATION_RC" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import time

run_dir = Path(sys.argv[1])
validation_rc = int(sys.argv[2])

def properties(path: Path) -> dict:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            parts = line.split(None, 1)
            if len(parts) == 2:
                key, value = parts
                separator = " "
        if separator:
            values[key] = value.strip()
    return values

def integer(values: dict, key: str) -> int:
    try:
        return int(values.get(key, "0") or 0)
    except ValueError:
        return 0

start = json.loads((run_dir / "START.json").read_text(encoding="utf-8"))
validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
control_start = properties(run_dir / "control-collector-start.systemd")
control_final = properties(run_dir / "control-collector-at-experiment-end.systemd")
experiment = properties(run_dir / "experiment-final.systemd")
experiment_cgroup = properties(run_dir / "experiment-cgroup-final.txt")
capture = run_dir / "features.jsonl"
ended_at = time.time()
registered_duration = int(
    properties(Path("/etc/sentinel-pulse/500ms-experiment.env")).get(
        "PULSE_500MS_DURATION_SECONDS", "0"
    )
)
stopped_at = float(experiment_cgroup.get("stopped_at_unix", ended_at))
duration = max(0.0, stopped_at - float(start["started_at_unix"]))
control_cpu_ns = max(
    0,
    integer(control_final, "CPUUsageNSec") - integer(control_start, "CPUUsageNSec"),
)
experiment_cpu_ns = integer(experiment_cgroup, "usage_usec") * 1000
service_ok = (
    experiment.get("Result") == "success"
    and integer(experiment, "ExecMainStatus") == 0
)
payload = {
    "schema": "sentinel-pulse-500ms-final-v1",
    "run_id": run_dir.name,
    "started_at_unix": start["started_at_unix"],
    "ended_at_unix": stopped_at,
    "duration_seconds": duration,
    "registered_max_duration_seconds": registered_duration,
    "finalized_at_unix": ended_at,
    "valid": validation_rc == 0 and validation.get("valid") is True and service_ok,
    "service_ok": service_ok,
    "service_result": experiment.get("Result"),
    "capture_sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
    "capture_bytes": capture.stat().st_size,
    "rows": validation.get("rows", 0),
    "workload_count": len(validation.get("workloads", {})),
    "interval_seconds": validation.get("interval_seconds", {}),
    "ingest_lag_seconds": validation.get("ingest_lag_seconds", {}),
    "window_start_to_emit_seconds": validation.get(
        "window_start_to_emit_seconds", {}
    ),
    "snapshot_read_seconds": validation.get("snapshot_read_seconds", {}),
    "collector_max_drops": validation.get("collector_max_drops", {}),
    "control_collector_cpu_seconds": control_cpu_ns / 1e9,
    "experiment_cpu_seconds": experiment_cpu_ns / 1e9,
    "experiment_average_cpu_cores": (
        experiment_cpu_ns / 1e9 / duration if duration else 0.0
    ),
    "experiment_memory_peak_bytes": integer(experiment_cgroup, "memory_peak_bytes"),
    "validation_errors": validation.get("errors", []),
}
(run_dir / "FINAL.json").write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

sha256sum "$RUN_DIR"/features.jsonl "$RUN_DIR"/START.json \
  "$RUN_DIR"/validation.json "$RUN_DIR"/FINAL.json \
  >"$RUN_DIR/SHA256SUMS"
chmod 0444 "$RUN_DIR"/*

cat "$RUN_DIR/FINAL.json"
if ((VALIDATION_RC != 0)); then
  exit "$VALIDATION_RC"
fi
/opt/sentinel-pulse/venv/bin/python - "$RUN_DIR/FINAL.json" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
raise SystemExit(0 if report.get("valid") is True else 1)
PY
