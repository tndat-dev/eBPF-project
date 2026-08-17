#!/usr/bin/env bash
# ExecStopPost helper: preserve cgroup counters before systemd removes them.
set -euo pipefail

: "${PULSE_500MS_RUN_DIR:?missing PULSE_500MS_RUN_DIR}"
EXPECTED_PREFIX=/var/lib/sentinel-pulse-500ms/runs/
if [[ $PULSE_500MS_RUN_DIR != "$EXPECTED_PREFIX"* ]] ||
   [[ ! -d $PULSE_500MS_RUN_DIR ]]; then
  echo "unsafe 500ms run directory: $PULSE_500MS_RUN_DIR" >&2
  exit 2
fi

CGROUP=/sys/fs/cgroup/system.slice/sentinel-pulse-collector-500ms-experiment.service
{
  printf 'stopped_at_unix '
  date +%s.%N
  cat "$CGROUP/cpu.stat"
  printf 'memory_current_bytes '
  cat "$CGROUP/memory.current"
  printf 'memory_peak_bytes '
  cat "$CGROUP/memory.peak"
  printf 'pids_current '
  cat "$CGROUP/pids.current"
} >"$PULSE_500MS_RUN_DIR/experiment-cgroup-final.txt"

systemctl show sentinel-pulse-collector.service \
  -p CPUUsageNSec -p MemoryCurrent -p MemoryPeak -p TasksCurrent \
  >"$PULSE_500MS_RUN_DIR/control-collector-at-experiment-end.systemd"
cat /proc/loadavg >"$PULSE_500MS_RUN_DIR/loadavg-at-experiment-end.txt"
