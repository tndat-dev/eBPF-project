#!/usr/bin/env bash
# Install an isolated collect-only 500 ms experiment. It never enables itself.
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "install_500ms_experiment.sh must run as root" >&2
  exit 2
fi

SOURCE_ROOT=${SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
SERVICE=sentinel-pulse-collector-500ms-experiment.service
UNIT_SOURCE="$SOURCE_ROOT/sentinel_pulse/systemd/$SERVICE"
METRICS_SOURCE="$SOURCE_ROOT/sentinel_pulse/record_500ms_metrics.sh"
DURATION_SECONDS=${DURATION_SECONDS:-900}
RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
STATE_ROOT=/var/lib/sentinel-pulse-500ms/runs
RUN_DIR="$STATE_ROOT/$RUN_ID"
OUTPUT="$RUN_DIR/features.jsonl"
ENV_DIR=/etc/sentinel-pulse
ENV_FILE="$ENV_DIR/500ms-experiment.env"

if [[ ! $DURATION_SECONDS =~ ^[0-9]+$ ]] ||
   ((DURATION_SECONDS < 60 || DURATION_SECONDS > 90000)); then
  echo "DURATION_SECONDS must be an integer from 60 through 90000" >&2
  exit 2
fi
if [[ ! $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "RUN_ID contains unsafe characters" >&2
  exit 2
fi

test -f "$UNIT_SOURCE"
test -x "$METRICS_SOURCE"
systemctl is-active --quiet sentinel-pulse-resolver.service
systemctl is-active --quiet sentinel-pulse-collector.service
test -s /run/sentinel-pulse/allowed-cgroups
test -x /opt/sentinel-pulse/bin/pulse_counter_loader
test -f /opt/sentinel-pulse/bin/pulse_counter.bpf.o
test -x /opt/sentinel-pulse/venv/bin/python
if systemctl is-active --quiet "$SERVICE"; then
  echo "$SERVICE is already active" >&2
  exit 3
fi
if [[ -e $RUN_DIR ]]; then
  echo "run already exists: $RUN_DIR" >&2
  exit 3
fi

install -m 0644 "$UNIT_SOURCE" "/etc/systemd/system/$SERVICE"
install -m 0755 "$METRICS_SOURCE" /opt/sentinel-pulse/bin/record_500ms_metrics
install -d -m 0750 "$ENV_DIR" "$STATE_ROOT"
install -d -m 0750 "$RUN_DIR"
cp --preserve=mode,timestamps /run/sentinel-pulse/cgroups.json "$RUN_DIR/cgroups-start.json"
cp --preserve=mode,timestamps /run/sentinel-pulse/allowed-cgroups "$RUN_DIR/allowed-cgroups-start"
cat >"$ENV_FILE.tmp" <<EOF
PULSE_500MS_DURATION_SECONDS=$DURATION_SECONDS
PULSE_500MS_OUTPUT=$OUTPUT
PULSE_500MS_RUN_ID=$RUN_ID
PULSE_500MS_RUN_DIR=$RUN_DIR
EOF
install -m 0640 "$ENV_FILE.tmp" "$ENV_FILE"
rm -f "$ENV_FILE.tmp"

/opt/sentinel-pulse/venv/bin/python - "$RUN_DIR/START.json" <<'PY'
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

output = Path(sys.argv[1])
files = {
    "bpf_object": Path("/opt/sentinel-pulse/bin/pulse_counter.bpf.o"),
    "loader": Path("/opt/sentinel-pulse/bin/pulse_counter_loader"),
    "unit": Path("/etc/systemd/system/sentinel-pulse-collector-500ms-experiment.service"),
    "metadata": output.parent / "cgroups-start.json",
    "allowlist": output.parent / "allowed-cgroups-start",
}
hashes = {
    name: hashlib.sha256(path.read_bytes()).hexdigest()
    for name, path in files.items()
}
payload = {
    "schema": "sentinel-pulse-500ms-start-v1",
    "started_at_unix": time.time(),
    "kernel": platform.release(),
    "sha256": hashes,
}
output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
chmod 0444 "$RUN_DIR/START.json" "$RUN_DIR/cgroups-start.json" \
  "$RUN_DIR/allowed-cgroups-start"
systemctl show sentinel-pulse-collector.service \
  -p CPUUsageNSec -p MemoryCurrent -p MemoryPeak -p TasksCurrent \
  >"$RUN_DIR/control-collector-start.systemd"
cat /proc/loadavg >"$RUN_DIR/loadavg-start.txt"
systemctl daemon-reload
systemctl start "$SERVICE"

for _attempt in $(seq 1 30); do
  if systemctl is-active --quiet "$SERVICE" && \
     test -s "$OUTPUT"; then
    break
  fi
  sleep 1
done

if ! systemctl is-active --quiet "$SERVICE" || \
   ! test -s "$OUTPUT"; then
  journalctl -u "$SERVICE" -n 80 --no-pager >&2 || true
  systemctl stop "$SERVICE" || true
  exit 3
fi

ENABLEMENT=$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)
case "$ENABLEMENT" in
  enabled|enabled-runtime|linked|linked-runtime|alias)
    echo "500ms experiment must never be enabled at boot: $ENABLEMENT" >&2
    systemctl stop "$SERVICE" || true
    exit 4
    ;;
  static|disabled|indirect|generated|transient)
    ;;
  *)
    echo "unexpected systemd enablement state: $ENABLEMENT" >&2
    systemctl stop "$SERVICE" || true
    exit 4
    ;;
esac

printf '500ms collect-only experiment active; output=%s rows=%s\n' \
  "$OUTPUT" \
  "$(wc -l <"$OUTPUT")"
