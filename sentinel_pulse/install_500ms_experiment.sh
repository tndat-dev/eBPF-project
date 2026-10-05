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
REQUIRE_CONTROL_COLLECTOR=${REQUIRE_CONTROL_COLLECTOR:-true}
COLLECTOR_VARIANT=${COLLECTOR_VARIANT:-legacy}
PROJECTED_CANARY_RUN_DIR=${PROJECTED_CANARY_RUN_DIR:-}
MODEL_MANIFEST_SOURCE=${MODEL_MANIFEST_SOURCE:-}
TELEMETRY_NOMINAL_INTERVAL_SECONDS=${TELEMETRY_NOMINAL_INTERVAL_SECONDS:-0.5}
TELEMETRY_MINIMUM_AVAILABILITY=${TELEMETRY_MINIMUM_AVAILABILITY:-1.0}
TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS=${TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS:-0.8}
TELEMETRY_RECOVERY_PROFILE_SOURCE=${TELEMETRY_RECOVERY_PROFILE_SOURCE:-}
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
case "$REQUIRE_CONTROL_COLLECTOR" in
  true|false) ;;
  *) echo "REQUIRE_CONTROL_COLLECTOR must be true or false" >&2; exit 2 ;;
esac
case "$COLLECTOR_VARIANT" in
  legacy|projected) ;;
  *) echo "COLLECTOR_VARIANT must be legacy or projected" >&2; exit 2 ;;
esac
python3 - "$TELEMETRY_NOMINAL_INTERVAL_SECONDS" \
  "$TELEMETRY_MINIMUM_AVAILABILITY" \
  "$TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS" <<'PY'
import math, sys
nominal, availability, maximum_gap = map(float, sys.argv[1:])
if not all(map(math.isfinite, (nominal, availability, maximum_gap))):
    raise SystemExit("telemetry availability contract is not finite")
if nominal <= 0 or not 0 < availability <= 1 or maximum_gap < 0.8:
    raise SystemExit("invalid telemetry availability contract")
PY

# Validate opt-in recovery before any service/runtime/environment mutation.
# Recovery is a separately registered diagnostic protocol, never a relaxed
# legacy NORMAL_PASS. The formal launcher must not use this flag yet.
if [[ -n $TELEMETRY_RECOVERY_PROFILE_SOURCE ]]; then
  PYTHONPATH="$SOURCE_ROOT" python3 - "$TELEMETRY_RECOVERY_PROFILE_SOURCE" \
    "$TELEMETRY_NOMINAL_INTERVAL_SECONDS" "$TELEMETRY_MINIMUM_AVAILABILITY" \
    "$TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS" <<'PY'
from pathlib import Path
import sys
from sentinel_pulse.recovery_deployment import contract
contract(Path(sys.argv[1]), *map(float, sys.argv[2:]))
PY
fi

test -f "$UNIT_SOURCE"
test -x "$METRICS_SOURCE"
systemctl is-active --quiet sentinel-pulse-resolver.service
if [[ $REQUIRE_CONTROL_COLLECTOR == true ]]; then
  systemctl is-active --quiet sentinel-pulse-collector.service
else
  ! systemctl is-active --quiet sentinel-pulse-collector.service
fi
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

# Select a tested loader/object before any /opt, unit or environment mutation.
# Projected mode revalidates its complete raw safety capture and live revisions.
COLLECTOR_LOADER=/opt/sentinel-pulse/bin/pulse_counter_loader
COLLECTOR_OBJECT=/opt/sentinel-pulse/bin/pulse_counter.bpf.o
PROJECTED_SELECTION=
if [[ $COLLECTOR_VARIANT == projected ]]; then
  : "${PROJECTED_CANARY_RUN_DIR:?required for projected mode}"
  : "${MODEL_MANIFEST_SOURCE:?required for projected mode}"
  [[ $PROJECTED_CANARY_RUN_DIR == /var/lib/sentinel-pulse-projection-canary/* ]]
  command -v jq >/dev/null
  PROJECTED_SELECTION=$(PYTHONPATH="$SOURCE_ROOT" /opt/sentinel-pulse/venv/bin/python \
    -m sentinel_pulse.select_projected_collector \
    --canary-run-dir "$PROJECTED_CANARY_RUN_DIR" \
    --model-manifest "$MODEL_MANIFEST_SOURCE")
fi

# The collector starts before install_detector_candidate.sh. Deploy the exact
# minimal capture/validation package here too; otherwise a clean source root on
# a worker can invoke a stale module from an earlier experiment.
runtime_modules=(
  __init__.py capture.py encoding.py features.py integrity.py validate_capture.py cgroup_pressure.py
  telemetry_recovery.py
  recovery_deployment.py validate_recovery_capture.py inspect_recovery_tail.py inspect_feature_tail.py
)
for module in "${runtime_modules[@]}"; do
  test -f "$SOURCE_ROOT/sentinel_pulse/$module" || {
    echo "missing worker runtime module: sentinel_pulse/$module" >&2
    exit 3
  }
done
install -d -m 0755 /opt/sentinel-pulse/sentinel_pulse
for module in "${runtime_modules[@]}"; do
  install -m 0644 "$SOURCE_ROOT/sentinel_pulse/$module" \
    "/opt/sentinel-pulse/sentinel_pulse/$module"
  cmp -s "$SOURCE_ROOT/sentinel_pulse/$module" \
    "/opt/sentinel-pulse/sentinel_pulse/$module" || {
    echo "installed worker runtime differs: sentinel_pulse/$module" >&2
    exit 3
  }
done
capture_help=$(cd /opt/sentinel-pulse && /opt/sentinel-pulse/venv/bin/python \
  -m sentinel_pulse.capture --help)
[[ $capture_help == *--interval-min-seconds* &&
   $capture_help == *--interval-max-seconds* ]] || {
  echo 'installed capture does not support the bounded interval contract' >&2
  exit 3
}
validate_help=$(cd /opt/sentinel-pulse && /opt/sentinel-pulse/venv/bin/python \
  -m sentinel_pulse.validate_capture --help)
[[ $validate_help == *--minimum-telemetry-availability* &&
   $validate_help == *--maximum-single-gap-seconds* ]] || {
  echo 'installed validator does not support the telemetry availability contract' >&2
  exit 3
}

if [[ -n $TELEMETRY_RECOVERY_PROFILE_SOURCE ]]; then
  # Render the candidate unit only. The legacy source unit is left unchanged.
  PYTHONPATH="$SOURCE_ROOT" python3 - "$UNIT_SOURCE" \
    "/etc/systemd/system/$SERVICE" "$RUN_DIR/telemetry-recovery-profile.json" <<'PY'
from pathlib import Path
import sys
from sentinel_pulse.recovery_deployment import render_unit
Path(sys.argv[2]).write_text(render_unit(Path(sys.argv[1]).read_text(), "collector", sys.argv[3]))
PY
  chmod 0644 "/etc/systemd/system/$SERVICE"
else
  install -m 0644 "$UNIT_SOURCE" "/etc/systemd/system/$SERVICE"
fi
install -m 0755 "$METRICS_SOURCE" /opt/sentinel-pulse/bin/record_500ms_metrics
install -d -m 0750 "$ENV_DIR" "$STATE_ROOT"
install -d -m 0750 "$RUN_DIR"
if [[ -n $TELEMETRY_RECOVERY_PROFILE_SOURCE ]]; then
  install -m 0444 "$TELEMETRY_RECOVERY_PROFILE_SOURCE" "$RUN_DIR/telemetry-recovery-profile.json"
fi
if [[ $COLLECTOR_VARIANT == projected ]]; then
  PRIVATE_BIN=/opt/sentinel-pulse/experiments/$RUN_ID
  test ! -e "$PRIVATE_BIN"
  install -d -m 0755 "$PRIVATE_BIN"
  COLLECTOR_LOADER=$PRIVATE_BIN/pulse_counter_projected_loader
  COLLECTOR_OBJECT=$PRIVATE_BIN/pulse_counter_projected.bpf.o
  install -m 0555 "$(jq -er '.loader' <<<"$PROJECTED_SELECTION")" "$COLLECTOR_LOADER"
  install -m 0444 "$(jq -er '.bpf_object' <<<"$PROJECTED_SELECTION")" "$COLLECTOR_OBJECT"
  [[ $(sha256sum "$COLLECTOR_LOADER" | awk '{print $1}') == \
     $(jq -er '.loader_sha256' <<<"$PROJECTED_SELECTION") ]]
  [[ $(sha256sum "$COLLECTOR_OBJECT" | awk '{print $1}') == \
     $(jq -er '.bpf_object_sha256' <<<"$PROJECTED_SELECTION") ]]
  printf '%s\n' "$PROJECTED_SELECTION" >"$RUN_DIR/PROJECTED_SELECTION.json"
  chmod 0444 "$RUN_DIR/PROJECTED_SELECTION.json"
fi
cp --preserve=mode,timestamps /run/sentinel-pulse/cgroups.json "$RUN_DIR/cgroups-start.json"
cp --preserve=mode,timestamps /run/sentinel-pulse/allowed-cgroups "$RUN_DIR/allowed-cgroups-start"
cat >"$ENV_FILE.tmp" <<EOF
PULSE_500MS_DURATION_SECONDS=$DURATION_SECONDS
PULSE_500MS_OUTPUT=$OUTPUT
PULSE_500MS_RUN_ID=$RUN_ID
PULSE_500MS_RUN_DIR=$RUN_DIR
PULSE_500MS_COLLECTOR_VARIANT=$COLLECTOR_VARIANT
PULSE_500MS_LOADER=$COLLECTOR_LOADER
PULSE_500MS_BPF_OBJECT=$COLLECTOR_OBJECT
PULSE_TELEMETRY_NOMINAL_INTERVAL_SECONDS=$TELEMETRY_NOMINAL_INTERVAL_SECONDS
PULSE_TELEMETRY_MINIMUM_AVAILABILITY=$TELEMETRY_MINIMUM_AVAILABILITY
PULSE_TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS=$TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS
PULSE_TELEMETRY_RECOVERY_PROFILE=$(if [[ -n $TELEMETRY_RECOVERY_PROFILE_SOURCE ]]; then printf '%s' "$RUN_DIR/telemetry-recovery-profile.json"; fi)
EOF
install -m 0640 "$ENV_FILE.tmp" "$ENV_FILE"
rm -f "$ENV_FILE.tmp"

PYTHONPATH="$SOURCE_ROOT" /opt/sentinel-pulse/venv/bin/python - "$RUN_DIR/START.json" \
  "$TELEMETRY_NOMINAL_INTERVAL_SECONDS" \
  "$TELEMETRY_MINIMUM_AVAILABILITY" \
  "$TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS" \
  "$COLLECTOR_VARIANT" "$COLLECTOR_LOADER" "$COLLECTOR_OBJECT" <<'PY'
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

output = Path(sys.argv[1])
nominal_interval, minimum_availability, maximum_single_gap = map(float, sys.argv[2:5])
files = {
    "bpf_object": Path(sys.argv[7]),
    "loader": Path(sys.argv[6]),
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
    "collector_variant": sys.argv[5],
    "collector_loader": sys.argv[6],
    "collector_bpf_object": sys.argv[7],
    "sha256": hashes,
    "telemetry_availability_contract": {
        "nominal_interval_seconds": nominal_interval,
        "minimum_availability": minimum_availability,
        "maximum_single_gap_seconds": maximum_single_gap,
    },
}
recovery_path = output.parent / "telemetry-recovery-profile.json"
if recovery_path.exists():
    from sentinel_pulse.recovery_deployment import contract
    payload["telemetry_recovery_contract"] = contract(
        recovery_path, nominal_interval, minimum_availability, maximum_single_gap)
    payload["sha256"]["telemetry_recovery_profile"] = payload[
        "telemetry_recovery_contract"]["profile_file_sha256"]
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
