#!/usr/bin/env bash
# Launch the readonly observer and verify actual data, not systemd-run's enqueue.
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'run as root' >&2; exit 2; }
SOURCE_ROOT=${SOURCE_ROOT:?explicit frozen source root required}
RUN_ID=${RUN_ID:?new diagnostic evidence ID required}
UNIT_NAME=${UNIT_NAME:?new systemd unit name required}
DURATION_SECONDS=${DURATION_SECONDS:-7800}
[[ $SOURCE_ROOT =~ ^/home/dat/[A-Za-z0-9._-]+$ ]]
[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $UNIT_NAME =~ ^sentinel-pulse-pressure-diagnostic-[A-Za-z0-9._-]+$ ]]
[[ $DURATION_SECONDS =~ ^[0-9]+$ ]] && ((DURATION_SECONDS >= 60 && DURATION_SECONDS <= 90000))
script="$SOURCE_ROOT/sentinel_pulse/record_node_pressure.sh"
run_dir="/var/lib/sentinel-pulse-diagnostics/$RUN_ID"
test -r "$script"
test -r "$SOURCE_ROOT/sentinel_pulse/node_clock_probe.py"
test -r "$SOURCE_ROOT/sentinel_pulse/cgroup_pressure.py"
test ! -e "$run_dir"
# Never overwrite/restart a previous diagnostic unit or its evidence.
[[ $(systemctl show "$UNIT_NAME.service" -p LoadState --value) == not-found ]]
# Git may retain a script as 0644. Invoke the interpreter explicitly; changing
# a frozen source's executable bit would change its source contract.
systemd-run --no-block --unit="$UNIT_NAME" --property=Type=exec \
  /usr/bin/env RUN_ID="$RUN_ID" DURATION_SECONDS="$DURATION_SECONDS" \
  /bin/bash "$script"
for ((attempt=0; attempt<20; attempt++)); do
  state=$(systemctl show "$UNIT_NAME.service" -p ActiveState --value)
  [[ $state != failed && $state != inactive ]] || {
    echo "observer failed before readiness: $state" >&2; exit 3;
  }
  if [[ $state == active && -s $run_dir/START.txt && -s $run_dir/clock.jsonl && -s $run_dir/sar.bin ]] &&
      (( $(wc -l < "$run_dir/clock.jsonl") >= 2 )); then
    # The first sample must parse, and the three source hashes must match.
    python3 - "$run_dir/clock.jsonl" <<'PY'
import json, pathlib, sys
with pathlib.Path(sys.argv[1]).open() as source:
    start = json.loads(source.readline())
    sample = json.loads(source.readline())
assert start.get("record_type") == "start"
assert sample.get("record_type") == "sample" and "service_cgroups" in sample
PY
    sha256sum -c "$run_dir/SOURCE_SHA256SUMS" >/dev/null
    printf 'observer_ready_at=%s\nunit=%s\nrun_dir=%s\n' \
      "$(date -u +%FT%TZ)" "$UNIT_NAME.service" "$run_dir"
    exit 0
  fi
  sleep 1
done
echo 'observer has no verified samples within 20 seconds' >&2
exit 3
