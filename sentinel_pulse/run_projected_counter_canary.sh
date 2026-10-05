#!/usr/bin/env bash
# Isolated collect-only safety experiment. Never installs/promotes the loader.
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'run as root' >&2; exit 2; }
SOURCE_ROOT=${SOURCE_ROOT:?point to the isolated source copy with projected build}
RUN_ID=${RUN_ID:?provide a fresh, immutable run ID}
DURATION_SECONDS=${DURATION_SECONDS:-900}
[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]] || exit 2
[[ $DURATION_SECONDS =~ ^[0-9]+$ ]] || exit 2
((DURATION_SECONDS >= 60 && DURATION_SECONDS <= 3600)) || exit 2
RUN_DIR="/var/lib/sentinel-pulse-projection-canary/$RUN_ID"
test ! -e "$RUN_DIR"
systemctl is-active --quiet sentinel-pulse-resolver.service
systemctl is-active --quiet sentinel-pulse-collector.service
if systemctl is-active --quiet sentinel-pulse-detector-candidate.service ||
   systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service; then
  echo 'projected canary must not overlap a candidate run' >&2
  exit 3
fi
test -s /run/sentinel-pulse/allowed-cgroups
test -x "$SOURCE_ROOT/sentinel_pulse/ebpf/pulse_counter_projected_loader"
test -r "$SOURCE_ROOT/sentinel_pulse/ebpf/pulse_counter_projected.bpf.o"
export PYTHONPATH="$SOURCE_ROOT"
PYTHON=/opt/sentinel-pulse/venv/bin/python
mkdir -m 0750 -p "$RUN_DIR"
export SOURCE_ROOT RUN_ID RUN_DIR DURATION_SECONDS
"$PYTHON" - <<'PY'
import hashlib, json, os, pathlib, platform, time
root=pathlib.Path(os.environ['SOURCE_ROOT'])
paths=('sentinel_pulse/ebpf/pulse_counter_projected_loader',
       'sentinel_pulse/ebpf/pulse_counter_projected.bpf.o',
       'sentinel_pulse/ebpf/pulse_counter.bpf.c',
       'sentinel_pulse/ebpf/pulse_counter_loader.c',
       'sentinel_pulse/ebpf/pulse_counter_projection.h',
       'sentinel_pulse/ebpf/pulse_counter_ids.h',
       'sentinel_pulse/capture.py','sentinel_pulse/features.py',
       'sentinel_pulse/encoding.py','sentinel_pulse/validate_capture.py',
       'sentinel_pulse/run_projected_counter_canary.sh')
run=pathlib.Path(os.environ['RUN_DIR'])
payload={'schema':'sentinel-pulse-projected-counter-canary-start-v1',
 'run_id':os.environ['RUN_ID'],'started_at_unix':time.time(),
 'registered_duration_seconds':int(os.environ['DURATION_SECONDS']),
 'kernel':platform.release(),'window_seconds':0.5,
 'evidence_class':'nonformal_collector_projection_safety_canary',
 'control_collector_remains_active':True,'ML_evaluation':False,
 'automatic_promotion':False,'source_root':str(root),
 'sha256':{p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths}}
with (run/'START.json').open('x') as out: json.dump(payload,out,indent=2)
for name in ('cgroups.json','allowed-cgroups'):
 (run/('start-'+name)).write_bytes((pathlib.Path('/run/sentinel-pulse')/name).read_bytes())
PY
set +e
(set +e
 timeout --signal=TERM --kill-after=10s "$DURATION_SECONDS" \
   "$SOURCE_ROOT/sentinel_pulse/ebpf/pulse_counter_projected_loader" \
   --object "$SOURCE_ROOT/sentinel_pulse/ebpf/pulse_counter_projected.bpf.o" \
   --allow-cgroup-file /run/sentinel-pulse/allowed-cgroups --interval-ms 500
 rc=$?
 [[ $rc -eq 0 || $rc -eq 124 ]]
) | "$PYTHON" -m sentinel_pulse.capture \
  --metadata-file /run/sentinel-pulse/cgroups.json --rolling-windows 10 \
  --interval-min-seconds 0.35 --interval-max-seconds 0.80 \
  --nominal-interval-seconds 0.5 --output "$RUN_DIR/features.jsonl"
capture_rc=$?
"$PYTHON" -m sentinel_pulse.validate_capture --capture "$RUN_DIR/features.jsonl" \
  --minimum-rows-per-workload 100 --interval-min-seconds 0.35 \
  --interval-max-seconds 0.80 --nominal-interval-seconds 0.5 \
  --minimum-telemetry-availability 1.0 --maximum-single-gap-seconds 0.80 \
  --output "$RUN_DIR/VALIDATION.json"
validation_rc=$?
export capture_rc validation_rc
"$PYTHON" - <<'PY'
import json,os,pathlib,time
run=pathlib.Path(os.environ['RUN_DIR'])
payload={'schema':'sentinel-pulse-projected-counter-canary-terminal-v1',
 'completed_at_unix':time.time(),'capture_exit_code':int(os.environ['capture_rc']),
 'validation_exit_code':int(os.environ['validation_rc']),
 'automatic_promotion':False,'ML_evaluation':False}
with (run/'TERMINAL.json').open('x') as out: json.dump(payload,out,indent=2)
PY
((capture_rc == 0 && validation_rc == 0))
