#!/usr/bin/env bash
# Analyses registered for the final-system run (protocol final-system-confirmation-v1), on .234 as root (RCA cases
# are root-owned; outputs are chowned to dat).
#
#   STAGE=campaign  once the campaign is TERMINAL (light, allowed during capture): ML expectations (arm A) on the
#                   primary rates and per rate, RCA coverage / ranking / latency (RCA from Alertmanager alerts;
#                   grouped-after-benign count for the distinct benign path), kernel -> recipient on the push path for
#                   the system (episodes opened by ML or tripwire), bridge counters
#   STAGE=final     after all three workers are TERMINAL (reads features + decisions: heavy, no live run): window table,
#                   ML live burden, tripwire A1 offline (same reference span and exec set), live tripwire + agreement
#                   + frame lag, system A vs S (rule_comparison, live tripwire), the same with the offline tripwire,
#                   frame lag of pulse-peer-discount-confirm for comparison, cadence gaps, RCA taxonomy, zombies
#
#   SRC=/mnt/.../source STAGE=campaign|final [RUN=/mnt/.../<run>] bash final_system_analysis.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
STAGE=${STAGE:?campaign or final}
RUN=${RUN:-/mnt/sentinel-pulse-archive/pulse-final-system-confirm}
NAME=$(basename "$RUN")
CAMPAIGN=$RUN/pulse-development-matrix
OUT=${OUT:-$RUN/analysis}
RCA=${RCA:-/var/lib/sentinel-pulse-rca/rca-$NAME}
BRIDGE=${BRIDGE:-/var/lib/sentinel-pulse-alert-bridge/$NAME}
PREVIOUS=/mnt/sentinel-pulse-archive/pulse-peer-discount-confirm
REFRESHED=/mnt/sentinel-pulse-archive/matched-r6-20261018/analysis-20261019/pulse-stable-candidate-selection/calibration-r6-1300-1900.npz
B=/var/tmp/burden-levers
NODES=(k8s-worker1.local k8s-worker4.local k8s-worker3.local)
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
mkdir -p "$OUT"; cd /tmp
try() { "$@" || echo "FAILED($?): $*" >&2; }
cfg() { python3 -c "import json;print(json.load(open('$RUN/CONFIG.json'))['$1'])"; }
ATTACKS_FROM=$(cfg attack_not_before)
SEL_START=$(cfg selection_start)
SEL_END=$(cfg selection_end)
EXEC_SET=$(python3 -c "import json;print(json.load(open('$RUN/CONFIG.json'))['tripwire']['exec_set'])")

if [ "$STAGE" = campaign ]; then
  test -f "$CAMPAIGN/TERMINAL.json" || exit 1
  try cp "$CAMPAIGN/RESULTS.json" "$OUT/campaign-RESULTS.json"
  try $PY "$SRC/scripts/analysis/confirm_campaign.py" --campaign "$CAMPAIGN" --output "$OUT/confirm-campaign.json"
  try $PY "$SRC/scripts/analysis/attack_vs_benign.py" --campaign "$CAMPAIGN" --output "$OUT/attack-vs-benign.json"
  try $PY "$SRC/scripts/analysis/rca_coverage.py" --cases "$RCA/cases" --campaign "$CAMPAIGN" --since "$ATTACKS_FROM" \
    --output "$OUT/rca-coverage.json"
  FROZEN=$(python3 -c "print($ATTACKS_FROM - 120)")
  try $PY -m sentinel_pulse.rca.evaluate_ranking --cases "$RCA/cases" --campaign "$CAMPAIGN" --output "$OUT/rca-ranking-stored.json"
  try $PY -m sentinel_pulse.rca.evaluate_ranking --cases "$RCA/cases" --campaign "$CAMPAIGN" --output "$OUT/rca-ranking-reranked.json" \
    --rerank-db "$RCA/context.sqlite3" --frozen-at "$FROZEN"
  try $PY "$SRC/scripts/analysis/rca_latency.py" --copy-dir "$RCA" --output "$OUT/rca-latency.json"
  try $PY "$SRC/scripts/analysis/rca_flow_coverage.py" --cases "$RCA/cases" --since "$ATTACKS_FROM" --output "$OUT/rca-flow-coverage.json"
  try cp "$RCA/STATUS.json" "$OUT/rca-status-after-campaign.json"
  BSINCE=$(python3 -c "import json;print(json.load(open('$BRIDGE/START.json'))['started_at'])" 2>/dev/null || echo "$ATTACKS_FROM")
  try python3 "$SRC/scripts/analysis/alert_delivery_latency.py" --results "$CAMPAIGN/RESULTS.json" --bridge "$BRIDGE" \
    --since "$BSINCE" --output "$OUT/delivery-latency-campaign.json"
  try cp "$BRIDGE/STATUS.json" "$OUT/bridge-status-after-campaign.json"
  chown -R dat:dat "$OUT" 2>/dev/null || true
  exit 0
fi

# ---- final: after the capture ----
for node in "${NODES[@]}"; do test -f "$RUN/workers/$node/TERMINAL.json" || exit 1; done
CAPTURE_END=$(python3 -c "import glob,json;print(max(json.load(open(p))['finished_at_unix'] for p in glob.glob('$RUN/workers/*/TERMINAL.json')))")
roots=(); for node in "${NODES[@]}"; do roots+=(--worker-root "$RUN/workers/$node"); done
mkdir -p "$B"
[ -f "$B/table-$NAME.npz" ] || try runuser -u dat -- env PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 $PY -u \
  -m sentinel_pulse.attack.window_table "${roots[@]}" --model-hash "$(cfg model_hash)" --policy-hash "$(cfg policy_hash)" \
  --since "$SEL_START" --output "$B/table-$NAME.npz"
try $PY "$SRC/scripts/analysis/burden_blind_test.py" \
  --run "name=$NAME,table=$B/table-$NAME.npz,since=$SEL_START,campaign=$CAMPAIGN" \
  --calibration "$REFRESHED" --calibration-table "$B/cal-pulse-live-recalibrated.npz" \
  --ml-results /mnt/sentinel-pulse-archive/pulse-stable-refreshed/analysis/burden-levers.json --live-rule le3s \
  --output "$OUT/burden-blind-test.json"
[ -f "$OUT/tripwire-a1-offline.json" ] || try $PY -u "$SRC/scripts/analysis/novel_syscalls.py" --workers-root "$RUN/workers" \
  --campaign "$CAMPAIGN" --reference-span "$SEL_START:$SEL_END" --normal-span "$SEL_END:$CAPTURE_END" \
  --exec-set "$EXEC_SET" --output "$OUT/tripwire-a1-offline.json"
[ -f "$OUT/live-tripwire.json" ] || try $PY -u "$SRC/scripts/analysis/live_tripwire.py" --workers-root "$RUN/workers" \
  --campaign "$CAMPAIGN" --normal-span "$SEL_END:$CAPTURE_END" --offline "$OUT/tripwire-a1-offline.json" \
  --output "$OUT/live-tripwire.json"
common=(--table "$B/table-$NAME.npz" --since "$SEL_START" --normal-from "$SEL_END" --campaign "$CAMPAIGN"
        --calibration "$REFRESHED" --calibration-table "$B/cal-pulse-live-recalibrated.npz" --workers-root "$RUN/workers")
try $PY -u "$SRC/scripts/analysis/rule_comparison.py" "${common[@]}" --tripwire "$OUT/live-tripwire.json" \
  --output "$OUT/final-system.json"
try $PY -u "$SRC/scripts/analysis/rule_comparison.py" "${common[@]}" --tripwire "$OUT/tripwire-a1-offline.json" \
  --output "$OUT/final-system-offline-tripwire.json"
[ -f "$OUT/frame-lag-previous-run.json" ] || try $PY -u "$SRC/scripts/analysis/live_tripwire.py" --workers-root "$PREVIOUS/workers" \
  --campaign "$PREVIOUS/pulse-development-matrix" --normal-span 0:0 --output "$OUT/frame-lag-previous-run.json"
try $PY "$SRC/scripts/analysis/rca_suspect_reasons.py" --cases "$RCA/cases" --campaign "$CAMPAIGN" --output "$OUT/rca-suspect-reasons.json"
try $PY "$SRC/scripts/analysis/alarm_taxonomy.py" --cases "$RCA/cases" --campaign "$CAMPAIGN" \
  --probe-spec "$SRC/validation-evidence/results-20261021/exec-probe-spec.json" --output "$OUT/alarm-taxonomy.json"
try $PY "$SRC/scripts/analysis/cadence_gaps.py" --workers-root "$RUN/workers" --output "$OUT/cadence-gaps.json"
try cp "$RCA/STATUS.json" "$OUT/rca-status-final.json"
try cp "$BRIDGE/STATUS.json" "$OUT/bridge-status-final.json"
# zombie processes under Tetragon (expected 0 with shareProcessNamespace), counted on every worker
python3 - "$OUT/tetragon-zombies.json" <<'PY' || echo "FAILED zombie count" >&2
import json, subprocess, sys
out = {}
for host in ('10.1.16.237', '10.1.16.238', '10.1.16.239'):
    cmd = "T=$(pgrep -xo tetragon); echo $(hostname) $(ps -eo stat,ppid | awk -v t=$T '$1 ~ /^Z/ && $2==t' | wc -l) $(ps -eo stat | grep -c ^Z)"
    r = subprocess.run(['runuser', '-u', 'dat', '--', 'sshpass', '-f', '/home/dat/.pulse-recovery-credential-20261005', 'ssh',
                        '-o', 'StrictHostKeyChecking=yes', 'dat@' + host, cmd], capture_output=True, text=True, timeout=60)
    parts = r.stdout.split()
    out[host] = dict(node=parts[0], under_tetragon=int(parts[1]), all_zombies=int(parts[2])) if len(parts) == 3 else dict(error=r.stderr[-200:])
json.dump(out, open(sys.argv[1], 'w'), indent=1); print(out)
PY
chown -R dat:dat "$OUT" 2>/dev/null || true
