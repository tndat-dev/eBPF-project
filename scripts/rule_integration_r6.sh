#!/usr/bin/env bash
# R6 of RULE_INTEGRATION_STATUS (protocol rule-integration-v1 + amendments 1 and 2): the system without and with
# rules on one live run, run on .234 as root (RCA cases are root-owned; outputs are chowned to dat). Reads the full
# feature archive of the run (tripwire): heavy, never during a live run.
#
#   1. falco_baseline.py   per-trial Falco outcome + normal events (selection end -> capture end)
#   2. novel_syscalls.py   tripwire A1: reference = selection span, exec set E, per-trial outcome + normal alerts
#   3. rule_comparison.py  arms A, B1, B2, B3, B_all against A (workload-clustered bootstrap, 10,000 draws)
#
#   SRC=/var/tmp/.../source-<sha> [RUN=/mnt/.../<run>] [ML_RULE=le3s ML_RESULTS=.../burden-levers.json] bash rule_integration_r6.sh
#   ML_RULE (default preview: the run's live previews) recomputes arm A instead: the secondary data of amendment 2
set -uo pipefail
SRC=${SRC:?source snapshot}
RUN=${RUN:-/mnt/sentinel-pulse-archive/pulse-peer-discount-confirm}
NAME=$(basename "$RUN")
CAMPAIGN=$RUN/pulse-development-matrix
OUT=${OUT:-$RUN/analysis/rule-integration}
RCA=${RCA:-/var/lib/sentinel-pulse-rca/rca-$NAME}
REFRESHED=/mnt/sentinel-pulse-archive/matched-r6-20261018/analysis-20261019/pulse-stable-candidate-selection/calibration-r6-1300-1900.npz
B=/var/tmp/burden-levers
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
mkdir -p "$OUT"; cd /tmp
try() { "$@" || echo "FAILED($?): $*" >&2; }
cfg() { python3 -c "import json;print(json.load(open('$RUN/CONFIG.json'))['$1'])"; }
SEL_START=$(cfg selection_start)
SEL_END=$(cfg selection_end)
CAPTURE_END=$(python3 -c "import glob,json;print(max(json.load(open(p))['finished_at_unix'] for p in glob.glob('$RUN/workers/*/TERMINAL.json')))")
echo "selection $SEL_START:$SEL_END capture end $CAPTURE_END"

logs=(); for d in "$RUN"/falco-logs/*/; do logs+=(--logs "$d"); done
[ -f "$OUT/falco-baseline.json" ] || try $PY "$SRC/scripts/analysis/falco_baseline.py" "${logs[@]}" --campaign "$CAMPAIGN" \
  --normal-since "$SEL_END" --normal-until "$CAPTURE_END" --output "$OUT/falco-baseline.json"
[ -f "$OUT/tripwire-a1.json" ] || try $PY -u "$SRC/scripts/analysis/novel_syscalls.py" --workers-root "$RUN/workers" \
  --campaign "$CAMPAIGN" --reference-span "$SEL_START:$SEL_END" --normal-span "$SEL_END:$CAPTURE_END" \
  --exec-set "$SRC/validation-evidence/results-20261021/pulse-stable-candidate/final/exec-set-E.json" \
  --output "$OUT/tripwire-a1.json"
try $PY -u "$SRC/scripts/analysis/rule_comparison.py" --table "$B/table-$NAME.npz" --since "$SEL_START" \
  --normal-from "$SEL_END" --campaign "$CAMPAIGN" --calibration "$REFRESHED" \
  --calibration-table "$B/cal-pulse-live-recalibrated.npz" --cases "$RCA/cases" \
  --probe-spec "$SRC/validation-evidence/results-20261021/exec-probe-spec.json" --falco "$OUT/falco-baseline.json" \
  --tripwire "$OUT/tripwire-a1.json" --workers-root "$RUN/workers" --ml-rule "${ML_RULE:-preview}" \
  ${ML_RESULTS:+--ml-results "$ML_RESULTS"} --output "$OUT/rule-comparison.json"
chown -R dat:dat "$OUT" 2>/dev/null || true
