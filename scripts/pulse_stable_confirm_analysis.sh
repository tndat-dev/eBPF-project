#!/usr/bin/env bash
# Analyses registered for the confirmation run pulse-stable-confirm (stable-confirmation-v1 + amendment 1; Pulse 5.19
# step 4, 5.22 rule 5; RCA 5.12), run on .234 as root (RCA cases are root-owned; outputs are chowned to dat).
# ML only: no rule-tier number is computed here (rules come after ML is complete, RULE_INTEGRATION_STATUS R6).
#
#   STAGE=campaign  once the campaign is TERMINAL (light: trial files + RCA on local disk, allowed during capture):
#                   expectations on the primary rates (6, 12, 24/s) and per rate, RCA coverage / ranking / latency /
#                   flow, RCA status counters (follow-up refusals)
#   STAGE=final     after all three workers are TERMINAL (reads features + decisions: heavy, no live run): window table,
#                   live burden + workload CI, blind test of the 5.22 choices, RCA suspect reasons (baseline seed),
#                   alarm taxonomy (5.18 replication), cadence gaps
#
#   SRC=/mnt/.../source STAGE=campaign|final bash pulse_stable_confirm_analysis.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
STAGE=${STAGE:?campaign or final}
RUN=${RUN:-/mnt/sentinel-pulse-archive/pulse-stable-confirm}
CAMPAIGN=$RUN/pulse-development-matrix
OUT=${OUT:-$RUN/analysis}
RCA=${RCA:-/var/lib/sentinel-pulse-rca/rca-$(basename "$RUN")}
REFRESHED=/mnt/sentinel-pulse-archive/matched-r6-20261018/analysis-20261019/pulse-stable-candidate-selection/calibration-r6-1300-1900.npz
B=/var/tmp/burden-levers
NODES=(k8s-worker1.local k8s-worker4.local k8s-worker3.local)
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
mkdir -p "$OUT"; cd /tmp
try() { "$@" || echo "FAILED($?): $*" >&2; }
cfg() { python3 -c "import json;print(json.load(open('$RUN/CONFIG.json'))['$1'])"; }
ATTACKS_FROM=$(cfg attack_not_before)
SELECTION_START=$(cfg selection_start)

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
  chown -R dat:dat "$OUT" 2>/dev/null || true
  exit 0
fi

# ---- final: after the capture ----
for node in "${NODES[@]}"; do test -f "$RUN/workers/$node/TERMINAL.json" || exit 1; done
roots=(); for node in "${NODES[@]}"; do roots+=(--worker-root "$RUN/workers/$node"); done
mkdir -p "$B"
[ -f "$B/table-pulse-stable-confirm.npz" ] || try runuser -u dat -- env PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 $PY -u \
  -m sentinel_pulse.attack.window_table "${roots[@]}" --model-hash "$(cfg model_hash)" --policy-hash "$(cfg policy_hash)" \
  --since "$SELECTION_START" --output "$B/table-pulse-stable-confirm.npz"
try $PY "$SRC/scripts/analysis/burden_blind_test.py" \
  --run "name=pulse-stable-confirm,table=$B/table-pulse-stable-confirm.npz,since=$SELECTION_START,campaign=$CAMPAIGN" \
  --calibration "$REFRESHED" --calibration-table "$B/cal-pulse-live-recalibrated.npz" \
  --ml-results /mnt/sentinel-pulse-archive/pulse-stable-refreshed/analysis/burden-levers.json --output "$OUT/burden-blind-test.json"
try $PY "$SRC/scripts/analysis/rca_suspect_reasons.py" --cases "$RCA/cases" --campaign "$CAMPAIGN" --output "$OUT/rca-suspect-reasons.json"
try $PY "$SRC/scripts/analysis/alarm_taxonomy.py" --cases "$RCA/cases" --campaign "$CAMPAIGN" \
  --probe-spec "$SRC/validation-evidence/results-20261021/exec-probe-spec.json" --output "$OUT/alarm-taxonomy.json"
try $PY "$SRC/scripts/analysis/cadence_gaps.py" --workers-root "$RUN/workers" --output "$OUT/cadence-gaps.json"
try cp "$RCA/STATUS.json" "$OUT/rca-status-final.json"
chown -R dat:dat "$OUT" 2>/dev/null || true
