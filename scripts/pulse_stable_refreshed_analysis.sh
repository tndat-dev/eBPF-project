#!/usr/bin/env bash
# Analyses registered for pulse-stable-refreshed (SENTINEL_PULSE_STATUS 5.9, 5.11a, 5.13; RCA 5.10), run on .234 as root
# (RCA cases are root-owned; outputs are chowned to dat).
#
#   STAGE=campaign  as soon as the campaign is TERMINAL (light: trial files + RCA cases on local disk; allowed while
#                   the capture still runs): live campaign result, RCA coverage/ranking with and without the
#                   privilege-drop rule, blind CUSUM/Cauchy interval rates, persistence indicator (T, f)
#   STAGE=final     after all three workers are TERMINAL (reads features/decisions: heavy, no live run): normal alert
#                   burden of the running rule and the latency3s grid, attack replay, blind CUSUM/Cauchy burden and
#                   the registered verdict, cadence gaps
#
#   SRC=/mnt/.../source STAGE=campaign|final bash pulse_stable_refreshed_analysis.sh
set -euo pipefail
SRC=${SRC:?source snapshot}
STAGE=${STAGE:?campaign or final}
RUN=/mnt/sentinel-pulse-archive/pulse-stable-refreshed
CAMPAIGN=$RUN/pulse-development-matrix
OUT=$RUN/analysis
RCA=/var/lib/sentinel-pulse-rca/rca-pulse-stable-refreshed
REFRESHED=/mnt/sentinel-pulse-archive/matched-r6-20261018/analysis-20261019/pulse-stable-candidate-selection/calibration-r6-1300-1900.npz
LIVE=/mnt/sentinel-pulse-archive/matched-r6-20261018
DEV=(--dev-campaign $LIVE/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
     --dev-campaign $LIVE/coordinator-rca-followup-20261019/pulse-development-matrix)
NODES=(k8s-worker1.local k8s-worker4.local k8s-worker3.local)
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
mkdir -p "$OUT"; cd /tmp
cfg() { python3 -c "import json;print(json.load(open('$RUN/CONFIG.json'))['$1'])"; }
MODEL=$(cfg model_hash); POLICY=$(cfg policy_hash)
ATTACKS_FROM=$(cfg attack_not_before)
SELECTION_START=$(cfg selection_start)

if [ "$STAGE" = campaign ]; then
  test -f "$CAMPAIGN/TERMINAL.json"
  cp "$CAMPAIGN/RESULTS.json" "$OUT/campaign-RESULTS.json"
  $PY "$SRC/scripts/analysis/attack_vs_benign.py" --campaign "$CAMPAIGN" --output "$OUT/attack-vs-benign.json"
  $PY "$SRC/scripts/analysis/rca_coverage.py" --cases "$RCA/cases" --campaign "$CAMPAIGN" --since "$ATTACKS_FROM" \
    --output "$OUT/rca-coverage.json"
  FROZEN=$(python3 -c "print($ATTACKS_FROM - 120)")
  # RCA 5.10: the live subscriber already ranks with the privilege-drop rule; the old rule is the comparison
  $PY -m sentinel_pulse.rca.evaluate_ranking --cases "$RCA/cases" --campaign "$CAMPAIGN" --output "$OUT/rca-ranking-stored.json"
  $PY -m sentinel_pulse.rca.evaluate_ranking --cases "$RCA/cases" --campaign "$CAMPAIGN" --output "$OUT/rca-ranking-reranked.json" \
    --rerank-db "$RCA/context.sqlite3" --frozen-at "$FROZEN"
  $PY -m sentinel_pulse.rca.evaluate_ranking --cases "$RCA/cases" --campaign "$CAMPAIGN" --output "$OUT/rca-ranking-old-rule.json" \
    --rerank-db "$RCA/context.sqlite3" --frozen-at "$FROZEN" --without-privilege-drop-rule
  $PY "$SRC/scripts/analysis/rca_latency.py" --copy-dir "$RCA" --output "$OUT/rca-latency.json"
  $PY "$SRC/scripts/analysis/rca_flow_coverage.py" --cases "$RCA/cases" --since "$ATTACKS_FROM" --output "$OUT/rca-flow-coverage.json"
  # 5.11a blind: same development selection (must reproduce cauchy_a10 / cusum_b3_h6), this run's campaign as test
  $PY "$SRC/scripts/analysis/ideas_screen.py" "${DEV[@]}" --test-campaign "$CAMPAIGN" --calibration "$REFRESHED" \
    --output "$OUT/ideas-screen-blind.json"
  # 5.8b / 5.9: persistence indicator (T = 5 s, f = 0.7: triage context) and the 1 s wait (<= 3 s alert option)
  $PY "$SRC/scripts/analysis/persistence_stage.py" "${DEV[@]}" --test-campaign "$CAMPAIGN" --output "$OUT/persistence-stage.json"
  $PY "$SRC/scripts/analysis/persistence_stage.py" "${DEV[@]}" --test-campaign "$CAMPAIGN" \
    --t-grid 0.25,0.5,0.75,1.0,1.5 --max-p95 3.0 --output "$OUT/persistence-stage-3s.json"
  chown -R dat:dat "$OUT" 2>/dev/null || true
  exit 0
fi

# ---- final: after the capture ----
for node in "${NODES[@]}"; do test -f "$RUN/workers/$node/TERMINAL.json"; done
CAMPAIGN_SPAN=$(python3 - "$CAMPAIGN" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
starts = [float(json.loads(l)['start_at']) for l in (root/'INTERVALS.jsonl').read_text().splitlines()]
print(f"{min(starts) - 60}:{json.loads((root/'TERMINAL.json').read_text())['finished_at_unix'] + 60}")
PY
)
# extra spans (e.g. pod recreation or cluster incident): EXTRA_EXCLUDE="a:b c:d" or the file $OUT/EXTRA_EXCLUDE,
# written from run-health evidence before any normal number of this run is looked at
EXTRA_EXCLUDE=${EXTRA_EXCLUDE:-$(cat "$OUT/EXTRA_EXCLUDE" 2>/dev/null || true)}
EXCL=(--exclude "$CAMPAIGN_SPAN")
for s in ${EXTRA_EXCLUDE:-}; do EXCL+=(--exclude "$s"); done
run() { $PY -m sentinel_pulse.attack.confirmation_study "$@" --model-hash $MODEL --policy-hash $POLICY; }
for node in "${NODES[@]}"; do
  run normal --worker-root "$RUN/workers/$node" --since "$SELECTION_START" "${EXCL[@]}" --grid latency3s \
    --output "$OUT/normal-asrun-$node.json"
done
run attack --campaign "$CAMPAIGN" --grid latency3s --output "$OUT/attack-asrun.json"
roots=(); for node in "${NODES[@]}"; do roots+=(--worker-root "$RUN/workers/$node"); done
$PY "$SRC/scripts/analysis/ideas_burden.py" "${roots[@]}" --model-hash $MODEL --policy-hash $POLICY \
  --since "$SELECTION_START" "${EXCL[@]}" --output "$OUT/ideas-burden-blind.json"
$PY "$SRC/scripts/analysis/ideas_verdict.py" --screen "$OUT/ideas-screen-blind.json" --burden "$OUT/ideas-burden-blind.json" \
  --output "$OUT/ideas-verdict.json"
$PY "$SRC/scripts/analysis/cadence_gaps.py" --workers-root "$RUN/workers" --output "$OUT/cadence-gaps.json"
chown -R dat:dat "$OUT" 2>/dev/null || true
