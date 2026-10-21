#!/usr/bin/env bash
# Analyses registered for pulse-stable-candidate (SENTINEL_PULSE_STATUS 5.7b, 5.7c, 5.8), run on .234.
#
#   STAGE=campaign  as soon as the campaign is TERMINAL (light: trial files + RCA cases on local disk;
#                   allowed while the capture is still running)
#   STAGE=final     after all three workers are TERMINAL (reads features/decisions: heavy, no live run)
#
#   SRC=/mnt/.../source STAGE=campaign|final bash pulse_stable_candidate_analysis.sh   (as root: RCA cases are root-owned)
set -euo pipefail
SRC=${SRC:?source snapshot}
STAGE=${STAGE:?campaign or final}
RUN=/mnt/sentinel-pulse-archive/pulse-stable-candidate
CAMPAIGN=$RUN/pulse-development-matrix
OUT=$RUN/analysis
RCA=/var/lib/sentinel-pulse-rca/rca-pulse-stable-candidate
MODEL=ec72d9ea22af7d84ac2e8567e19205f121498ad11e48a9b2ef673697f5843cd4
POLICY=a51e5abc966cd5c37efa3f31a366f82b1c17aac4be24fdd856ea04e8faec54fb
REFRESHED=/mnt/sentinel-pulse-archive/matched-r6-20261018/analysis-20261019/pulse-stable-candidate-selection/calibration-r6-1300-1900.npz
LIVE=/mnt/sentinel-pulse-archive/matched-r6-20261018
LIVE_MAIN=$LIVE/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
LIVE_FOLLOW=$LIVE/coordinator-rca-followup-20261019/pulse-development-matrix
NODES=(k8s-worker1.local k8s-worker4.local k8s-worker3.local)
# aims-redis-0 and aims-minio-pool-0-0 recreated 20/10 10:41:50 (broken ext4 mounts); excluded for all workloads
RESTART=1792467710:1792468200
# analysis scripts need numpy: the system python3 on .234 has none (failed 20/10 ~18:00)
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
mkdir -p "$OUT"; cd /tmp
cfg() { python3 -c "import json;print(json.load(open('$RUN/CONFIG.json'))['$1'])"; }
ATTACKS_FROM=$(cfg attack_not_before)
SELECTION_START=$(cfg selection_start)

if [ "$STAGE" = campaign ]; then
  test -f "$CAMPAIGN/TERMINAL.json"
  cp "$CAMPAIGN/RESULTS.json" "$OUT/campaign-RESULTS.json"
  $PY "$SRC/scripts/analysis/attack_vs_benign.py" --campaign "$CAMPAIGN" --output "$OUT/attack-vs-benign.json"
  $PY "$SRC/scripts/analysis/rca_coverage.py" --cases "$RCA/cases" --campaign "$CAMPAIGN" --since "$ATTACKS_FROM" \
    --output "$OUT/rca-coverage.json"
  $PY -m sentinel_pulse.rca.evaluate_ranking --cases "$RCA/cases" --campaign "$CAMPAIGN" --output "$OUT/rca-ranking-stored.json"
  $PY -m sentinel_pulse.rca.evaluate_ranking --cases "$RCA/cases" --campaign "$CAMPAIGN" --output "$OUT/rca-ranking-reranked.json" \
    --rerank-db "$RCA/context.sqlite3" --frozen-at "$(python3 -c "print($ATTACKS_FROM - 120)")"
  $PY "$SRC/scripts/analysis/rca_latency.py" --copy-dir "$RCA" --output "$OUT/rca-latency.json"
  $PY "$SRC/scripts/analysis/rca_flow_coverage.py" --cases "$RCA/cases" --since "$ATTACKS_FROM" --output "$OUT/rca-flow-coverage.json"
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
EXCL=(--exclude "$CAMPAIGN_SPAN" --exclude "$RESTART")
run() { $PY -m sentinel_pulse.attack.confirmation_study "$@" --model-hash $MODEL --policy-hash $POLICY; }
# main normal burden (as run) and 5.7b (refreshed calibration of 19/10 13:00-18:25), same spans, looser grid has k2of2_a10
for node in "${NODES[@]}"; do
  run normal --worker-root "$RUN/workers/$node" --since "$SELECTION_START" "${EXCL[@]}" --grid latency3s \
    --output "$OUT/normal-asrun-$node.json"
  run normal --worker-root "$RUN/workers/$node" --since "$SELECTION_START" "${EXCL[@]}" --grid latency3s \
    --calibration "$REFRESHED" --output "$OUT/normal-refreshed-$node.json"
done
run attack --campaign "$CAMPAIGN" --grid latency3s --output "$OUT/attack-asrun.json"
run attack --campaign "$CAMPAIGN" --grid latency3s --calibration "$REFRESHED" --output "$OUT/attack-refreshed.json"
$PY "$SRC/scripts/analysis/cadence_gaps.py" --workers-root "$RUN/workers" --output "$OUT/cadence-gaps.json"
# 5.7c: exec set E frozen from pulse-live-recalibrated only, then tested on this run
$PY "$SRC/scripts/analysis/novel_syscalls.py" --workers-root "$LIVE/workers" --campaign "$LIVE_MAIN" --campaign "$LIVE_FOLLOW" \
  --reference-span 1792389600:1792411200 --output "$OUT/novel-syscalls-pulse-live-recalibrated-full.json"
python3 -c "
import json; d = json.load(open('$OUT/novel-syscalls-pulse-live-recalibrated-full.json'))
json.dump(sorted(d['novel_ids_by_label'].get('benign', {}), key=int), open('$OUT/exec-set-E.json', 'w'))"
REF_END=$(python3 -c "
import json
print(min(json.load(open('$RUN/workers/'+n+'/TERMINAL.json'))['finished_at_unix'] for n in '${NODES[*]}'.split()))")
$PY "$SRC/scripts/analysis/novel_syscalls.py" --workers-root "$RUN/workers" --campaign "$CAMPAIGN" \
  --reference-span "${CAMPAIGN_SPAN#*:}:$REF_END" --exec-set "$OUT/exec-set-E.json" --output "$OUT/novel-syscalls-exec-aware.json"
$PY "$SRC/scripts/analysis/novel_syscalls.py" --workers-root "$RUN/workers" --campaign "$CAMPAIGN" \
  --reference-span "${CAMPAIGN_SPAN#*:}:$REF_END" --output "$OUT/novel-syscalls-plain.json"
# live fast scoring vs sklearn on stored decisions: 2 sealed segments per worker
segs=()
for node in "${NODES[@]}"; do segs+=(--segment "$RUN/workers/$node/segments/s00003" --segment "$RUN/workers/$node/segments/s00030"); done
$PY -m sentinel_pulse.pipeline.scorer_equivalence "${segs[@]}" --candidate "$(cfg candidate)" --model-hash $MODEL \
  --policy "$(cfg policy)" --policy-hash $POLICY --limit-per-segment 20000 --output "$OUT/scorer-equivalence-sklearn-vs-live-fast.json"
chown -R dat:dat "$OUT" 2>/dev/null || true
