#!/usr/bin/env bash
# Evidence for the R7 candidate and policy (run on .234 as dat after the R6 capture ends).
#   A. normal alert burden of every policy on the R6 normal tail with the R6 candidate as run;
#   B. recalibrate the R6 candidate on R6 normal 13:00-19:00 (19/10 UTC+7) = periodic refresh;
#   C. burden on 19:00-end and replay of both R6 campaigns under that new calibration.
# Spans exclude the Tetragon-contention start and both campaigns (+-60 s).
set -euo pipefail
SRC=${SRC:?source snapshot with confirmation_study --model-hash on calibrate}
ROOT=/mnt/sentinel-pulse-archive/matched-r6-20261018
OUT=$ROOT/analysis-20261019/r7-selection
MAIN=$ROOT/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
FOLLOW=$ROOT/coordinator-rca-followup-20261019/pulse-development-matrix
MODEL=ec72d9ea22af7d84ac2e8567e19205f121498ad11e48a9b2ef673697f5843cd4
POLICY=f61073512035dad4177b0fcce518f6a4b452322250b28b8a563605c2f0a8c9cb
CAL_START=1792389600   # 19/10 13:00 UTC+7
CAL_END=1792411200     # 19/10 19:00 UTC+7
NODES=(k8s-worker1.local k8s-worker4.local k8s-worker3.local)
for node in "${NODES[@]}"; do
  until [ -f "$ROOT/workers/$node/TERMINAL.json" ]; do sleep 60; done
done
mkdir -p "$OUT"
span() {
  python3 - "$1" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
starts = [float(json.loads(l)['start_at']) for l in (root/'INTERVALS.jsonl').read_text().splitlines()]
print(f"{min(starts) - 60}:{json.loads((root/'TERMINAL.json').read_text())['finished_at_unix'] + 60}")
PY
}
# 18:25-19:20 (19/10): cluster incident (heavy analysis jobs, master2 NotReady, Longhorn rebuild,
# monitored pods restarted); excluded before any R6 normal result was looked at.
INCIDENT=1792409100:1792412400
EXCL=(--exclude "$(span "$MAIN")" --exclude "$(span "$FOLLOW")" --exclude "$INCIDENT")
cd /tmp
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
run() { /home/dat/ml-venv/bin/python -m sentinel_pulse.attack.confirmation_study "$@" --model-hash $MODEL --policy-hash $POLICY; }
# A + C(normal): same evaluation span, R6 calibration as run vs. refreshed calibration
run calibrate --worker-root "$ROOT/workers/${NODES[0]}" --worker-root "$ROOT/workers/${NODES[1]}" \
  --worker-root "$ROOT/workers/${NODES[2]}" --since $CAL_START --until $CAL_END "${EXCL[@]}" \
  --output "$OUT/calibration-r6-1300-1900.npz"
for node in "${NODES[@]}"; do
  for grid in default looser; do
    run normal --worker-root "$ROOT/workers/$node" --since $CAL_END "${EXCL[@]}" --grid $grid \
      --output "$OUT/normal-asrun-$grid-$node.json"
    run normal --worker-root "$ROOT/workers/$node" --since $CAL_END "${EXCL[@]}" --grid $grid \
      --calibration "$OUT/calibration-r6-1300-1900.npz" --output "$OUT/normal-refreshed-$grid-$node.json"
  done
done
for grid in default looser; do
  run attack --campaign "$MAIN" --campaign "$FOLLOW" --grid $grid --output "$OUT/attack-asrun-$grid.json"
  run attack --campaign "$MAIN" --campaign "$FOLLOW" --grid $grid \
    --calibration "$OUT/calibration-r6-1300-1900.npz" --output "$OUT/attack-refreshed-$grid.json"
done
# D. apply the pre-registered selection rule (SENTINEL_PULSE_STATUS 5.7)
/home/dat/ml-venv/bin/python -m sentinel_pulse.attack.select_policy --selection-dir "$OUT" --output "$OUT/SELECTION.json"
