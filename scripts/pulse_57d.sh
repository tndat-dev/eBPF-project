#!/usr/bin/env bash
# Pulse 5.7d (development): rolling recalibration + k2of2 on the 48 h soak, with the strategies of protocol
# calibration-strategies-v1; same inputs and exclusions as 5.6. Step 2 of after_stable_candidate_chain.sh as its
# own unit (22/10), on .234 as dat.   SRC=/mnt/.../source bash pulse_57d.sh
set -euo pipefail
SRC=${SRC:?source snapshot}
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
cd /tmp
A=/mnt/sentinel-pulse-archive
OUT57=$A/confirmation-study-20261018/rolling-recalibration-k2of2-20261021
mkdir -p $OUT57
[ -f $OUT57/RESULTS.json ] || /home/dat/ml-venv/bin/python -u -m sentinel_pulse.attack.rolling_recalibration \
  --worker-root $A/matched-parallel-20261015/workers/k8s-worker1.local \
  --worker-root $A/matched-parallel-20261015/workers/k8s-worker4.local \
  --worker-root $A/matched-parallel-20261015/workers/k8s-worker3.local \
  --campaign $A/matched-parallel-r3-20261015/pulse-development-matrix \
  --campaign $A/matched-parallel-r5-rabbit-20261015/pulse-development-matrix \
  --static-span 1792024200:1792049400 --eval-start 1792053600 \
  --exclude 1792033200:1792034700 --exclude 1792049794:1792051759 \
  --strategy static --strategy rolling-6-1 --strategy rolling-12-1 \
  --strategy weighted-24-6-1 --strategy mondrian-6-1 --strategy aci-static --strategy aci-rolling-6-1 \
  --scale 3 --scale 5 --scale 10 --confirm-k 2 --confirm-n 2 --output $OUT57/RESULTS.json
echo "done $(date -u +%FT%T)"
