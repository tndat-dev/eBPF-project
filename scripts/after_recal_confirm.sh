#!/usr/bin/env bash
# After pulse-live-recal-confirm, on .234 as root (one unit, sequential; protocol live-recalibration-confirmation-v1):
# the final-system analyses (campaign stage when the campaign is TERMINAL, final stage when all three workers are
# TERMINAL; R_system is the run's live system), then R vs F (recal_comparison.py: the same rows rescored with the
# bundle calibration) and the installation check of every applied refresh (live_recalibration_check.py), then
# lossless compression of the run.
#   SRC=/mnt/.../source [RUN=/mnt/.../<run>] bash after_recal_confirm.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
RUN=${RUN:-/mnt/sentinel-pulse-archive/pulse-live-recal-confirm}
export RUN
NAME=$(basename "$RUN"); OUT=$RUN/analysis; B=/var/tmp/burden-levers
PY=/home/dat/ml-venv/bin/python
REFRESHED=/mnt/sentinel-pulse-archive/matched-r6-20261018/analysis-20261019/pulse-stable-candidate-selection/calibration-r6-1300-1900.npz
until [ -f $RUN/pulse-development-matrix/TERMINAL.json ]; do sleep 300; done
[ -f $OUT/confirm-campaign.json ] || SRC=$SRC STAGE=campaign bash $SRC/scripts/final_system_analysis.sh || echo "campaign stage FAILED"
echo "campaign stage done $(date -u +%FT%T)"
for n in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  until [ -f $RUN/workers/$n/TERMINAL.json ]; do sleep 300; done
done
[ -f $OUT/final-system.json ] || SRC=$SRC STAGE=final bash $SRC/scripts/final_system_analysis.sh || echo "final stage FAILED"
echo "final stage done $(date -u +%FT%T)"
cfg() { python3 -c "import json;print(json.load(open('$RUN/CONFIG.json'))['$1'])"; }
cd /tmp
PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 $PY -u $SRC/scripts/analysis/recal_comparison.py --table $B/table-$NAME.npz \
  --since "$(cfg selection_start)" --selection-end "$(cfg selection_end)" --campaign $RUN/pulse-development-matrix \
  --calibration $REFRESHED --calibration-table $B/cal-pulse-live-recalibrated.npz \
  --ml-rule le3s --ml-results /mnt/sentinel-pulse-archive/pulse-stable-refreshed/analysis/burden-levers.json \
  --tripwire $OUT/live-tripwire.json --workers-root $RUN/workers --output $OUT/recal-comparison.json || echo "recal comparison FAILED"
PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 $PY -u $SRC/scripts/analysis/live_recalibration_check.py $RUN \
  --output $OUT/live-recalibration-check.json || echo "installation check FAILED"
chown -R dat:dat $OUT 2>/dev/null || true
echo "recalibration analyses done $(date -u +%FT%T)"
runuser -u dat -- python3 $SRC/scripts/compress_raw_frames.py --run-root $RUN --files features.jsonl decisions.jsonl \
  || echo "compress FAILED"
echo "retention done $(date -u +%FT%T)"
