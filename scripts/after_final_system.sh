#!/usr/bin/env bash
# After pulse-final-system-confirm, on .234 as root (one unit, sequential; protocol final-system-confirmation-v1):
# campaign stage when the campaign is TERMINAL (light), final stage when all three workers are TERMINAL (heavy, no
# live run), then lossless compression of the run. The workers' local decision copies (the NFS copy is the sealed
# one) are removed by hand in the clean-up after the run.
#   SRC=/mnt/.../source [RUN=/mnt/.../<run>] bash after_final_system.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
RUN=${RUN:-/mnt/sentinel-pulse-archive/pulse-final-system-confirm}
export RUN
until [ -f $RUN/pulse-development-matrix/TERMINAL.json ]; do sleep 300; done
[ -f $RUN/analysis/confirm-campaign.json ] || SRC=$SRC STAGE=campaign bash $SRC/scripts/final_system_analysis.sh || echo "campaign stage FAILED"
echo "campaign stage done $(date -u +%FT%T)"
for n in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  until [ -f $RUN/workers/$n/TERMINAL.json ]; do sleep 300; done
done
[ -f $RUN/analysis/final-system.json ] || SRC=$SRC STAGE=final bash $SRC/scripts/final_system_analysis.sh || echo "final stage FAILED"
echo "final stage done $(date -u +%FT%T)"
runuser -u dat -- python3 $SRC/scripts/compress_raw_frames.py --run-root $RUN --files features.jsonl decisions.jsonl \
  || echo "compress FAILED"
echo "retention done $(date -u +%FT%T)"
