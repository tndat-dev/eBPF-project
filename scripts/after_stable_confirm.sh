#!/usr/bin/env bash
# After pulse-stable-confirm, on .234 as root (one unit, sequential): campaign stage when the campaign is TERMINAL
# (light), final stage when all three workers are TERMINAL (heavy, no live run), then lossless compression of the run.
# Falco logs are copied off the nodes by hand right after the run (capture requirement of rule-integration-v1
# amendment 1); nothing here computes a rule number.
#   SRC=/mnt/.../source [RUN=/mnt/.../<run> LIVE_RULE=le3s] bash after_stable_confirm.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
RUN=${RUN:-/mnt/sentinel-pulse-archive/pulse-stable-confirm}
export RUN LIVE_RULE=${LIVE_RULE:-stable}
until [ -f $RUN/pulse-development-matrix/TERMINAL.json ]; do sleep 300; done
[ -f $RUN/analysis/confirm-campaign.json ] || SRC=$SRC STAGE=campaign bash $SRC/scripts/pulse_stable_confirm_analysis.sh || echo "campaign stage FAILED"
echo "campaign stage done $(date -u +%FT%T)"
for n in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  until [ -f $RUN/workers/$n/TERMINAL.json ]; do sleep 300; done
done
[ -f $RUN/analysis/cadence-gaps.json ] || SRC=$SRC STAGE=final bash $SRC/scripts/pulse_stable_confirm_analysis.sh || echo "final stage FAILED"
echo "final stage done $(date -u +%FT%T)"
runuser -u dat -- python3 $SRC/scripts/compress_raw_frames.py --run-root $RUN --files features.jsonl decisions.jsonl \
  || echo "compress FAILED"
echo "retention done $(date -u +%FT%T)"
