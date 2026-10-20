#!/usr/bin/env bash
# Run both stages of pulse_stable_candidate_analysis.sh as their inputs become ready (as root on .234).
#   SRC=/mnt/.../source bash pulse_stable_candidate_analysis_wait.sh
set -euo pipefail
SRC=${SRC:?source snapshot}
RUN=/mnt/sentinel-pulse-archive/pulse-stable-candidate
until [ -f $RUN/pulse-development-matrix/TERMINAL.json ]; do sleep 120; done
[ -f $RUN/analysis/rca-flow-coverage.json ] || SRC=$SRC STAGE=campaign bash $SRC/scripts/pulse_stable_candidate_analysis.sh
echo "campaign stage done $(date -u +%FT%T)"
for n in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  until [ -f $RUN/workers/$n/TERMINAL.json ]; do sleep 120; done
done
SRC=$SRC STAGE=final nice -n 10 bash $SRC/scripts/pulse_stable_candidate_analysis.sh
echo "all analysis stages done $(date -u +%FT%T)"
