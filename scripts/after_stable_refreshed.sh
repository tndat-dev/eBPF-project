#!/usr/bin/env bash
# After pulse-stable-refreshed, on .234 as root (one unit, strictly sequential so heavy NFS reads never overlap):
#   1. campaign TERMINAL  -> pulse_stable_refreshed_analysis.sh STAGE=campaign (light; capture may still run)
#   2. workers TERMINAL   -> STAGE=final (main result: normal burden, replay, blind CUSUM/Cauchy verdict)
#   3. then the queued heavy chain as dat (feature groups phase B, Pulse 5.7d)
#   SRC=/mnt/.../source bash after_stable_refreshed.sh
set -euo pipefail
SRC=${SRC:?source snapshot}
RUN=/mnt/sentinel-pulse-archive/pulse-stable-refreshed
until [ -f $RUN/pulse-development-matrix/TERMINAL.json ]; do sleep 300; done
[ -f $RUN/analysis/persistence-stage-3s.json ] || SRC=$SRC STAGE=campaign bash $SRC/scripts/pulse_stable_refreshed_analysis.sh
echo "campaign stage done $(date -u +%FT%T)"
for n in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  until [ -f $RUN/workers/$n/TERMINAL.json ]; do sleep 300; done
done
[ -f $RUN/analysis/cadence-gaps.json ] || SRC=$SRC STAGE=final bash $SRC/scripts/pulse_stable_refreshed_analysis.sh
echo "final stage done $(date -u +%FT%T)"
runuser -u dat -- env SRC=$SRC WAIT_RUN=pulse-stable-refreshed bash $SRC/scripts/after_stable_candidate_chain.sh
