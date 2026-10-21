#!/usr/bin/env bash
# After pulse-stable-refreshed, on .234 as root (one unit, strictly sequential so heavy NFS reads never overlap):
#   1. campaign TERMINAL  -> pulse_stable_refreshed_analysis.sh STAGE=campaign (light; capture may still run)
#   2. workers TERMINAL   -> STAGE=final (main result: normal burden, replay, blind CUSUM/Cauchy verdict)
#   3. baseline fresh replication (Pulse 5.15b), calibration strategies on fresh data (Pulse 5.17),
#      then the queued heavy chain as dat (feature groups phase B, Pulse 5.7d)
#   SRC=/mnt/.../source bash after_stable_refreshed.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
RUN=/mnt/sentinel-pulse-archive/pulse-stable-refreshed
until [ -f $RUN/pulse-development-matrix/TERMINAL.json ]; do sleep 300; done
[ -f $RUN/analysis/persistence-stage-3s.json ] || SRC=$SRC STAGE=campaign bash $SRC/scripts/pulse_stable_refreshed_analysis.sh || echo "campaign stage FAILED"
echo "campaign stage done $(date -u +%FT%T)"
for n in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  until [ -f $RUN/workers/$n/TERMINAL.json ]; do sleep 300; done
done
[ -f $RUN/analysis/cadence-gaps.json ] || SRC=$SRC STAGE=final bash $SRC/scripts/pulse_stable_refreshed_analysis.sh || echo "final stage FAILED"
echo "final stage done $(date -u +%FT%T)"
# protocol baseline-fresh-replication-v1 (Pulse 5.15b): frozen baselines + tree_ae on this run's fresh data
[ -f /var/tmp/baselines/FRESH-ADOPTION.json ] || runuser -u dat -- env SRC=$SRC bash $SRC/scripts/pulse_baselines_fresh.sh || echo "fresh baselines FAILED"
# protocol calibration-strategies-v1, fresh primary run (Pulse 5.17): calibration strategies on this run's own data
CAL=$RUN/analysis/calibration-strategies.json
if [ ! -f $CAL ]; then
  cfg() { python3 -c "import json;print(json.load(open('$RUN/CONFIG.json'))['$1'])"; }
  roots=(); for n in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do roots+=(--worker-root $RUN/workers/$n); done
  EX=(); for s in $(cat $RUN/analysis/EXTRA_EXCLUDE 2>/dev/null || true); do EX+=(--exclude "$s"); done
  runuser -u dat -- env PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 /home/dat/ml-venv/bin/python -u \
    -m sentinel_pulse.attack.rolling_recalibration "${roots[@]}" --campaign $RUN/pulse-development-matrix \
    --static-span "$(cfg selection_start):$(cfg selection_end)" --eval-start "$(cfg selection_end)" "${EX[@]}" \
    --model-hash "$(cfg model_hash)" --policy-hash "$(cfg policy_hash)" \
    --strategy asrun --strategy static --strategy rolling-6-1 --strategy weighted-24-6-1 --strategy mondrian-6-1 \
    --strategy aci-asrun --strategy aci-rolling-6-1 --scale 3 --scale 5 --scale 10 --confirm-k 2 --confirm-n 2 \
    --output /var/tmp/calibration-strategies-refreshed.json \
    && cp /var/tmp/calibration-strategies-refreshed.json $CAL || echo "calibration strategies FAILED"
fi
runuser -u dat -- env SRC=$SRC WAIT_RUN=pulse-stable-refreshed bash $SRC/scripts/after_stable_candidate_chain.sh
