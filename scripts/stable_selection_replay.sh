#!/usr/bin/env bash
# Pulse 5.19 step 3, on .234 as root: combined replay of the one change that passed its own rule (temporal rule
# cusum_b3_h6; scorer stays base29, calibration stays asrun): asrun + k2of2 alpha x10 (reference) and
# asrun + CUSUM on pulse-stable-refreshed, normal burden + campaign, same tool and spans as
# calibration-strategies-v1. Both replays run in parallel. (22/10 16:20: the heavy chain that used to follow is
# split into feature_groups_primary.sh and pulse_57d.sh, run in parallel; no live run is active.)
#   SRC=/mnt/.../source bash stable_selection_replay.sh
set -uo pipefail
SRC=${SRC:?source snapshot}
RUN=/mnt/sentinel-pulse-archive/pulse-stable-refreshed
while [ "$(systemctl is-active after-stable-refreshed)" = active ]; do sleep 300; done
cfg() { python3 -c "import json;print(json.load(open('$RUN/CONFIG.json'))['$1'])"; }
roots=(); for n in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do roots+=(--worker-root $RUN/workers/$n); done
EX=(); for s in $(cat $RUN/analysis/EXTRA_EXCLUDE 2>/dev/null || true); do EX+=(--exclude "$s"); done
pids=()
for t in kofn cusum-3-6; do
  OUT=$RUN/analysis/stable-selection-$t.json
  [ -f $OUT ] && continue
  ( runuser -u dat -- env PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 /home/dat/ml-venv/bin/python -u \
      -m sentinel_pulse.attack.rolling_recalibration "${roots[@]}" --campaign $RUN/pulse-development-matrix \
      --static-span "$(cfg selection_start):$(cfg selection_end)" --eval-start "$(cfg selection_end)" "${EX[@]}" \
      --model-hash "$(cfg model_hash)" --policy-hash "$(cfg policy_hash)" --strategy asrun --scale 10 \
      --confirm-k 2 --confirm-n 2 --temporal $t --output /var/tmp/stable-selection-$t.json \
    && cp /var/tmp/stable-selection-$t.json $OUT && rm -f /var/tmp/stable-selection-$t.json || echo "replay $t FAILED" ) &
  pids+=($!)
done
for p in "${pids[@]}"; do wait $p; done
echo "combined replay done $(date -u +%FT%T)"
echo "done $(date -u +%FT%T)"
