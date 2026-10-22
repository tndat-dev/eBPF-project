#!/usr/bin/env bash
# Feature-group phase B on the primary holdout (SYSCALL 5B, protocol feature-group-evaluation-v1), on .234 as dat.
# Same steps as step 1 of after_stable_candidate_chain.sh, with the three per-node holdout dumps in parallel
# (no live run is active; 22/10). The pulse-live-recalibrated replay already exists and is reused.
#   SRC=/mnt/.../source bash feature_groups_primary.sh
set -euo pipefail
SRC=${SRC:?source snapshot}
STUDY=/var/tmp/feature-groups/study
L=/var/tmp/feature-groups
NFS_OUT=/mnt/sentinel-pulse-archive/matched-parallel-r4-20261015/feature-groups
LIVE=/mnt/sentinel-pulse-archive/matched-r6-20261018
DEV=(--campaign /mnt/sentinel-pulse-archive/matched-parallel-r3-20261015/pulse-development-matrix
     --campaign /mnt/sentinel-pulse-archive/matched-parallel-r5-rabbit-20261015/pulse-development-matrix)
LIVEC=(--campaign $LIVE/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
       --campaign $LIVE/coordinator-rca-followup-20261019/pulse-development-matrix)
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
cd /tmp
mkdir -p $NFS_OUT
echo "start $(date -u +%FT%T)"
pids=()
for node in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  [ -f $L/score-dump/$node/TERMINAL.json ] && continue
  $PY -u -m sentinel_pulse.syscall_study.score_dump --study $STUDY --node $node --output $L/score-dump/$node \
    > $L/primary-dump-$node.log 2>&1 &
  pids+=($!)
done
[ -f $L/replay-pulse-attack-dev/RESULTS.json ] || \
  $PY -u -m sentinel_pulse.syscall_study.arm_attack_replay --study $STUDY "${DEV[@]}" --alpha-scale 1 --output $L/replay-pulse-attack-dev \
    > $L/primary-replay-dev.log 2>&1 &
pids+=($!)
for p in "${pids[@]}"; do wait $p; done
echo "dumps and replay done $(date -u +%FT%T)"
for set in pulse-attack-dev pulse-live-recalibrated; do
  c=("${DEV[@]}"); [ $set = pulse-live-recalibrated ] && c=("${LIVEC[@]}")
  [ -f $L/budget-$set/RESULTS.json ] || \
    $PY -u -m sentinel_pulse.syscall_study.arm_budget --study $STUDY --dump-root $L/score-dump --replay $L/replay-$set "${c[@]}" \
      --confirm-k 2 --confirm-n 2 --output $L/budget-$set
  $PY -u -m sentinel_pulse.syscall_study.arm_bootstrap --budget-dir $L/budget-$set --output $L/BOOTSTRAP-$set.json
  python3 $SRC/scripts/analysis/arm_scenarios.py --budget-dir $L/budget-$set "${c[@]}" --output $L/arm-scenarios-$set.json
  cp $L/budget-$set/RESULTS.json $NFS_OUT/RESULTS-$set.json; cp $L/BOOTSTRAP-$set.json $L/arm-scenarios-$set.json $NFS_OUT/
done
echo "done $(date -u +%FT%T)"
