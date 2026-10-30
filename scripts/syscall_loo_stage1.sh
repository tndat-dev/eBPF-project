#!/usr/bin/env bash
# syscall-ablation-loo-v1 + amendment 1, stage 1 (one seed, 46 arms x 21 workloads) on .234 as dat, no live run active.
# Fit in 8 shards in parallel on local disk, merge, register the syscall-arms holdout, then the syscall study's
# evaluation chain (holdout score dumps, attack replays, budget matching under k2of2, bootstrap, per-scenario).
#   SRC=/var/tmp/syscall-loo/source-<sha> bash syscall_loo_stage1.sh
set -euo pipefail
SRC=${SRC:?source snapshot}
A=/mnt/sentinel-pulse-archive
SOURCE=$A/matched-parallel-r4-20261015/syscall-matched-study
L=/var/tmp/syscall-loo
STUDY=$L/stage1
NFS_OUT=$A/matched-parallel-r4-20261015/syscall-loo-stage1
LIVE=$A/matched-r6-20261018
DEV=(--campaign $A/matched-parallel-r3-20261015/pulse-development-matrix
     --campaign $A/matched-parallel-r5-rabbit-20261015/pulse-development-matrix)
LIVEC=(--campaign $LIVE/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
       --campaign $LIVE/coordinator-rca-followup-20261019/pulse-development-matrix)
PY=/home/dat/ml-venv/bin/python
SHARDS=${SHARDS:-8}
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
cd /tmp
mkdir -p $STUDY $NFS_OUT
python3 -c "import json,sys; json.dump(dict(source_study='$SOURCE', study_output='$STUDY', seeds=[73021]), open('$L/config-stage1.json','w'), indent=1)"
echo "fit start $(date -u +%FT%T)"
pids=()
for k in $(seq 0 $((SHARDS - 1))); do
  [ -f $STUDY/TERMINAL.json ] && break
  $PY -u -m sentinel_pulse.syscall_study.loo_study --config $L/config-stage1.json --shard $k/$SHARDS > $L/fit-$k.log 2>&1 &
  pids+=($!)
done
for p in "${pids[@]}"; do wait $p; done
[ -f $STUDY/TERMINAL.json ] || $PY -m sentinel_pulse.syscall_study.loo_study --config $L/config-stage1.json --merge $SHARDS > $L/merge.log
echo "fit done $(date -u +%FT%T)"
[ -f $STUDY/NORMAL_HOLDOUT_START.json ] || $PY -m sentinel_pulse.syscall_study.feature_groups register --study $STUDY --source $SOURCE > $L/register.log
pids=()
for node in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  [ -f $L/score-dump/$node/TERMINAL.json ] && continue
  $PY -u -m sentinel_pulse.syscall_study.score_dump --study $STUDY --node $node --output $L/score-dump/$node > $L/dump-$node.log 2>&1 &
  pids+=($!)
done
[ -f $L/replay-pulse-attack-dev/RESULTS.json ] || \
  $PY -u -m sentinel_pulse.syscall_study.arm_attack_replay --study $STUDY "${DEV[@]}" --alpha-scale 1 --output $L/replay-pulse-attack-dev \
    > $L/replay-dev.log 2>&1 &
pids+=($!)
[ -f $L/replay-pulse-live-recalibrated/RESULTS.json ] || \
  $PY -u -m sentinel_pulse.syscall_study.arm_attack_replay --study $STUDY --workers-root $LIVE/workers "${LIVEC[@]}" \
    --alpha-scale 1 --output $L/replay-pulse-live-recalibrated > $L/replay-live.log 2>&1 &
pids+=($!)
for p in "${pids[@]}"; do wait $p; done
echo "dumps and replays done $(date -u +%FT%T)"
for set in pulse-attack-dev pulse-live-recalibrated; do
  c=("${DEV[@]}"); [ $set = pulse-live-recalibrated ] && c=("${LIVEC[@]}")
  [ -f $L/budget-$set/RESULTS.json ] || \
    $PY -u -m sentinel_pulse.syscall_study.arm_budget --study $STUDY --dump-root $L/score-dump --replay $L/replay-$set "${c[@]}" \
      --confirm-k 2 --confirm-n 2 --output $L/budget-$set > $L/budget-$set.log 2>&1
  $PY -u -m sentinel_pulse.syscall_study.arm_bootstrap --budget-dir $L/budget-$set --output $L/BOOTSTRAP-$set.json
  python3 $SRC/scripts/analysis/arm_scenarios.py --budget-dir $L/budget-$set "${c[@]}" --output $L/arm-scenarios-$set.json
  cp $L/budget-$set/RESULTS.json $NFS_OUT/RESULTS-$set.json; cp $L/BOOTSTRAP-$set.json $L/arm-scenarios-$set.json $NFS_OUT/
done
echo "stage 1 done $(date -u +%FT%T)"
