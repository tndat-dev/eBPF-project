#!/usr/bin/env bash
# syscall-ablation-loo-v1 + amendment 1, stage 2 (seeds 73021-73023, the arms of ARMS.json chosen from the stage-1 receipts by
# scripts/analysis/syscall_loo_stage2_arms.py) on .234 as dat, no live run active. Same chain as stage 1.
# Fit in 8 shards in parallel on local disk, merge, register the syscall-arms holdout, then the syscall study's
# evaluation chain (holdout score dumps, attack replays, budget matching under k2of2, bootstrap, per-scenario).
#   SRC=/var/tmp/syscall-loo/source-<sha> ARMS=…/ARMS.json [SHARDS=12] bash syscall_loo_stage2.sh
set -euo pipefail
SRC=${SRC:?source snapshot}
A=/mnt/sentinel-pulse-archive
SOURCE=$A/matched-parallel-r4-20261015/syscall-matched-study
L=/var/tmp/syscall-loo
STUDY=$L/stage2
ARMS=${ARMS:?arms file}
NFS_OUT=$A/matched-parallel-r4-20261015/syscall-loo-stage2
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
python3 -c "import json,sys; a=json.load(open('$ARMS')); json.dump(dict(source_study='$SOURCE', study_output='$STUDY', seeds=a['seeds'], arms=a['arms']), open('$L/config-stage2.json','w'), indent=1)"
echo "fit start $(date -u +%FT%T)"
pids=()
for k in $(seq 0 $((SHARDS - 1))); do
  [ -f $STUDY/TERMINAL.json ] && break
  $PY -u -m sentinel_pulse.syscall_study.loo_study --config $L/config-stage2.json --shard $k/$SHARDS > $L/s2-fit-$k.log 2>&1 &
  pids+=($!)
done
for p in "${pids[@]}"; do wait $p; done
[ -f $STUDY/TERMINAL.json ] || $PY -m sentinel_pulse.syscall_study.loo_study --config $L/config-stage2.json --merge $SHARDS > $L/s2-merge.log
echo "fit done $(date -u +%FT%T)"
[ -f $STUDY/NORMAL_HOLDOUT_START.json ] || $PY -m sentinel_pulse.syscall_study.feature_groups register --study $STUDY --source $SOURCE > $L/s2-register.log
pids=()
for node in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  [ -f $L/s2-score-dump/$node/TERMINAL.json ] && continue
  $PY -u -m sentinel_pulse.syscall_study.score_dump --study $STUDY --node $node --output $L/s2-score-dump/$node > $L/s2-dump-$node.log 2>&1 &
  pids+=($!)
done
[ -f $L/s2-replay-pulse-attack-dev/RESULTS.json ] || \
  $PY -u -m sentinel_pulse.syscall_study.arm_attack_replay --study $STUDY "${DEV[@]}" --alpha-scale 1 --output $L/s2-replay-pulse-attack-dev \
    > $L/s2-replay-dev.log 2>&1 &
pids+=($!)
[ -f $L/s2-replay-pulse-live-recalibrated/RESULTS.json ] || \
  $PY -u -m sentinel_pulse.syscall_study.arm_attack_replay --study $STUDY --workers-root $LIVE/workers "${LIVEC[@]}" \
    --alpha-scale 1 --output $L/s2-replay-pulse-live-recalibrated > $L/s2-replay-live.log 2>&1 &
pids+=($!)
for p in "${pids[@]}"; do wait $p; done
echo "dumps and replays done $(date -u +%FT%T)"
for set in pulse-attack-dev pulse-live-recalibrated; do
  c=("${DEV[@]}"); [ $set = pulse-live-recalibrated ] && c=("${LIVEC[@]}")
  [ -f $L/s2-budget-$set/RESULTS.json ] || \
    $PY -u -m sentinel_pulse.syscall_study.arm_budget --study $STUDY --dump-root $L/s2-score-dump --replay $L/s2-replay-$set "${c[@]}" \
      --confirm-k 2 --confirm-n 2 --output $L/s2-budget-$set > $L/s2-budget-$set.log 2>&1
  $PY -u -m sentinel_pulse.syscall_study.arm_bootstrap --budget-dir $L/s2-budget-$set --output $L/s2-BOOTSTRAP-$set.json
  python3 $SRC/scripts/analysis/arm_scenarios.py --budget-dir $L/s2-budget-$set "${c[@]}" --output $L/s2-arm-scenarios-$set.json
  cp $L/s2-budget-$set/RESULTS.json $NFS_OUT/RESULTS-$set.json; cp $L/s2-BOOTSTRAP-$set.json $L/s2-arm-scenarios-$set.json $NFS_OUT/
done
echo "stage 2 done $(date -u +%FT%T)"
