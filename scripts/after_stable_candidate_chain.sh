#!/usr/bin/env bash
# Heavy analyses queued behind pulse-stable-candidate (run on .234 as dat; each reads tens of GB from NFS,
# so they run one after another and only after the live run and its final analysis stage are done):
#   1. feature-group study phase B (SYSCALL 5B): holdout score dump for the 693 models, attack replay on
#      pulse-attack-dev and pulse-live-recalibrated, matched budgets under k2of2, bootstrap, per-scenario recall;
#   2. Pulse 5.7d: rolling recalibration + k2of2 on the 48 h soak.
#   SRC=/mnt/.../source bash after_stable_candidate_chain.sh
set -euo pipefail
SRC=${SRC:?source snapshot}
STUDY=/var/tmp/feature-groups/study
L=/var/tmp/feature-groups
NFS_OUT=/mnt/sentinel-pulse-archive/matched-parallel-r4-20261015/feature-groups
SYSCALL_ROOT=/mnt/sentinel-pulse-archive/matched-parallel-r4-20261015
LIVE=/mnt/sentinel-pulse-archive/matched-r6-20261018
DEV=(--campaign /mnt/sentinel-pulse-archive/matched-parallel-r3-20261015/pulse-development-matrix
     --campaign /mnt/sentinel-pulse-archive/matched-parallel-r5-rabbit-20261015/pulse-development-matrix)
LIVEC=(--campaign $LIVE/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
       --campaign $LIVE/coordinator-rca-followup-20261019/pulse-development-matrix)
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
cd /tmp

# wait: live run over and its final analysis stage finished
for n in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  until [ -f /mnt/sentinel-pulse-archive/pulse-stable-candidate/workers/$n/TERMINAL.json ]; do sleep 300; done
done
while [ "$(systemctl is-active pulse-stable-candidate-analysis)" = active ]; do sleep 300; done
echo "start chain $(date -u +%FT%T)"

# 1. feature groups, phase B
mkdir -p $NFS_OUT
for node in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  $PY -u -m sentinel_pulse.syscall_study.score_dump --study $STUDY --node $node --output $L/score-dump/$node
done
[ -f $L/replay-pulse-attack-dev/RESULTS.json ] || \
  $PY -u -m sentinel_pulse.syscall_study.arm_attack_replay --study $STUDY "${DEV[@]}" --alpha-scale 1 --output $L/replay-pulse-attack-dev
[ -f $L/replay-pulse-live-recalibrated/RESULTS.json ] || \
  $PY -u -m sentinel_pulse.syscall_study.arm_attack_replay --study $STUDY --workers-root $LIVE/workers "${LIVEC[@]}" \
    --alpha-scale 1 --output $L/replay-pulse-live-recalibrated
for set in pulse-attack-dev pulse-live-recalibrated; do
  c=("${DEV[@]}"); [ $set = pulse-live-recalibrated ] && c=("${LIVEC[@]}")
  [ -f $L/budget-$set/RESULTS.json ] || \
    $PY -u -m sentinel_pulse.syscall_study.arm_budget --study $STUDY --dump-root $L/score-dump --replay $L/replay-$set "${c[@]}" \
      --confirm-k 2 --confirm-n 2 --output $L/budget-$set
  $PY -u -m sentinel_pulse.syscall_study.arm_bootstrap --budget-dir $L/budget-$set --output $L/BOOTSTRAP-$set.json
  python3 $SRC/scripts/analysis/arm_scenarios.py --budget-dir $L/budget-$set "${c[@]}" --output $L/arm-scenarios-$set.json
  cp $L/budget-$set/RESULTS.json $NFS_OUT/RESULTS-$set.json; cp $L/BOOTSTRAP-$set.json $L/arm-scenarios-$set.json $NFS_OUT/
done
echo "feature groups phase B done $(date -u +%FT%T)"

# 2. Pulse 5.7d: rolling recalibration + k2of2 on the 48 h soak (same inputs and exclusions as 5.6)
OUT57=/mnt/sentinel-pulse-archive/confirmation-study-20261018/rolling-recalibration-k2of2-20261021
mkdir -p $OUT57
[ -f $OUT57/RESULTS.json ] || $PY -u -m sentinel_pulse.attack.rolling_recalibration \
  --worker-root /mnt/sentinel-pulse-archive/matched-parallel-20261015/workers/k8s-worker1.local \
  --worker-root /mnt/sentinel-pulse-archive/matched-parallel-20261015/workers/k8s-worker4.local \
  --worker-root /mnt/sentinel-pulse-archive/matched-parallel-20261015/workers/k8s-worker3.local \
  "${DEV[@]}" --static-span 1792024200:1792049400 --eval-start 1792053600 \
  --exclude 1792033200:1792034700 --exclude 1792049794:1792051759 \
  --strategy static --strategy rolling-6-1 --strategy rolling-12-1 \
  --scale 3 --scale 5 --scale 10 --confirm-k 2 --confirm-n 2 --output $OUT57/RESULTS.json
echo "chain done $(date -u +%FT%T)"
