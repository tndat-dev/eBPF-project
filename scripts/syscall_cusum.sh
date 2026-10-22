#!/usr/bin/env bash
# Protocol syscall-feature-groups-under-stable-rule-v1 on .234 as dat: the syscall arms (SYSCALL 5.9 inputs) and the
# feature-group arms (primary holdout, SYSCALL 5B) re-compared at matched budgets under Pulse's stable CUSUM rule.
#   1. copy the syscall-arms score dump and replays to local disk (done before the confirmation live run starts);
#   2. syscall arms: arm_budget --cusum-drift 3, bootstrap, per-scenario recall, for both attack sets, with the stable
#      on_alarm=cap (amendment 1; the on_alarm=keep results computed before the change stay in syscall-arms-cusum/);
#   3. after feature-groups-primary-1022: the same (cap) on the feature-group dumps (local), with branch-only p-values.
# CPU only after step 1 (no NFS reads beyond small trial files), nice 19.   SRC=/mnt/.../source bash syscall_cusum.sh
set -euo pipefail
SRC=${SRC:?source snapshot}
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
cd /tmp
A=/mnt/sentinel-pulse-archive
R4=$A/matched-parallel-r4-20261015
L=/var/tmp/syscall-cusum
FG=/var/tmp/feature-groups
DEV=(--campaign $A/matched-parallel-r3-20261015/pulse-development-matrix
     --campaign $A/matched-parallel-r5-rabbit-20261015/pulse-development-matrix)
LIVEC=(--campaign $A/matched-r6-20261018/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
       --campaign $A/matched-r6-20261018/coordinator-rca-followup-20261019/pulse-development-matrix)
mkdir -p $L
[ -d $L/score-dump ] || { rsync -a $R4/score-dump-20261018/ $L/score-dump.partial/; mv $L/score-dump.partial $L/score-dump; }
for set in pulse-attack-dev pulse-live-recalibrated; do
  [ -d $L/replay-$set ] || { rsync -a $R4/syscall-arms-bootstrap/replay-$set/ $L/replay-$set.partial/; mv $L/replay-$set.partial $L/replay-$set; }
done
echo "local copies done $(date -u +%FT%T)"
mkdir -p $R4/syscall-arms-cusum-cap
pids=()
for set in pulse-attack-dev pulse-live-recalibrated; do
  c=("${DEV[@]}"); [ $set = pulse-live-recalibrated ] && c=("${LIVEC[@]}")
  ( [ -f $L/budget-cap-$set/RESULTS.json ] || $PY -u -m sentinel_pulse.syscall_study.arm_budget --study $R4/syscall-matched-study \
      --dump-root $L/score-dump --replay $L/replay-$set "${c[@]}" --cusum-drift 3 --cusum-on-alarm cap --output $L/budget-cap-$set
    $PY -u -m sentinel_pulse.syscall_study.arm_bootstrap --budget-dir $L/budget-cap-$set --output $L/BOOTSTRAP-cap-$set.json
    python3 $SRC/scripts/analysis/arm_scenarios.py --budget-dir $L/budget-cap-$set "${c[@]}" --output $L/arm-scenarios-cap-$set.json
    cp $L/budget-cap-$set/RESULTS.json $R4/syscall-arms-cusum-cap/RESULTS-$set.json
    cp $L/BOOTSTRAP-cap-$set.json $L/arm-scenarios-cap-$set.json $R4/syscall-arms-cusum-cap/ ) &
  pids+=($!)
done
for p in "${pids[@]}"; do wait $p; done
echo "syscall arms done $(date -u +%FT%T)"
while [ "$(systemctl is-active feature-groups-primary-1022)" = active ]; do sleep 300; done
[ "$(systemctl show -p Result --value feature-groups-primary-1022)" = success ] || { echo "feature-groups-primary-1022 did not succeed"; exit 1; }
mkdir -p $R4/feature-groups/cusum-cap
pids=()
for set in pulse-attack-dev pulse-live-recalibrated; do
  c=("${DEV[@]}"); [ $set = pulse-live-recalibrated ] && c=("${LIVEC[@]}")
  ( [ -f $FG/cusum-cap-budget-$set/RESULTS.json ] || $PY -u -m sentinel_pulse.syscall_study.arm_budget --study $FG/study \
      --dump-root $FG/score-dump --replay $FG/replay-$set "${c[@]}" --cusum-drift 3 --cusum-on-alarm cap \
      --pvalue joint --pvalue tree --pvalue support --output $FG/cusum-cap-budget-$set
    $PY -u -m sentinel_pulse.syscall_study.arm_bootstrap --budget-dir $FG/cusum-cap-budget-$set --output $FG/CUSUM-CAP-BOOTSTRAP-$set.json
    python3 $SRC/scripts/analysis/arm_scenarios.py --budget-dir $FG/cusum-cap-budget-$set "${c[@]}" --output $FG/cusum-cap-arm-scenarios-$set.json
    cp $FG/cusum-cap-budget-$set/RESULTS.json $R4/feature-groups/cusum-cap/RESULTS-$set.json
    cp $FG/CUSUM-CAP-BOOTSTRAP-$set.json $FG/cusum-cap-arm-scenarios-$set.json $R4/feature-groups/cusum-cap/ ) &
  pids+=($!)
done
for p in "${pids[@]}"; do wait $p; done
echo "done $(date -u +%FT%T)"
