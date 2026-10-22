#!/usr/bin/env bash
# feature-group-evaluation-v1: base29@tree / base29@support on the primary holdout (feature_groups_primary.sh of 22/10
# left out the branch-only p-values), k2of2 as the registered v1 rule; run 23/10 01:35 as unit fg-branches-1023 on .234.
set -euo pipefail
FG=/var/tmp/feature-groups; A=/mnt/sentinel-pulse-archive
export PYTHONPATH=/home/dat/eBPF-project PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
cd /tmp
DEV=(--campaign $A/matched-parallel-r3-20261015/pulse-development-matrix --campaign $A/matched-parallel-r5-rabbit-20261015/pulse-development-matrix)
LIVEC=(--campaign $A/matched-r6-20261018/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix --campaign $A/matched-r6-20261018/coordinator-rca-followup-20261019/pulse-development-matrix)
pids=()
for set in pulse-attack-dev pulse-live-recalibrated; do
  c=("${DEV[@]}"); [ $set = pulse-live-recalibrated ] && c=("${LIVEC[@]}")
  ( [ -f $FG/branches-budget-$set/RESULTS.json ] || /home/dat/ml-venv/bin/python -u -m sentinel_pulse.syscall_study.arm_budget --study $FG/study \
      --dump-root $FG/score-dump --replay $FG/replay-$set "${c[@]}" --confirm-k 2 --confirm-n 2 --arm base29 \
      --pvalue joint --pvalue tree --pvalue support --output $FG/branches-budget-$set
    /home/dat/ml-venv/bin/python -u -m sentinel_pulse.syscall_study.arm_bootstrap --budget-dir $FG/branches-budget-$set --output $FG/BRANCHES-BOOTSTRAP-$set.json ) &
  pids+=($!)
done
for p in "${pids[@]}"; do wait $p; done
echo "done $(date -u +%FT%T)"
