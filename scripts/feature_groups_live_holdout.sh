#!/usr/bin/env bash
# Feature-group phase B on the second holdout (protocol feature-group-evaluation-v1-live-holdout), on .234 as dat.
# Local copy only; CPU-bound: one process per node. score -> register -> k2of2 budgets (joint/tree/support)
# -> paired bootstrap vs base29 -> per-scenario recall.
#   SRC=/var/tmp/feature-groups/source-<sha> bash feature_groups_live_holdout.sh
set -euo pipefail
SRC=${SRC:?source}
L=/var/tmp/feature-groups
OUT=$L/eval-live-holdout
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
cd /tmp
LIVE=/mnt/sentinel-pulse-archive/matched-r6-20261018
C=(--campaign $LIVE/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
   --campaign $LIVE/coordinator-rca-followup-20261019/pulse-development-matrix)
HOLD=1792389600:1792437742
INCIDENT=1792409100:1792412400
pids=()
for n in k8s-worker1.local k8s-worker3.local k8s-worker4.local; do
  [ -f $OUT/replay/RESULTS-$n.json ] && continue
  $PY -u -m sentinel_pulse.syscall_study.baselines score --workers-root /var/tmp/pulse-live-copy/workers \
    --pulse-study $L/study --study-arm all "${C[@]}" --output $OUT --holdout $HOLD --exclude $INCIDENT --node $n \
    > $L/live-holdout-score-$n.log 2>&1 &
  pids+=($!)
done
for p in "${pids[@]}"; do wait $p; done
$PY -m sentinel_pulse.syscall_study.baselines register --output $OUT --pulse-study $L/study --holdout $HOLD --arm study
[ -f $L/live-holdout-budget/RESULTS.json ] || $PY -u -m sentinel_pulse.syscall_study.arm_budget --study $OUT \
  --dump-root $OUT/score-dump --replay $OUT/replay "${C[@]}" --confirm-k 2 --confirm-n 2 --calibration-fraction 0.42 \
  --pvalue joint --pvalue tree --pvalue support --output $L/live-holdout-budget
$PY -u -m sentinel_pulse.syscall_study.arm_bootstrap --budget-dir $L/live-holdout-budget --output $L/LIVE-HOLDOUT-BOOTSTRAP.json
$PY $SRC/scripts/analysis/arm_scenarios.py --budget-dir $L/live-holdout-budget "${C[@]}" --output $L/live-holdout-arm-scenarios.json
echo "done $(date -u +%FT%T)"
