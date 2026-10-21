#!/usr/bin/env bash
# Development numbers for tree_ae (Pulse 5.15b), derived from the finished baseline evaluation on
# pulse-live-recalibrated (no rescoring): combine -> k2of2 budgets -> bootstrap vs base29 -> scenarios.
# Defined after the autoencoder development result was seen; the decisive test is the fresh replication.
#   SRC=/var/tmp/baselines/source-<sha> bash pulse_baselines_tree_ae_dev.sh   (on .234 as dat)
set -euo pipefail
SRC=${SRC:?source}
B=/var/tmp/baselines
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
cd /tmp
LIVE=/mnt/sentinel-pulse-archive/matched-r6-20261018
C=(--campaign $LIVE/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
   --campaign $LIVE/coordinator-rca-followup-20261019/pulse-development-matrix)
HOLD=1792389600:1792437742
OUT=$B/eval-tree-ae-dev
[ -f $OUT/NORMAL_HOLDOUT_START.json ] || $PY -m sentinel_pulse.syscall_study.baselines combine \
  --source $B/eval-pulse-live-recalibrated --output $OUT --pulse-study /var/tmp/feature-groups/study --holdout $HOLD
[ -f $B/tree-ae-budget/RESULTS.json ] || $PY -u -m sentinel_pulse.syscall_study.arm_budget --study $OUT \
  --dump-root $OUT/score-dump --replay $OUT/replay "${C[@]}" --confirm-k 2 --confirm-n 2 \
  --calibration-fraction 0.42 --output $B/tree-ae-budget
$PY -u -m sentinel_pulse.syscall_study.arm_bootstrap --budget-dir $B/tree-ae-budget --output $B/TREE-AE-BOOTSTRAP.json
$PY $SRC/scripts/analysis/arm_scenarios.py --budget-dir $B/tree-ae-budget "${C[@]}" --output $B/tree-ae-arm-scenarios.json
echo "tree_ae dev done $(date -u +%FT%T)"
