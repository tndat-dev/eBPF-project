#!/usr/bin/env bash
# Pulse G1 baselines (protocol baseline-evaluation-v1) on .234 as dat. Local copies only; the two campaigns'
# small JSON files are the only NFS reads. fit -> score (one process per node) -> register -> k2of2 budgets
# -> paired bootstrap vs base29 -> per-scenario recall.
set -euo pipefail
SHA=58a891e
B=/var/tmp/baselines
SRC=$B/source-$SHA
mkdir -p $B
[ -d $SRC ] || { mkdir -p $SRC.partial; git -C /home/dat/eBPF-project archive $SHA | tar -x -C $SRC.partial; mv $SRC.partial $SRC; }
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
cd /tmp
STUDY=/var/tmp/feature-groups/study   # its base29 arm reproduces the syscall-arms base29 models (REFERENCE_CHECK.json)
LIVE=/mnt/sentinel-pulse-archive/matched-r6-20261018
C=(--campaign $LIVE/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
   --campaign $LIVE/coordinator-rca-followup-20261019/pulse-development-matrix)
HOLD=1792389600:1792437742            # 19/10 13:00 .. capture end (last worker TERMINAL)
INCIDENT=1792409100:1792412400        # 19/10 18:25-19:20
OUT=$B/eval-pulse-live-recalibrated
echo "fit $(date -u +%FT%T)"
$PY -u -m sentinel_pulse.syscall_study.baselines fit --source-study $STUDY \
  --workload-dir /var/tmp/feature-groups/workloads --output $B/models
echo "score $(date -u +%FT%T)"
pids=()
for n in k8s-worker1.local k8s-worker3.local k8s-worker4.local; do
  [ -f $OUT/replay/RESULTS-$n.json ] && continue
  $PY -u -m sentinel_pulse.syscall_study.baselines score --workers-root /var/tmp/pulse-live-copy/workers \
    --pulse-study $STUDY --baselines $B/models "${C[@]}" --output $OUT --holdout $HOLD --exclude $INCIDENT \
    --node $n > $B/score-$n.log 2>&1 &
  pids+=($!)
done
for p in "${pids[@]}"; do wait $p; done
$PY -m sentinel_pulse.syscall_study.baselines register --output $OUT --pulse-study $STUDY --holdout $HOLD
echo "budget $(date -u +%FT%T)"
[ -f $B/budget/RESULTS.json ] || $PY -u -m sentinel_pulse.syscall_study.arm_budget --study $OUT \
  --dump-root $OUT/score-dump --replay $OUT/replay "${C[@]}" --confirm-k 2 --confirm-n 2 \
  --calibration-fraction 0.42 --output $B/budget
$PY -u -m sentinel_pulse.syscall_study.arm_bootstrap --budget-dir $B/budget --output $B/BOOTSTRAP.json
$PY $SRC/scripts/analysis/arm_scenarios.py --budget-dir $B/budget "${C[@]}" --output $B/arm-scenarios.json
echo "done $(date -u +%FT%T)"
