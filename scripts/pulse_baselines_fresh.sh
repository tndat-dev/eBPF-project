#!/usr/bin/env bash
# Protocol baseline-fresh-replication-v1 on .234 as dat, after pulse-stable-refreshed has ended (reads its capture
# from NFS; run inside after_stable_refreshed.sh so no other heavy job overlaps). Frozen models, no refit.
#   SRC=/mnt/.../source bash pulse_baselines_fresh.sh
set -euo pipefail
SRC=${SRC:?source snapshot}
B=/var/tmp/baselines
RUN=/mnt/sentinel-pulse-archive/pulse-stable-refreshed
CAMPAIGN=$RUN/pulse-development-matrix
OUT=$B/fresh-pulse-stable-refreshed
STUDY=/var/tmp/feature-groups/study
PY=/home/dat/ml-venv/bin/python
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
cd /tmp
NODES=(k8s-worker1.local k8s-worker4.local k8s-worker3.local)
for n in "${NODES[@]}"; do test -f $RUN/workers/$n/TERMINAL.json; done
HOLD=$(python3 - "$RUN" <<'PY'
import json, sys
run = sys.argv[1]
start = json.load(open(f'{run}/pulse-development-matrix/TERMINAL.json'))['finished_at_unix'] + 60
end = max(json.load(open(f'{run}/workers/{n}/TERMINAL.json'))['finished_at_unix']
          for n in ('k8s-worker1.local', 'k8s-worker4.local', 'k8s-worker3.local'))
print(f'{start}:{end}')
PY
)
EXCL=()
for s in $(cat $RUN/analysis/EXTRA_EXCLUDE 2>/dev/null || true); do EXCL+=(--exclude "$s"); done
pids=()
for n in "${NODES[@]}"; do
  [ -f $OUT/replay/RESULTS-$n.json ] && continue
  $PY -u -m sentinel_pulse.syscall_study.baselines score --workers-root $RUN/workers --pulse-study $STUDY \
    --baselines $B/models --campaign $CAMPAIGN --output $OUT --holdout $HOLD "${EXCL[@]}" --node $n \
    > $B/fresh-score-$n.log 2>&1 &
  pids+=($!)
done
for p in "${pids[@]}"; do wait $p; done
$PY -m sentinel_pulse.syscall_study.baselines register --output $OUT --pulse-study $STUDY --holdout $HOLD
[ -f $B/fresh-budget/RESULTS.json ] || $PY -u -m sentinel_pulse.syscall_study.arm_budget --study $OUT \
  --dump-root $OUT/score-dump --replay $OUT/replay --campaign $CAMPAIGN --confirm-k 2 --confirm-n 2 \
  --calibration-fraction 0.42 --output $B/fresh-budget
$PY -u -m sentinel_pulse.syscall_study.arm_bootstrap --budget-dir $B/fresh-budget --output $B/FRESH-BOOTSTRAP.json
$PY $SRC/scripts/analysis/arm_scenarios.py --budget-dir $B/fresh-budget --campaign $CAMPAIGN --output $B/fresh-arm-scenarios.json
$PY $SRC/scripts/analysis/adoption_verdict.py --bootstrap $B/FRESH-BOOTSTRAP.json \
  --budget-results $B/fresh-budget/RESULTS.json --output $B/FRESH-ADOPTION.json
echo "fresh baselines done $(date -u +%FT%T)"
