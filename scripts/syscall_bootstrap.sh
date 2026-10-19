#!/usr/bin/env bash
# Syscall experiment, corrected and with CIs (run on .234 as dat after the R6 capture ends):
# trial keys are now campaign-qualified (bare '12:attack' repeated across R3/R5 and across the
# two R6 campaigns), so both replays are recomputed, then matched-budget outcomes per trial,
# then the paired workload-clustered bootstrap of protocol v2.
set -euo pipefail
SRC=${SRC:?source snapshot}
R4=/mnt/sentinel-pulse-archive/matched-parallel-r4-20261015
R6=/mnt/sentinel-pulse-archive/matched-r6-20261018
R3C=/mnt/sentinel-pulse-archive/matched-parallel-r3-20261015/pulse-development-matrix
R5C=/mnt/sentinel-pulse-archive/matched-parallel-r5-rabbit-20261015/pulse-development-matrix
MAIN=$R6/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
FOLLOW=$R6/coordinator-rca-followup-20261019/pulse-development-matrix
OUT=$R4/bootstrap-20261020
for node in k8s-worker1.local k8s-worker4.local k8s-worker3.local; do
  until [ -f "$R6/workers/$node/TERMINAL.json" ]; do sleep 60; done
done
mkdir -p "$OUT"
cd /tmp
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
py() { /home/dat/ml-venv/bin/python -u -m "$@"; }
py sentinel_pulse.syscall_study.arm_attack_replay --study "$R4/syscall-matched-study" \
  --campaign "$R3C" --campaign "$R5C" --alpha-scale 1 --output "$OUT/replay-r3r5"
py sentinel_pulse.syscall_study.arm_attack_replay --study "$R4/syscall-matched-study" --workers-root "$R6/workers" \
  --campaign "$MAIN" --campaign "$FOLLOW" --alpha-scale 1 --output "$OUT/replay-r6"
for set in r3r5 r6; do
  campaigns=(--campaign "$R3C" --campaign "$R5C"); [ $set = r6 ] && campaigns=(--campaign "$MAIN" --campaign "$FOLLOW")
  py sentinel_pulse.syscall_study.arm_budget --study "$R4/syscall-matched-study" --dump-root "$R4/score-dump-20261018" \
    --replay "$OUT/replay-$set" "${campaigns[@]}" --output "$OUT/budget-$set"
  py sentinel_pulse.syscall_study.arm_bootstrap --budget-dir "$OUT/budget-$set" --output "$OUT/BOOTSTRAP-$set.json"
done
