#!/usr/bin/env bash
# Syscall experiment, corrected and with CIs. Needs only sealed segments, but it reads tens of GB
# from NFS: running it beside the live pulse-live-recalibrated capture (19/10 18:30-18:55, even from the idle .235)
# raised worker cadence gaps (+63/+18/+46 in 13 min), so it runs only when no live run is active.
# PY/PYLIB point at a scikit-learn 1.9.0 stack on .235.
# trial keys are now campaign-qualified (bare '12:attack' repeated across R3/R5 and across the
# two pulse-live-recalibrated campaigns), so both replays are recomputed, then matched-budget outcomes per trial,
# then the paired workload-clustered bootstrap of protocol v2.
set -euo pipefail
SRC=${SRC:?source snapshot}
SYSCALL_ROOT=/mnt/sentinel-pulse-archive/matched-parallel-r4-20261015
LIVE_ROOT=/mnt/sentinel-pulse-archive/matched-r6-20261018
DEV_CAMPAIGN=/mnt/sentinel-pulse-archive/matched-parallel-r3-20261015/pulse-development-matrix
DEV_RABBITMQ_CAMPAIGN=/mnt/sentinel-pulse-archive/matched-parallel-r5-rabbit-20261015/pulse-development-matrix
MAIN=$LIVE_ROOT/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
FOLLOW=$LIVE_ROOT/coordinator-rca-followup-20261019/pulse-development-matrix
OUT=$SYSCALL_ROOT/syscall-arms-bootstrap   # bootstrap-20261020/ holds a replay stopped at 18:55 (IO contention), not used
mkdir -p "$OUT"
cd /tmp
PY=${PY:-/home/dat/ml-venv/bin/python}
export PYTHONPATH=${PYLIB:+$PYLIB:}$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
py() { "$PY" -u -m "$@"; }
py sentinel_pulse.syscall_study.arm_attack_replay --study "$SYSCALL_ROOT/syscall-matched-study" \
  --campaign "$DEV_CAMPAIGN" --campaign "$DEV_RABBITMQ_CAMPAIGN" --alpha-scale 1 --output "$OUT/replay-pulse-attack-dev"
py sentinel_pulse.syscall_study.arm_attack_replay --study "$SYSCALL_ROOT/syscall-matched-study" --workers-root "$LIVE_ROOT/workers" \
  --campaign "$MAIN" --campaign "$FOLLOW" --alpha-scale 1 --output "$OUT/replay-pulse-live-recalibrated"
for set in pulse-attack-dev pulse-live-recalibrated; do
  campaigns=(--campaign "$DEV_CAMPAIGN" --campaign "$DEV_RABBITMQ_CAMPAIGN")
  [ $set = pulse-live-recalibrated ] && campaigns=(--campaign "$MAIN" --campaign "$FOLLOW")
  py sentinel_pulse.syscall_study.arm_budget --study "$SYSCALL_ROOT/syscall-matched-study" --dump-root "$SYSCALL_ROOT/score-dump-20261018" \
    --replay "$OUT/replay-$set" "${campaigns[@]}" --output "$OUT/budget-$set"
  py sentinel_pulse.syscall_study.arm_bootstrap --budget-dir "$OUT/budget-$set" --output "$OUT/BOOTSTRAP-$set.json"
done
