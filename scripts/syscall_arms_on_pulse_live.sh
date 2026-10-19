#!/usr/bin/env bash
# Syscall experiment on the pulse-live-recalibrated campaigns (run on .234 as dat). Waits for the RCA follow-up
# campaign to finish so heavy NFS reads never overlap a live campaign, then:
#  1. replays all 693 R4 models on the pulse-live-recalibrated attack/benign/control intervals (full-ID deltas
#     recorded by the pulse-live-recalibrated workers);
#  2. compares the 11 arms at matched normal alert budgets (calibration from the R4
#     holdout score dump), now including the benign-launch positive rate.
set -euo pipefail
SRC=${SRC:?source snapshot}
SYSCALL_ROOT=/mnt/sentinel-pulse-archive/matched-parallel-r4-20261015
LIVE_ROOT=/mnt/sentinel-pulse-archive/matched-r6-20261018
MAIN=$LIVE_ROOT/coordinator-runtime-r6-d791d24-20261019/pulse-development-matrix
FOLLOW=$LIVE_ROOT/coordinator-rca-followup-20261019/pulse-development-matrix
until [ -f "$FOLLOW/TERMINAL.json" ]; do sleep 120; done
cd /tmp
export PYTHONPATH=$SRC PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1
/home/dat/ml-venv/bin/python -u -m sentinel_pulse.syscall_study.arm_attack_replay \
  --study "$SYSCALL_ROOT/syscall-matched-study" --workers-root "$LIVE_ROOT/workers" \
  --campaign "$MAIN" --campaign "$FOLLOW" \
  --alpha-scale 1 --alpha-scale 3 --alpha-scale 5 --alpha-scale 10 \
  --output "$LIVE_ROOT/analysis-20261019/arm-replay-r6"
/home/dat/ml-venv/bin/python -u -m sentinel_pulse.syscall_study.arm_budget \
  --study "$SYSCALL_ROOT/syscall-matched-study" --dump-root "$SYSCALL_ROOT/score-dump-20261018" \
  --replay "$LIVE_ROOT/analysis-20261019/arm-replay-r6" --campaign "$MAIN" --campaign "$FOLLOW" \
  --output "$LIVE_ROOT/analysis-20261019/arm-budget-r6"
