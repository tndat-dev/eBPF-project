#!/usr/bin/env bash
# Start a live run (scripts/launch_run.sh all) once the previous run's analysis unit has finished, so no heavy
# NFS analysis overlaps the new capture. Run as dat via systemd-run with an EnvironmentFile holding
# LAB_SSH_PASSWORD and the launch_run.sh variables (RUN, SNAP, CANDIDATE, MODEL_HASH, POLICY, POLICY_HASH, FAST,
# RCA_PREV_UNIT); the file is root-only and read by systemd, not by this script.
set -euo pipefail
# the planner records the snapshot's commit (git rev-parse): SNAP must be a git checkout, not a git archive
git -C "$SNAP" rev-parse HEAD >/dev/null
# WAIT_UNITS: space-separated units that must all be inactive (WAIT_UNIT kept for the older single-unit form)
WAIT_UNITS=${WAIT_UNITS:-${WAIT_UNIT:-pulse-stable-candidate-analysis}}
for unit in $WAIT_UNITS; do
  while [ "$(systemctl is-active "$unit")" = active ]; do sleep 120; done
  echo "wait unit $unit is $(systemctl is-active "$unit") ($(systemctl show -p Result --value "$unit"))"
done
echo "launching $RUN $(date -u +%FT%T)"
cd /tmp
bash "$SNAP/scripts/launch_run.sh" all
echo "launched $RUN $(date -u +%FT%T)"
