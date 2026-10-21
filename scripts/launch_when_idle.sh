#!/usr/bin/env bash
# Start a live run (scripts/launch_run.sh all) once the previous run's analysis unit has finished, so no heavy
# NFS analysis overlaps the new capture. Run as dat via systemd-run with an EnvironmentFile holding
# LAB_SSH_PASSWORD and the launch_run.sh variables (RUN, SNAP, CANDIDATE, MODEL_HASH, POLICY, POLICY_HASH, FAST,
# RCA_PREV_UNIT); the file is root-only and read by systemd, not by this script.
set -euo pipefail
WAIT_UNIT=${WAIT_UNIT:-pulse-stable-candidate-analysis}
while [ "$(systemctl is-active "$WAIT_UNIT")" = active ]; do sleep 120; done
echo "wait unit $WAIT_UNIT is $(systemctl is-active "$WAIT_UNIT") ($(systemctl show -p Result --value "$WAIT_UNIT")); launching $RUN $(date -u +%FT%T)"
cd /tmp
bash "$SNAP/scripts/launch_run.sh" all
echo "launched $RUN $(date -u +%FT%T)"
