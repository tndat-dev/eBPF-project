#!/usr/bin/env bash
# Attach the external fail-closed supervisor only after formal launch commits.
set -Eeuo pipefail

EVIDENCE_ROOT=${1:?usage: attach_lifecycle_supervisor_when_ready.sh EVIDENCE_ROOT LIFECYCLE_PID}
LIFECYCLE_PID=${2:?usage: attach_lifecycle_supervisor_when_ready.sh EVIDENCE_ROOT LIFECYCLE_PID}
LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
POLL_SECONDS=${POLL_SECONDS:-10}
WAIT_TIMEOUT_SECONDS=${WAIT_TIMEOUT_SECONDS:-2400}

: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
[[ $LIFECYCLE_PID =~ ^[1-9][0-9]*$ ]]
[[ $POLL_SECONDS =~ ^[1-9][0-9]*$ ]]
[[ $WAIT_TIMEOUT_SECONDS =~ ^[1-9][0-9]*$ ]]
deadline=$(( $(date +%s) + WAIT_TIMEOUT_SECONDS ))

while kill -0 "$LIFECYCLE_PID" 2>/dev/null; do
  if [[ -e "$EVIDENCE_ROOT/NORMAL_PASS" || \
        -e "$EVIDENCE_ROOT/ARCHIVE_COMPLETE" ]]; then
    exit 0
  fi
  # SOAK_START is intentionally written before worker mutation. Waiting on it
  # alone races with workers.txt creation; ACTIVE is the launch commit marker.
  if [[ -f "$EVIDENCE_ROOT/ACTIVE" && \
        -f "$EVIDENCE_ROOT/SOAK_START.json" && \
        -f "$EVIDENCE_ROOT/workers.txt" && \
        $(wc -l <"$EVIDENCE_ROOT/workers.txt") -eq 3 ]]; then
    exec "$LOCAL_ROOT/sentinel_pulse/supervise_500ms_candidate_lifecycle.sh" \
      "$EVIDENCE_ROOT" "$LIFECYCLE_PID"
  fi
  (( $(date +%s) < deadline )) || {
    echo "formal lifecycle did not reach ACTIVE before supervisor timeout" >&2
    exit 2
  }
  sleep "$POLL_SECONDS"
done

echo "lifecycle exited before a three-worker ACTIVE commit" >&2
exit 3
