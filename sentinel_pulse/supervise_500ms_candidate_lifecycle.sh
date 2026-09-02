#!/usr/bin/env bash
# Fail-closed external guard for a long-running candidate lifecycle process.
set -Eeuo pipefail

EVIDENCE_ROOT=${1:?usage: supervise_500ms_candidate_lifecycle.sh EVIDENCE_ROOT LIFECYCLE_PID}
LIFECYCLE_PID=${2:?usage: supervise_500ms_candidate_lifecycle.sh EVIDENCE_ROOT LIFECYCLE_PID}
LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
POLL_SECONDS=${POLL_SECONDS:-30}
EXIT_GRACE_SECONDS=${EXIT_GRACE_SECONDS:-120}

: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
[[ $LIFECYCLE_PID =~ ^[1-9][0-9]*$ ]]
[[ $POLL_SECONDS =~ ^[1-9][0-9]*$ ]]
[[ $EXIT_GRACE_SECONDS =~ ^[1-9][0-9]*$ ]]
test -f "$EVIDENCE_ROOT/SOAK_START.json"
test -f "$EVIDENCE_ROOT/workers.txt"

python3 - "$EVIDENCE_ROOT/LIFECYCLE_SUPERVISOR.json" \
  "$LIFECYCLE_PID" "$POLL_SECONDS" "$EXIT_GRACE_SECONDS" <<'PY'
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

out, lifecycle_pid, poll_seconds, grace_seconds = sys.argv[1:]
Path(out).write_text(json.dumps({
    "schema": "sentinel-pulse-lifecycle-supervisor-v1",
    "attached_at": datetime.now(timezone.utc).isoformat(),
    "lifecycle_pid": int(lifecycle_pid),
    "poll_seconds": int(poll_seconds),
    "exit_grace_seconds": int(grace_seconds),
    "mutates_runtime_only_after_lifecycle_exit_without_terminal_evidence": True,
    "automatic_promotion": False,
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

while kill -0 "$LIFECYCLE_PID" 2>/dev/null; do
  if [[ -e "$EVIDENCE_ROOT/NORMAL_PASS" || \
        -e "$EVIDENCE_ROOT/ARCHIVE_COMPLETE" ]]; then
    exit 0
  fi
  sleep "$POLL_SECONDS"
done

# Give the exiting lifecycle time to finish its terminal rename/checksum path.
deadline=$(( $(date +%s) + EXIT_GRACE_SECONDS ))
while (( $(date +%s) < deadline )); do
  if [[ -e "$EVIDENCE_ROOT/NORMAL_PASS" || \
        -e "$EVIDENCE_ROOT/ARCHIVE_COMPLETE" ]]; then
    exit 0
  fi
  sleep 2
done

exec 9>"$EVIDENCE_ROOT/.lifecycle-supervisor.lock"
flock 9
if [[ -e "$EVIDENCE_ROOT/NORMAL_PASS" || \
      -e "$EVIDENCE_ROOT/ARCHIVE_COMPLETE" ]]; then
  exit 0
fi

reason=lifecycle_process_exited_without_terminal_evidence
if [[ -e "$EVIDENCE_ROOT/FINALIZE_FAILED" ]]; then
  if ! reason=$(PYTHONPATH="$LOCAL_ROOT" python3 -m \
    sentinel_pulse.classify_normal_failure "$EVIDENCE_ROOT"); then
    reason=normal_finalize_failed
  fi
fi
if [[ ! -e "$EVIDENCE_ROOT/FAILED" ]]; then
  printf 'failed_at=%s\nreason=%s\nhost=control-plane\nlifecycle_pid=%s\n' \
    "$(date -u +%FT%TZ)" "$reason" "$LIFECYCLE_PID" \
    >"$EVIDENCE_ROOT/FAILED.tmp"
  mv "$EVIDENCE_ROOT/FAILED.tmp" "$EVIDENCE_ROOT/FAILED"
fi
rm -f "$EVIDENCE_ROOT/ACTIVE"

if [[ ! -e "$EVIDENCE_ROOT/ARCHIVE_COMPLETE" ]]; then
  "$LOCAL_ROOT/sentinel_pulse/freeze_failed_500ms_normal_soak.sh" \
    "$EVIDENCE_ROOT"
fi
