#!/usr/bin/env bash
# Run a bounded live-normal canary through terminal, checksum-bound collection.
set -Eeuo pipefail

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
EVIDENCE_ROOT=${EVIDENCE_ROOT:?choose a new control-plane evidence directory}
POLL_SECONDS=${POLL_SECONDS:-10}
TERMINAL_GRACE_SECONDS=${TERMINAL_GRACE_SECONDS:-600}
SSH_USER=${SSH_USER:-dat}
: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"

[[ $POLL_SECONDS =~ ^[1-9][0-9]*$ ]]
[[ $TERMINAL_GRACE_SECONDS =~ ^[1-9][0-9]*$ ]]
(( TERMINAL_GRACE_SECONDS >= 300 ))

"$LOCAL_ROOT/sentinel_pulse/start_bounded_live_canary.sh"

test -f "$EVIDENCE_ROOT/ACTIVE"
test -f "$EVIDENCE_ROOT/START.json"
test -f "$EVIDENCE_ROOT/workers.txt"
RUN_ID=$(jq -er '.run_id' "$EVIDENCE_ROOT/START.json")
DURATION_SECONDS=$(jq -er '.duration_seconds' "$EVIDENCE_ROOT/START.json")
STARTED_EPOCH=$(python3 - "$EVIDENCE_ROOT/START.json" <<'PY'
from datetime import datetime
import json
from pathlib import Path
import sys

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["started_at"]
print(int(datetime.fromisoformat(value).timestamp()))
PY
)
DEADLINE=$((STARTED_EPOCH + DURATION_SECONDS + TERMINAL_GRACE_SECONDS))

remote_sudo() {
  local host=$1; shift
  printf '%s\n' "$SSHPASS" | sshpass -e ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=8 "$SSH_USER@$host" "sudo -S -p '' $*"
}

write_monitor_row() {
  local node=$1 state=$2 decisions=$3 alerts=$4 finalizer=$5
  python3 - "$EVIDENCE_ROOT/MONITOR.jsonl" \
    "$node" "$state" "$decisions" "$alerts" "$finalizer" <<'PY'
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
row = {
    "schema": "sentinel-pulse-bounded-supervisor-row-v1",
    "observed_at": datetime.now(timezone.utc).isoformat(),
    "node": sys.argv[2],
    "terminal_state": sys.argv[3],
    "decisions": int(sys.argv[4]),
    "alerts": int(sys.argv[5]),
    "finalizer_state": sys.argv[6],
}
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(row, separators=(",", ":")) + "\n")
PY
}

while :; do
  complete=0
  failure=0
  observed_alerts=0
  while read -r host node unit; do
    snapshot=$(remote_sudo "$host" bash -c \
      "'source /etc/sentinel-pulse-detector-candidate.env; run=/var/lib/sentinel-pulse-500ms/runs/$RUN_ID; if test -f \"\$run/CANARY_COMPLETE\"; then terminal=complete; elif test -f \"\$run/CANARY_FAILED.txt\"; then terminal=failed; else terminal=active; fi; printf \"terminal=%s\\ndecisions=%s\\nalerts=%s\\nfinalizer=%s\\n\" \"\$terminal\" \"\$(wc -l < \"\$PULSE_DECISIONS\" 2>/dev/null || echo 0)\" \"\$(wc -l < \"\$PULSE_ALERTS\" 2>/dev/null || echo 0)\" \"\$(systemctl is-active $unit.service 2>/dev/null || true)\"'" \
    ) || {
      snapshot=$'terminal=failed\ndecisions=0\nalerts=0\nfinalizer=unreachable'
    }
    value() { sed -n "s/^$1=//p" <<<"$snapshot"; }
    terminal=$(value terminal)
    decisions=$(value decisions)
    alerts=$(value alerts)
    finalizer=$(value finalizer)
    [[ $decisions =~ ^[0-9]+$ && $alerts =~ ^[0-9]+$ ]] || {
      terminal=failed; decisions=0; alerts=0
    }
    write_monitor_row "$node" "$terminal" "$decisions" "$alerts" "$finalizer"
    observed_alerts=$((observed_alerts + alerts))
    if [[ $terminal == complete ]]; then
      complete=$((complete + 1))
    fi
    if [[ $terminal == failed ]]; then
      failure=1
    fi
  done <"$EVIDENCE_ROOT/workers.txt"

  if ((observed_alerts > 0 || failure == 1)); then
    "$LOCAL_ROOT/sentinel_pulse/freeze_failed_bounded_live_canary.sh" \
      "$EVIDENCE_ROOT"
    exit 1
  fi
  if ((complete == 3)); then
    if "$LOCAL_ROOT/sentinel_pulse/collect_bounded_live_canary.sh" \
      "$EVIDENCE_ROOT"; then
      exit 0
    fi
    # Collection includes the workload coverage gate. A checksum, identity or
    # coverage rejection must still reach a terminal archived state.
    "$LOCAL_ROOT/sentinel_pulse/freeze_failed_bounded_live_canary.sh" \
      "$EVIDENCE_ROOT"
    exit 1
  fi
  if (( $(date +%s) >= DEADLINE )); then
    printf 'supervisor_deadline_exceeded_at=%s\n' "$(date -u +%FT%TZ)" \
      >"$EVIDENCE_ROOT/SUPERVISOR_TIMEOUT"
    "$LOCAL_ROOT/sentinel_pulse/freeze_failed_bounded_live_canary.sh" \
      "$EVIDENCE_ROOT"
    exit 1
  fi
  sleep "$POLL_SECONDS"
done
