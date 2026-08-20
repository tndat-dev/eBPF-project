#!/usr/bin/env bash
# Read-only fail-closed monitor for a preregistered Pulse normal soak.
set -u

EVIDENCE_ROOT=${1:?usage: monitor_500ms_normal_soak.sh EVIDENCE_ROOT}
SSH_USER=${SSH_USER:-dat}
POLL_SECONDS=${POLL_SECONDS:-60}
: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
MARKER="$EVIDENCE_ROOT/SOAK_START.json"
WORKERS_FILE="$EVIDENCE_ROOT/workers.txt"
LOG="$EVIDENCE_ROOT/MONITOR.jsonl"
test -f "$MARKER" && test -f "$WORKERS_FILE" && test -f "$EVIDENCE_ROOT/ACTIVE" || exit 2
test ! -e "$EVIDENCE_ROOT/FAILED" || exit 2

eligible_epoch=$(python3 - "$MARKER" <<'PY'
from datetime import datetime
import json, pathlib, sys
marker=json.loads(pathlib.Path(sys.argv[1]).read_text())
print(datetime.fromisoformat(marker["eligible_finalize_after"]).timestamp())
PY
)

write_row() {
  python3 - "$LOG" "$@" <<'PY'
import json, pathlib, sys, time
path=pathlib.Path(sys.argv[1])
host, collector, detector, restarts, decisions, alerts, feature, expected = sys.argv[2:]
row={
    "checked_at_unix": time.time(), "host": host,
    "collector": collector, "detector": detector,
    "nrestarts": int(restarts), "decisions": int(decisions),
    "alerts": int(alerts), "feature_source": feature,
    "expected_feature_source": expected,
}
with path.open("a", encoding="utf-8") as out:
    out.write(json.dumps(row, separators=(",", ":")) + "\n")
PY
}

fail() {
  local reason=$1 host=${2:-unknown}
  printf 'failed_at=%s\nreason=%s\nhost=%s\n' \
    "$(date -u +%FT%TZ)" "$reason" "$host" >"$EVIDENCE_ROOT/FAILED"
  rm -f "$EVIDENCE_ROOT/ACTIVE"
  exit 1
}

while true; do
  while read -r host _node expected_feature; do
    snapshot=$(printf '%s\n' "$SSHPASS" | sshpass -e ssh \
      -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" \
      "sudo -S bash -c 'source /etc/sentinel-pulse-detector-candidate.env; printf \"collector=%s\\ndetector=%s\\nrestarts=%s\\ndecisions=%s\\nalerts=%s\\nfeature=%s\\n\" \"\$(systemctl is-active sentinel-pulse-collector-500ms-experiment)\" \"\$(systemctl is-active sentinel-pulse-detector-candidate)\" \"\$(systemctl show sentinel-pulse-detector-candidate -p NRestarts --value)\" \"\$(wc -l < \"\$PULSE_DECISIONS\")\" \"\$(wc -l < \"\$PULSE_ALERTS\")\" \"\$PULSE_FEATURES\"'" 2>/dev/null) || fail ssh_unreachable "$host"
    value() { sed -n "s/^$1=//p" <<<"$snapshot"; }
    collector=$(value collector); detector=$(value detector)
    restarts=$(value restarts); decisions=$(value decisions)
    alerts=$(value alerts); feature=$(value feature)
    [[ $restarts =~ ^[0-9]+$ && $decisions =~ ^[0-9]+$ && $alerts =~ ^[0-9]+$ ]] || fail invalid_snapshot "$host"
    write_row "$host" "$collector" "$detector" "$restarts" "$decisions" "$alerts" "$feature" "$expected_feature"
    [[ $collector == active ]] || fail collector_inactive "$host"
    [[ $detector == active ]] || fail detector_inactive "$host"
    ((restarts == 0)) || fail detector_restarted "$host"
    ((alerts == 0)) || fail normal_alert_observed "$host"
    [[ $feature == "$expected_feature" ]] || fail feature_source_mismatch "$host"
  done <"$WORKERS_FILE"
  now=$(date +%s)
  if ((now >= ${eligible_epoch%.*})); then
    printf 'ready_at=%s\n' "$(date -u +%FT%TZ)" >"$EVIDENCE_ROOT/READY_TO_FINALIZE"
    exit 0
  fi
  sleep "$POLL_SECONDS"
done
