#!/usr/bin/env bash
# Resumable fail-closed normal -> blind lifecycle. It never promotes a model.
set -euo pipefail

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
PYTHON=${PYTHON:-python3}
MODEL_SOURCE=${MODEL_SOURCE:?point to the frozen candidate directory}
POLICY_SOURCE=${POLICY_SOURCE:-$LOCAL_ROOT/sentinel_pulse/protocol/decision-policy-semantic-v4.json}
NORMAL_RUN_ID=${NORMAL_RUN_ID:-pulse500-normal-soak-$(date -u +%Y%m%dT%H%M%SZ)}
NORMAL_EVIDENCE_ROOT=${NORMAL_EVIDENCE_ROOT:-$LOCAL_ROOT/validation-evidence/sentinel-pulse-campaign/$NORMAL_RUN_ID}
BLIND_RUN_ID=${BLIND_RUN_ID:-pulse500-blind-$(date -u +%Y%m%dT%H%M%SZ)}
BLIND_EVIDENCE_ROOT=${BLIND_EVIDENCE_ROOT:-$LOCAL_ROOT/validation-evidence/sentinel-pulse-campaign/$BLIND_RUN_ID}
FINALIZE_MARGIN_SECONDS=${FINALIZE_MARGIN_SECONDS:-300}
STOP_AFTER_NORMAL=${STOP_AFTER_NORMAL:-false}
STATE_ROOT=${STATE_ROOT:-$LOCAL_ROOT/validation-evidence/sentinel-pulse-campaign}
PHASE_LOG=${PHASE_LOG:-$STATE_ROOT/$NORMAL_RUN_ID-lifecycle.jsonl}

: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
[[ $NORMAL_RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $BLIND_RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $FINALIZE_MARGIN_SECONDS =~ ^[0-9]+$ ]]
[[ $STOP_AFTER_NORMAL == true || $STOP_AFTER_NORMAL == false ]]
test -f "$MODEL_SOURCE/manifest.json"
test -f "$POLICY_SOURCE"
mkdir -p "$STATE_ROOT"

phase() {
  python3 - "$PHASE_LOG" "$1" <<'PY'
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

path = Path(sys.argv[1])
row = {
    "schema": "sentinel-pulse-candidate-lifecycle-phase-v1",
    "phase": sys.argv[2],
    "recorded_at": datetime.now(timezone.utc).isoformat(),
    "automatic_promotion": False,
}
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(row, separators=(",", ":")) + "\n")
PY
}

if [[ ! -e "$NORMAL_EVIDENCE_ROOT/SOAK_START.json" ]]; then
  traffic_gate="$STATE_ROOT/$NORMAL_RUN_ID-traffic-gate.json"
  phase production_traffic_preflight
  if ! "$PYTHON" -m sentinel_pulse.traffic_gate --samples 20 \
    --output "$traffic_gate"; then
    phase terminal_traffic_preflight_rejected
    exit 5
  fi
  phase normal_preflight
  LOCAL_ROOT="$LOCAL_ROOT" MODEL_SOURCE="$MODEL_SOURCE" \
    POLICY_SOURCE="$POLICY_SOURCE" RUN_ID="$NORMAL_RUN_ID" \
    EVIDENCE_ROOT="$NORMAL_EVIDENCE_ROOT" \
    "$LOCAL_ROOT/sentinel_pulse/start_500ms_normal_soak.sh"
  phase normal_active
fi

if [[ -e "$NORMAL_EVIDENCE_ROOT/FAILED" ]]; then
  if [[ ! -e "$NORMAL_EVIDENCE_ROOT/ARCHIVE_COMPLETE" ]]; then
    phase normal_failure_archive
    "$LOCAL_ROOT/sentinel_pulse/freeze_failed_500ms_normal_soak.sh" \
      "$NORMAL_EVIDENCE_ROOT"
  fi
  phase terminal_normal_infrastructure_failure
  exit 3
fi

if [[ -e "$NORMAL_EVIDENCE_ROOT/ACTIVE" ]]; then
  phase normal_monitor
  if ! "$LOCAL_ROOT/sentinel_pulse/monitor_500ms_normal_soak.sh" \
    "$NORMAL_EVIDENCE_ROOT"; then
    phase normal_monitor_failed
    "$LOCAL_ROOT/sentinel_pulse/freeze_failed_500ms_normal_soak.sh" \
      "$NORMAL_EVIDENCE_ROOT"
    phase terminal_normal_failure
    exit 3
  fi
fi

if [[ ! -e "$NORMAL_EVIDENCE_ROOT/NORMAL_PASS" ]]; then
  test -e "$NORMAL_EVIDENCE_ROOT/READY_TO_FINALIZE"
  eligible_epoch=$(python3 - "$NORMAL_EVIDENCE_ROOT/SOAK_START.json" <<'PY'
from datetime import datetime
import json
from pathlib import Path
import sys
print(int(datetime.fromisoformat(json.loads(Path(sys.argv[1]).read_text())["eligible_finalize_after"]).timestamp()))
PY
  )
  delay=$((eligible_epoch + FINALIZE_MARGIN_SECONDS - $(date +%s)))
  ((delay <= 0)) || sleep "$delay"
  phase normal_finalize
  if MODEL_SOURCE="$MODEL_SOURCE" POLICY_SOURCE="$POLICY_SOURCE" \
      FINALIZE_MARGIN_SECONDS="$FINALIZE_MARGIN_SECONDS" \
      "$LOCAL_ROOT/sentinel_pulse/finalize_500ms_normal_soak.sh" \
      "$NORMAL_EVIDENCE_ROOT"; then
    :
  else
    finalize_rc=$?
    phase normal_finalize_failed
    if [[ ! -e "$NORMAL_EVIDENCE_ROOT/FAILED" ]]; then
      printf 'failed_at=%s\nreason=normal_finalize_failed\nhost=control-plane\nexit_code=%s\n' \
        "$(date -u +%FT%TZ)" "$finalize_rc" \
        >"$NORMAL_EVIDENCE_ROOT/FAILED.tmp"
      mv "$NORMAL_EVIDENCE_ROOT/FAILED.tmp" \
        "$NORMAL_EVIDENCE_ROOT/FAILED"
    fi
    rm -f "$NORMAL_EVIDENCE_ROOT/ACTIVE"
    if [[ ! -e "$NORMAL_EVIDENCE_ROOT/ARCHIVE_COMPLETE" ]]; then
      phase normal_finalize_failure_archive
      "$LOCAL_ROOT/sentinel_pulse/freeze_failed_500ms_normal_soak.sh" \
        "$NORMAL_EVIDENCE_ROOT"
    fi
    phase terminal_normal_finalize_failure
    exit 3
  fi
fi

test -e "$NORMAL_EVIDENCE_ROOT/NORMAL_PASS"
if [[ $STOP_AFTER_NORMAL == true ]]; then
  phase lifecycle_complete_after_normal
  exit 0
fi
phase normal_pass_blind_interlock_open
if [[ -e "$BLIND_EVIDENCE_ROOT" ]]; then
  if [[ -e "$BLIND_EVIDENCE_ROOT/BLIND_RESULT.json" && \
        ! -e "$BLIND_EVIDENCE_ROOT/LIFECYCLE_FAILED" && \
        ! -e "$BLIND_EVIDENCE_ROOT/FINALIZE_FAILED" ]]; then
    phase lifecycle_complete
    exit 0
  fi
  echo "existing blind evidence is not terminal-success; refusing automatic rerun" >&2
  phase terminal_blind_failure
  exit 4
fi

phase blind_active
NORMAL_EVIDENCE_ROOT="$NORMAL_EVIDENCE_ROOT" MODEL_SOURCE="$MODEL_SOURCE" \
  POLICY_SOURCE="$POLICY_SOURCE" RUN_ID="$BLIND_RUN_ID" \
  EVIDENCE_ROOT="$BLIND_EVIDENCE_ROOT" \
  "$LOCAL_ROOT/sentinel_pulse/run_500ms_blind_campaign.sh"
phase lifecycle_complete
