#!/usr/bin/env bash
# Wait for the exact formal normal terminal gate, then launch blind evaluation.
set -euo pipefail

NORMAL_EVIDENCE_ROOT=${NORMAL_EVIDENCE_ROOT:?point to the formal normal soak}
LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
WAIT_TIMEOUT_SECONDS=${WAIT_TIMEOUT_SECONDS:-10800}
POLL_SECONDS=${POLL_SECONDS:-60}
[[ $WAIT_TIMEOUT_SECONDS =~ ^[0-9]+$ ]] && ((WAIT_TIMEOUT_SECONDS >= 600))
[[ $POLL_SECONDS =~ ^[0-9]+$ ]] && ((POLL_SECONDS >= 15 && POLL_SECONDS <= 300))
deadline=$(( $(date +%s) + WAIT_TIMEOUT_SECONDS ))

while (( $(date +%s) < deadline )); do
  if [[ -f "$NORMAL_EVIDENCE_ROOT/NORMAL_PASS" ]]; then
    exec "$LOCAL_ROOT/sentinel_pulse/run_500ms_blind_campaign.sh"
  fi
  if [[ -e "$NORMAL_EVIDENCE_ROOT/FAILED" || \
        -e "$NORMAL_EVIDENCE_ROOT/FINALIZE_FAILED" ]]; then
    echo "formal normal run failed; blind interlock remains closed" >&2
    exit 3
  fi
  sleep "$POLL_SECONDS"
done
echo "timed out waiting for formal NORMAL_PASS" >&2
exit 4
