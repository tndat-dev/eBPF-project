#!/usr/bin/env bash
# Disconnect-safe full lifecycle: start, execute, freeze and evaluate. No promote.
set -euo pipefail

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
RUN_ID=${RUN_ID:-pulse500-blind-$(date -u +%Y%m%dT%H%M%SZ)}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-$LOCAL_ROOT/validation-evidence/sentinel-pulse-campaign/$RUN_ID}
REMOTE_ROOT=${REMOTE_ROOT:-/home/dat/eBPF-project-pulse-blind}
SSH_USER=${SSH_USER:-dat}
: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
export LOCAL_ROOT RUN_ID EVIDENCE_ROOT REMOTE_ROOT

complete=false
on_exit() {
  local rc=$?
  if [[ $complete != true && -f "$EVIDENCE_ROOT/workers.txt" ]]; then
    while read -r host _node _feature _injections; do
      printf '%s\n' "$SSHPASS" | sshpass -e ssh \
        -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" \
        "sudo -S -p '' systemctl stop sentinel-pulse-detector-candidate.service sentinel-pulse-collector-500ms-experiment.service" \
        >/dev/null 2>&1 || true
    done <"$EVIDENCE_ROOT/workers.txt"
    printf 'failed_at=%s\nexit_code=%s\n' "$(date -u +%FT%TZ)" "$rc" \
      >"$EVIDENCE_ROOT/LIFECYCLE_FAILED"
    rm -f "$EVIDENCE_ROOT/ACTIVE"
  fi
}
trap on_exit EXIT

"$LOCAL_ROOT/sentinel_pulse/start_500ms_blind_matrix.sh"
PYTHONPATH="$LOCAL_ROOT" /home/dat/ml-venv/bin/python \
  -m sentinel_pulse.run_500ms_blind_matrix \
  --evidence-root "$EVIDENCE_ROOT" \
  --model-dir "$EVIDENCE_ROOT/model" \
  --attack-contract "$EVIDENCE_ROOT/protocol/blind-attack-contract.json" \
  --implementation-contract "$EVIDENCE_ROOT/protocol/attack-implementation-contract.json"
"$LOCAL_ROOT/sentinel_pulse/finalize_500ms_blind_matrix.sh" "$EVIDENCE_ROOT"
complete=true
