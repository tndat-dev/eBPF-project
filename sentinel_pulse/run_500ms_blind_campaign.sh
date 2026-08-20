#!/usr/bin/env bash
# Disconnect-safe full lifecycle: start, execute, freeze and evaluate. No promote.
set -euo pipefail

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
RUN_ID=${RUN_ID:-pulse500-blind-$(date -u +%Y%m%dT%H%M%SZ)}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-$LOCAL_ROOT/validation-evidence/sentinel-pulse-campaign/$RUN_ID}
REMOTE_ROOT=${REMOTE_ROOT:-/home/dat/eBPF-project-pulse-blind}
export LOCAL_ROOT RUN_ID EVIDENCE_ROOT REMOTE_ROOT

"$LOCAL_ROOT/sentinel_pulse/start_500ms_blind_matrix.sh"
PYTHONPATH="$LOCAL_ROOT" /home/dat/ml-venv/bin/python \
  -m sentinel_pulse.run_500ms_blind_matrix \
  --evidence-root "$EVIDENCE_ROOT" \
  --model-dir "$EVIDENCE_ROOT/model" \
  --attack-contract "$LOCAL_ROOT/sentinel_pulse/protocol/blind-attack-contract.json" \
  --implementation-contract "$LOCAL_ROOT/ml-service/aims_blind_attack_contract.json"
"$LOCAL_ROOT/sentinel_pulse/finalize_500ms_blind_matrix.sh" "$EVIDENCE_ROOT"
