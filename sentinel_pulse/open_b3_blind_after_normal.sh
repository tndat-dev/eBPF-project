#!/usr/bin/env bash
# Open the frozen B3 blind matrix only after the exact R5 normal gate passes.
set -Eeuo pipefail

CONTROL_ROOT=${CONTROL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
RUNTIME_ROOT=${RUNTIME_ROOT:-/home/dat/eBPF-project-runtime-pulse-a2-pilot}
NORMAL_EVIDENCE_ROOT=${NORMAL_EVIDENCE_ROOT:?point to the terminal B3 normal evidence}
MODEL_SOURCE=${MODEL_SOURCE:-$RUNTIME_ROOT/.runtime-artifacts/sentinel-pulse-a2-b3-model}
POLICY_SOURCE=${POLICY_SOURCE:-$RUNTIME_ROOT/sentinel_pulse/protocol/decision-policy-temporal-b3.json}
ATTACK_CONTRACT=${ATTACK_CONTRACT:-$CONTROL_ROOT/sentinel_pulse/protocol/blind-attack-contract-b3.json}
IMPLEMENTATION_CONTRACT=${IMPLEMENTATION_CONTRACT:-$RUNTIME_ROOT/sentinel_pulse/protocol/attack-implementation-contract-b1.json}
RUNTIME_SOURCE=${RUNTIME_SOURCE:-$RUNTIME_ROOT/sentinel/benchmarks/runtime_attack_blind_b1.c}
EXEC_PROVENANCE_POLICY=${EXEC_PROVENANCE_POLICY:-$RUNTIME_ROOT/sentinel/k8s/tetragon-sentinel-pulse-exec-provenance.yaml}
RUN_ID=${RUN_ID:-sentinel-pulse-formal-blind-b3-$(date -u +%Y%m%dT%H%M%SZ)}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-/home/dat/sentinel-pulse-evidence/blind-b1/$RUN_ID}

test -f "$NORMAL_EVIDENCE_ROOT/NORMAL_PASS"
test -f "$NORMAL_EVIDENCE_ROOT/NORMAL_REPORT.json"
test ! -e "$NORMAL_EVIDENCE_ROOT/ACTIVE"
test ! -e "$NORMAL_EVIDENCE_ROOT/INFRA_FAILURE.json"
test -f "$ATTACK_CONTRACT"

expected_commit=$(jq -er '.candidate_binding.runtime_source_git_commit' "$ATTACK_CONTRACT")
observed_commit=$(git -C "$RUNTIME_ROOT" rev-parse HEAD)
[[ $observed_commit == "$expected_commit" ]] || {
  echo "B3 runtime worktree differs from the source commit used by the normal soak" >&2
  exit 1
}
[[ -z $(git -C "$RUNTIME_ROOT" status --porcelain) ]] || {
  echo "B3 runtime worktree is not clean" >&2
  exit 1
}

exec env \
  LOCAL_ROOT="$RUNTIME_ROOT" \
  NORMAL_EVIDENCE_ROOT="$NORMAL_EVIDENCE_ROOT" \
  MODEL_SOURCE="$MODEL_SOURCE" \
  POLICY_SOURCE="$POLICY_SOURCE" \
  ATTACK_CONTRACT="$ATTACK_CONTRACT" \
  IMPLEMENTATION_CONTRACT="$IMPLEMENTATION_CONTRACT" \
  RUNTIME_SOURCE="$RUNTIME_SOURCE" \
  EXEC_PROVENANCE_POLICY="$EXEC_PROVENANCE_POLICY" \
  RUN_ID="$RUN_ID" \
  EVIDENCE_ROOT="$EVIDENCE_ROOT" \
  "$RUNTIME_ROOT/sentinel_pulse/start_500ms_blind_matrix.sh"
