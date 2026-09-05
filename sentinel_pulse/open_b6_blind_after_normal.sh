#!/usr/bin/env bash
# Open B6 blind evaluation only after the exact independently validated normal run passes.
set -Eeuo pipefail

CONTROL_ROOT=${CONTROL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
RUNTIME_ROOT=${RUNTIME_ROOT:-/home/dat/eBPF-project-runtime-pulse-b6}
NORMAL_EVIDENCE_ROOT=${NORMAL_EVIDENCE_ROOT:?point to terminal B6 normal evidence}
MODEL_SOURCE=${MODEL_SOURCE:-$RUNTIME_ROOT/.runtime-artifacts/sentinel-pulse-a2-b6-model}
POLICY_SOURCE=${POLICY_SOURCE:-$RUNTIME_ROOT/sentinel_pulse/protocol/decision-policy-temporal-b6.json}
ATTACK_CONTRACT=${ATTACK_CONTRACT:-$CONTROL_ROOT/sentinel_pulse/protocol/blind-attack-contract-b6.json}
IMPLEMENTATION_CONTRACT=${IMPLEMENTATION_CONTRACT:-$RUNTIME_ROOT/sentinel_pulse/protocol/attack-implementation-contract-b1.json}
RUNTIME_SOURCE=${RUNTIME_SOURCE:-$RUNTIME_ROOT/sentinel/benchmarks/runtime_attack_blind_b1.c}
EXEC_PROVENANCE_POLICY=${EXEC_PROVENANCE_POLICY:-$RUNTIME_ROOT/sentinel/k8s/tetragon-sentinel-pulse-exec-provenance.yaml}
RUN_ID=${RUN_ID:-sentinel-pulse-formal-blind-b6-$(date -u +%Y%m%dT%H%M%SZ)}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-/home/dat/sentinel-pulse-evidence/blind-b6/$RUN_ID}

test -f "$NORMAL_EVIDENCE_ROOT/NORMAL_PASS"
test -f "$NORMAL_EVIDENCE_ROOT/NORMAL_REPORT.json"
test ! -e "$NORMAL_EVIDENCE_ROOT/ACTIVE"
test ! -e "$NORMAL_EVIDENCE_ROOT/FAILED"
test ! -e "$NORMAL_EVIDENCE_ROOT/INFRA_FAILURE.json"
test -f "$ATTACK_CONTRACT"

expected_commit=$(jq -er '.candidate_binding.runtime_source_git_commit' "$ATTACK_CONTRACT")
expected_model=$(jq -er '.candidate_binding.model_manifest_sha256' "$ATTACK_CONTRACT")
expected_policy=$(jq -er '.candidate_binding.decision_policy_sha256' "$ATTACK_CONTRACT")
observed_commit=$(git -C "$RUNTIME_ROOT" rev-parse HEAD)
observed_model=$(sha256sum "$MODEL_SOURCE/manifest.json" | awk '{print $1}')
observed_policy=$(sha256sum "$POLICY_SOURCE" | awk '{print $1}')
[[ $observed_commit == "$expected_commit" ]]
[[ $observed_model == "$expected_model" ]]
[[ $observed_policy == "$expected_policy" ]]
[[ $(jq -er '.model_manifest_sha256' "$NORMAL_EVIDENCE_ROOT/SOAK_START.json") == "$expected_model" ]]
[[ $(jq -er '.decision_policy_sha256' "$NORMAL_EVIDENCE_ROOT/SOAK_START.json") == "$expected_policy" ]]
[[ -z $(git -C "$RUNTIME_ROOT" status --porcelain --untracked-files=no) ]]
unexpected_untracked=$(git -C "$RUNTIME_ROOT" ls-files --others --exclude-standard | \
  awk '$0 !~ /^\.runtime-artifacts\//')
[[ -z $unexpected_untracked ]]

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
