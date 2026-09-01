#!/usr/bin/env bash
# Start an isolated, non-promoting Pulse blind campaign after an exact normal pass.
set -euo pipefail

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
REMOTE_ROOT=${REMOTE_ROOT:-/home/dat/eBPF-project-pulse-blind}
NORMAL_EVIDENCE_ROOT=${NORMAL_EVIDENCE_ROOT:?point to the passed formal normal soak}
MODEL_SOURCE=${MODEL_SOURCE:?point to the exact candidate used by the normal soak}
POLICY_SOURCE=${POLICY_SOURCE:-$LOCAL_ROOT/sentinel_pulse/protocol/decision-policy-semantic-v4.json}
ATTACK_CONTRACT=${ATTACK_CONTRACT:-$LOCAL_ROOT/sentinel_pulse/protocol/blind-attack-contract.json}
IMPLEMENTATION_CONTRACT=${IMPLEMENTATION_CONTRACT:-$LOCAL_ROOT/ml-service/aims_blind_attack_contract.json}
RUNTIME_SOURCE=${RUNTIME_SOURCE:-$LOCAL_ROOT/sentinel/benchmarks/runtime_attack_blind.c}
EXEC_PROVENANCE_POLICY=${EXEC_PROVENANCE_POLICY:-$LOCAL_ROOT/sentinel/k8s/tetragon-sentinel-pulse-exec-provenance.yaml}
RUN_ID=${RUN_ID:-pulse500-blind-$(date -u +%Y%m%dT%H%M%SZ)}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-$LOCAL_ROOT/validation-evidence/sentinel-pulse-campaign/$RUN_ID}
DURATION_SECONDS=${DURATION_SECONDS:-43200}
SCHEDULE_SEED=${SCHEDULE_SEED:-20260820}
SSH_USER=${SSH_USER:-dat}
WORKERS=("10.1.16.237|k8s-worker1.local" "10.1.16.239|k8s-worker3.local" "10.1.16.238|k8s-worker4.local")

: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
for command in sshpass rsync kubectl jq gcc sha256sum; do command -v "$command" >/dev/null; done
[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $DURATION_SECONDS =~ ^[0-9]+$ ]] && ((DURATION_SECONDS >= 21600 && DURATION_SECONDS <= 90000))
[[ $SCHEDULE_SEED =~ ^[0-9]+$ ]]
test -f "$NORMAL_EVIDENCE_ROOT/NORMAL_PASS"
test -f "$NORMAL_EVIDENCE_ROOT/NORMAL_REPORT.json"
test -f "$NORMAL_EVIDENCE_ROOT/SOAK_START.json"
test -f "$MODEL_SOURCE/manifest.json"
test -f "$POLICY_SOURCE"
test -f "$ATTACK_CONTRACT"
test -f "$IMPLEMENTATION_CONTRACT"
test -f "$RUNTIME_SOURCE"
test -f "$EXEC_PROVENANCE_POLICY"
test ! -e "$EVIDENCE_ROOT"

normal_sha=$(sha256sum "$NORMAL_EVIDENCE_ROOT/NORMAL_REPORT.json" | awk '{print $1}')
grep -Fx "normal_report_sha256=$normal_sha" "$NORMAL_EVIDENCE_ROOT/NORMAL_PASS" >/dev/null
jq -e '.normal_gate == true and .expected_workload_gate == true' \
  "$NORMAL_EVIDENCE_ROOT/NORMAL_REPORT.json" >/dev/null
model_sha=$(sha256sum "$MODEL_SOURCE/manifest.json" | awk '{print $1}')
policy_sha=$(sha256sum "$POLICY_SOURCE" | awk '{print $1}')
contract_sha=$(sha256sum "$ATTACK_CONTRACT" | awk '{print $1}')
implementation_sha=$(sha256sum "$IMPLEMENTATION_CONTRACT" | awk '{print $1}')
source_sha=$(sha256sum "$RUNTIME_SOURCE" | awk '{print $1}')
exec_provenance_policy_sha=$(sha256sum "$EXEC_PROVENANCE_POLICY" | awk '{print $1}')
runtime_commit=$(git -C "$LOCAL_ROOT" rev-parse HEAD)
[[ $(jq -er '.model_manifest_sha256' "$NORMAL_EVIDENCE_ROOT/SOAK_START.json") == "$model_sha" ]]
[[ $(jq -er '.decision_policy_sha256' "$NORMAL_EVIDENCE_ROOT/SOAK_START.json") == "$policy_sha" ]]
contract_schema=$(jq -er '.schema' "$ATTACK_CONTRACT")
if [[ $contract_schema == sentinel-pulse-blind-attack-contract-v1 ]]; then
  [[ $(jq -er '.blind_attack_contract_sha256' "$MODEL_SOURCE/manifest.json") == "$contract_sha" ]]
elif [[ $contract_schema == sentinel-pulse-blind-attack-contract-v2 ]]; then
  jq -e --arg model "$model_sha" --arg policy "$policy_sha" '
    .frozen_before_candidate_evaluation == true and
    .candidate_parameters_locked_before_contract_authoring == true and
    .candidate_binding.model_manifest_sha256 == $model and
    .candidate_binding.decision_policy_sha256 == $policy
  ' "$ATTACK_CONTRACT" >/dev/null
  contract_runtime_commit=$(jq -er '.candidate_binding.runtime_source_git_commit // empty' "$ATTACK_CONTRACT")
  if [[ -n $contract_runtime_commit && $contract_runtime_commit != "$runtime_commit" ]]; then
    echo "successor blind contract belongs to another runtime commit" >&2
    exit 1
  fi
else
  echo "unsupported blind attack contract schema: $contract_schema" >&2
  exit 1
fi
[[ $(jq -er '.source.sha256' "$IMPLEMENTATION_CONTRACT") == "$source_sha" ]]
expected_injections=$(jq -er '.expected_injections' "$ATTACK_CONTRACT")
[[ $expected_injections =~ ^[0-9]+$ ]] && ((expected_injections > 0))
[[ -z $(git -C "$LOCAL_ROOT" status --porcelain --untracked-files=no) ]]

node_total=$(kubectl get nodes -o json | jq '.items | length')
node_bad=$(kubectl get nodes -o json | PYTHONPATH="$LOCAL_ROOT" python3 \
  -m sentinel_pulse.cluster_health --resource nodes --count)
pod_bad=$(kubectl -n production get pods -o json | PYTHONPATH="$LOCAL_ROOT" python3 \
  -m sentinel_pulse.cluster_health --resource pods --grace-seconds 0 --count)
longhorn_bad=$(kubectl -n longhorn-system get volumes.longhorn.io -o json | \
  jq '[.items[] | select(.status.robustness != "healthy")] | length')
cnpg_bad=$(kubectl -n production get clusters.postgresql.cnpg.io -o json | \
  jq '[.items[] | select((.status.readyInstances // 0) != (.status.instances // .spec.instances // 0) or (.status.phase // "") != "Cluster in healthy state")] | length')
tetragon_ready=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o json | \
  jq '[.items[] | select(.status.phase == "Running" and ([.status.containerStatuses[]?.ready] | all))] | length')
[[ $node_total -eq 6 && $node_bad -eq 0 && $pod_bad -eq 0 && \
   $longhorn_bad -eq 0 && $cnpg_bad -eq 0 && $tetragon_ready -eq 6 ]]

mkdir -p "$EVIDENCE_ROOT"
PROTOCOL_STAGED="$EVIDENCE_ROOT/protocol"
mkdir -p "$PROTOCOL_STAGED"
install -m 0444 "$POLICY_SOURCE" "$PROTOCOL_STAGED/decision-policy.json"
install -m 0444 "$ATTACK_CONTRACT" "$PROTOCOL_STAGED/blind-attack-contract.json"
install -m 0444 "$IMPLEMENTATION_CONTRACT" \
  "$PROTOCOL_STAGED/attack-implementation-contract.json"
install -m 0444 "$RUNTIME_SOURCE" "$PROTOCOL_STAGED/runtime_attack_blind.c"
install -m 0444 "$EXEC_PROVENANCE_POLICY" \
  "$PROTOCOL_STAGED/tetragon-exec-provenance.yaml"
[[ $(sha256sum "$PROTOCOL_STAGED/decision-policy.json" | awk '{print $1}') == "$policy_sha" ]]
[[ $(sha256sum "$PROTOCOL_STAGED/blind-attack-contract.json" | awk '{print $1}') == "$contract_sha" ]]
[[ $(sha256sum "$PROTOCOL_STAGED/attack-implementation-contract.json" | awk '{print $1}') == "$implementation_sha" ]]
[[ $(sha256sum "$PROTOCOL_STAGED/runtime_attack_blind.c" | awk '{print $1}') == "$source_sha" ]]
MODEL_STAGED="$EVIDENCE_ROOT/model"
mkdir -p "$MODEL_STAGED"
rsync -a --checksum "$MODEL_SOURCE/" "$MODEL_STAGED/"
[[ $(sha256sum "$MODEL_STAGED/manifest.json" | awk '{print $1}') == "$model_sha" ]]
(cd "$MODEL_STAGED" && sha256sum -c manifest.sha256)
model_rel=${MODEL_STAGED#"$LOCAL_ROOT/"}
[[ $model_rel != "$MODEL_STAGED" ]]
binary="$EVIDENCE_ROOT/runtime_attack_blind"
gcc -O2 -Wall -Wextra -Werror -static \
  "$PROTOCOL_STAGED/runtime_attack_blind.c" -o "$binary"
binary_sha=$(sha256sum "$binary" | awk '{print $1}')
[[ $binary_sha == $(jq -er '.binary.sha256' "$IMPLEMENTATION_CONTRACT") ]]
chmod 0444 "$binary"

python3 - "$EVIDENCE_ROOT/BLIND_START.json" "$RUN_ID" "$model_sha" \
  "$policy_sha" "$contract_sha" "$implementation_sha" "$source_sha" \
  "$binary_sha" "$normal_sha" "$exec_provenance_policy_sha" "$SCHEDULE_SEED" "$DURATION_SECONDS" \
  "$expected_injections" "$runtime_commit" <<'PY'
from datetime import datetime, timezone
import json, pathlib, sys
(out, run_id, model, policy, contract, implementation, source, binary,
 normal, exec_provenance_policy, schedule_seed, duration, expected, commit) = sys.argv[1:]
payload = {
    "schema": "sentinel-pulse-blind-start-v1",
    "created_at": datetime.now(timezone.utc).isoformat(),
    "run_id": run_id,
    "model_manifest_sha256": model,
    "decision_policy_sha256": policy,
    "blind_attack_contract_sha256": contract,
    "attack_implementation_contract_sha256": implementation,
    "runtime_source_sha256": source,
    "runtime_binary_sha256": binary,
    "normal_report_sha256": normal,
    "exec_provenance_policy_sha256": exec_provenance_policy,
    "schedule_seed": int(schedule_seed),
    "collector_duration_seconds": int(duration),
    "expected_injections": int(expected),
    "blind_evaluation_started": True,
    "attack_outcomes_used_for_training_or_tuning": False,
    "automatic_promotion": False,
    "cluster_preflight": "6 nodes and Tetragon pods ready; zero node pressure, production pod, Longhorn or CNPG failure",
    "source_git_commit": commit,
}
pathlib.Path(out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY

remote() { local host=$1; shift; sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" "$@"; }
remote_sudo() { local host=$1; shift; printf '%s\n' "$SSHPASS" | sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" "sudo -S -p '' $*"; }

started=()
complete=false
cleanup() {
  local rc=$?
  if [[ $complete != true ]]; then
    for host in "${started[@]}"; do
      remote_sudo "$host" systemctl stop sentinel-pulse-detector-candidate.service sentinel-pulse-collector-500ms-experiment.service >/dev/null 2>&1 || true
    done
    printf 'failed_at=%s\nexit_code=%s\n' "$(date -u +%FT%TZ)" "$rc" >"$EVIDENCE_ROOT/START_FAILED"
  fi
}
trap cleanup EXIT

for target in "${WORKERS[@]}"; do
  IFS='|' read -r host node <<<"$target"
  [[ $(remote "$host" hostname -f) == "$node" ]]
  remote "$host" "systemctl is-active --quiet sentinel-pulse-resolver sentinel-pulse-collector && ! systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment && ! systemctl is-active --quiet sentinel-pulse-detector-candidate"
  remote "$host" "mkdir -p '$REMOTE_ROOT/sentinel_pulse' '$REMOTE_ROOT/$(dirname "$model_rel")'"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" "$LOCAL_ROOT/sentinel_pulse/" "$SSH_USER@$host:$REMOTE_ROOT/sentinel_pulse/"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" "$MODEL_STAGED/" "$SSH_USER@$host:$REMOTE_ROOT/$model_rel/"
  started+=("$host")
  remote_sudo "$host" env SOURCE_ROOT="$REMOTE_ROOT" RUN_ID="$RUN_ID" DURATION_SECONDS="$DURATION_SECONDS" "$REMOTE_ROOT/sentinel_pulse/install_500ms_experiment.sh"
  feature="/var/lib/sentinel-pulse-500ms/runs/$RUN_ID/features.jsonl"
  remote_sudo "$host" env SOURCE_ROOT="$REMOTE_ROOT" MODEL_SOURCE="$REMOTE_ROOT/$model_rel" FEATURE_SOURCE="$feature" DEPLOYMENT_ID="$RUN_ID" ENABLE_INJECTION_TRACKING=true "$REMOTE_ROOT/sentinel_pulse/install_detector_candidate.sh"
  env_snapshot=$(remote_sudo "$host" cat /etc/sentinel-pulse-detector-candidate.env)
  injection_path=$(sed -n 's/^PULSE_INJECTIONS=//p' <<<"$env_snapshot")
  [[ $injection_path == /var/lib/sentinel-pulse-detector/runs/*/injections.jsonl ]]
  printf '%s %s %s %s\n' "$host" "$node" "$feature" "$injection_path" >>"$EVIDENCE_ROOT/workers.txt"
done

(
  cd "$EVIDENCE_ROOT"
  sha256sum BLIND_START.json runtime_attack_blind model/manifest.json \
    protocol/decision-policy.json protocol/blind-attack-contract.json \
    protocol/attack-implementation-contract.json \
    protocol/runtime_attack_blind.c protocol/tetragon-exec-provenance.yaml
) >"$EVIDENCE_ROOT/START_SHA256SUMS"
(cd "$EVIDENCE_ROOT" && sha256sum -c START_SHA256SUMS)
touch "$EVIDENCE_ROOT/ACTIVE"
complete=true
printf 'Pulse blind services active: run=%s evidence=%s\n' "$RUN_ID" "$EVIDENCE_ROOT"
