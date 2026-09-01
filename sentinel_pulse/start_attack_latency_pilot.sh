#!/usr/bin/env bash
# Stage an explicitly non-formal attack-latency pilot. Never promotes a model.
set -Eeuo pipefail

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
MODEL_SOURCE=${MODEL_SOURCE:?point to the frozen pilot model bundle}
POLICY_SOURCE=${POLICY_SOURCE:?point to the frozen pilot decision policy}
NORMAL_CANARY_AGGREGATE=${NORMAL_CANARY_AGGREGATE:?point to AGGREGATE.v2.json}
ATTACK_CONTRACT=${ATTACK_CONTRACT:-$LOCAL_ROOT/sentinel_pulse/protocol/blind-attack-contract.json}
IMPLEMENTATION_CONTRACT=${IMPLEMENTATION_CONTRACT:-$LOCAL_ROOT/ml-service/aims_blind_attack_contract.json}
RUNTIME_SOURCE=${RUNTIME_SOURCE:-$LOCAL_ROOT/sentinel/benchmarks/runtime_attack_blind.c}
EXEC_PROVENANCE_POLICY=${EXEC_PROVENANCE_POLICY:-$LOCAL_ROOT/sentinel/k8s/tetragon-sentinel-pulse-exec-provenance.yaml}
RUN_ID=${RUN_ID:-pulse500-attack-latency-pilot-$(date -u +%Y%m%dT%H%M%SZ)}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-/home/dat/sentinel-pulse-evidence/pilot-a2/$RUN_ID}
REMOTE_ROOT=${REMOTE_ROOT:-/home/dat/sentinel-pulse-attack-pilot-$RUN_ID}
DURATION_SECONDS=${DURATION_SECONDS:-2700}
SCHEDULE_SEED=${SCHEDULE_SEED:-20260831}
PILOT_CONTROLLERS=${PILOT_CONTROLLERS:-api-gateway,aims-postgres-cnpg,aims-kafka-dual-role}
PILOT_TRIAL_SEED=${PILOT_TRIAL_SEED:-13001}
PILOT_RATE_PER_SECOND=${PILOT_RATE_PER_SECOND:-12}
PREVIOUS_PILOT_EVIDENCE=${PREVIOUS_PILOT_EVIDENCE:-}
SSH_USER=${SSH_USER:-dat}
PYTHON=${PYTHON:-/home/dat/ml-venv/bin/python}
WORKERS=("10.1.16.237|k8s-worker1.local" "10.1.16.239|k8s-worker3.local" "10.1.16.238|k8s-worker4.local")

: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
for command in sshpass rsync kubectl jq gcc sha256sum; do command -v "$command" >/dev/null; done
[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $DURATION_SECONDS =~ ^[0-9]+$ ]] && ((DURATION_SECONDS >= 1200 && DURATION_SECONDS <= 90000))
[[ $SCHEDULE_SEED =~ ^[0-9]+$ ]]
[[ $PILOT_TRIAL_SEED =~ ^[0-9]+$ ]]
[[ $PILOT_RATE_PER_SECOND =~ ^[0-9]+$ ]]
test ! -e "$EVIDENCE_ROOT"
test -f "$MODEL_SOURCE/manifest.json"
test -f "$MODEL_SOURCE/manifest.sha256"
test -f "$POLICY_SOURCE"
test -f "$NORMAL_CANARY_AGGREGATE"
test -f "$ATTACK_CONTRACT"
test -f "$IMPLEMENTATION_CONTRACT"
test -f "$RUNTIME_SOURCE"
test -f "$EXEC_PROVENANCE_POLICY"
previous_report=""
previous_plan=""
previous_failure_index_sha=""
previous_report_sha=""
previous_plan_sha=""
if [[ -n $PREVIOUS_PILOT_EVIDENCE ]]; then
  test -f "$PREVIOUS_PILOT_EVIDENCE/FAILURE_TERMINAL.json"
  test -f "$PREVIOUS_PILOT_EVIDENCE/FAILURE_SHA256SUMS"
  test -f "$PREVIOUS_PILOT_EVIDENCE/PILOT_PLAN.json"
  test -f "$PREVIOUS_PILOT_EVIDENCE/INFRA_FAILURE.json"
  test ! -e "$PREVIOUS_PILOT_EVIDENCE/ACTIVE"
  (cd "$PREVIOUS_PILOT_EVIDENCE" && sha256sum -c FAILURE_SHA256SUMS)
  previous_plan="$PREVIOUS_PILOT_EVIDENCE/PILOT_PLAN.json"
  if [[ -f $PREVIOUS_PILOT_EVIDENCE/REPORT.partial.json ]]; then
    previous_report="$PREVIOUS_PILOT_EVIDENCE/REPORT.partial.json"
    previous_report_sha=$(sha256sum "$previous_report" | awk '{print $1}')
  fi
  previous_failure_index_sha=$(sha256sum "$PREVIOUS_PILOT_EVIDENCE/FAILURE_SHA256SUMS" | awk '{print $1}')
  previous_plan_sha=$(sha256sum "$previous_plan" | awk '{print $1}')
fi

model_sha=$(sha256sum "$MODEL_SOURCE/manifest.json" | awk '{print $1}')
policy_sha=$(sha256sum "$POLICY_SOURCE" | awk '{print $1}')
contract_sha=$(sha256sum "$ATTACK_CONTRACT" | awk '{print $1}')
implementation_sha=$(sha256sum "$IMPLEMENTATION_CONTRACT" | awk '{print $1}')
source_sha=$(sha256sum "$RUNTIME_SOURCE" | awk '{print $1}')
exec_provenance_policy_sha=$(sha256sum "$EXEC_PROVENANCE_POLICY" | awk '{print $1}')
canary_sha=$(sha256sum "$NORMAL_CANARY_AGGREGATE" | awk '{print $1}')
runtime_commit=$(git -C "$LOCAL_ROOT" rev-parse HEAD)

jq -e --arg model "$model_sha" --arg policy "$policy_sha" '
  .schema == "sentinel-pulse-live-normal-canary-aggregate-v2" and
  .valid == true and .accuracy_claim_allowed == false and .alerts == 0 and
  .model_manifest_sha256 == $model and .decision_policy_sha256 == $policy
' "$NORMAL_CANARY_AGGREGATE" >/dev/null
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

SSHPASS="$SSHPASS" PYTHONPATH="$LOCAL_ROOT" "$PYTHON" - <<'PY'
import os
from sentinel_pulse.run_500ms_blind_matrix import Runtime, cluster_gate
cluster_gate(Runtime(os.environ["SSHPASS"]))
PY

mkdir -p "$EVIDENCE_ROOT/staged" "$EVIDENCE_ROOT/model" "$EVIDENCE_ROOT/protocol"
rsync -a --exclude='__pycache__' --exclude='*.pyc' \
  "$LOCAL_ROOT/sentinel_pulse/" "$EVIDENCE_ROOT/staged/sentinel_pulse/"
rsync -a --checksum "$MODEL_SOURCE/" "$EVIDENCE_ROOT/model/"
install -m 0444 "$POLICY_SOURCE" "$EVIDENCE_ROOT/protocol/decision-policy.json"
install -m 0444 "$ATTACK_CONTRACT" "$EVIDENCE_ROOT/protocol/blind-attack-contract.json"
install -m 0444 "$IMPLEMENTATION_CONTRACT" "$EVIDENCE_ROOT/protocol/attack-implementation-contract.json"
install -m 0444 "$RUNTIME_SOURCE" "$EVIDENCE_ROOT/protocol/runtime_attack_blind.c"
install -m 0444 "$EXEC_PROVENANCE_POLICY" \
  "$EVIDENCE_ROOT/protocol/tetragon-exec-provenance.yaml"
(cd "$EVIDENCE_ROOT/model" && sha256sum -c manifest.sha256)

(
  cd "$EVIDENCE_ROOT"
  find staged/sentinel_pulse -type f -print0 | sort -z | xargs -0 sha256sum
) >"$EVIDENCE_ROOT/RUNTIME_SOURCE_SHA256SUMS"
chmod -R a-w "$EVIDENCE_ROOT/staged" "$EVIDENCE_ROOT/model" "$EVIDENCE_ROOT/protocol"

gcc -O2 -Wall -Wextra -Werror -static \
  "$EVIDENCE_ROOT/protocol/runtime_attack_blind.c" \
  -o "$EVIDENCE_ROOT/runtime_attack_blind"
binary_sha=$(sha256sum "$EVIDENCE_ROOT/runtime_attack_blind" | awk '{print $1}')
[[ $binary_sha == $(jq -er '.binary.sha256' "$IMPLEMENTATION_CONTRACT") ]]
chmod 0444 "$EVIDENCE_ROOT/runtime_attack_blind"

PYTHONPATH="$LOCAL_ROOT" "$PYTHON" - \
  "$ATTACK_CONTRACT" "$MODEL_SOURCE/manifest.json" \
  "$EVIDENCE_ROOT/PILOT_PLAN.json" "$PILOT_CONTROLLERS" \
  "$PILOT_TRIAL_SEED" "$PILOT_RATE_PER_SECOND" "$SCHEDULE_SEED" \
  "$previous_plan" "$previous_report" <<'PY'
import json, pathlib, random, sys
from sentinel_pulse.blind_contract import load_contract
from sentinel_pulse.run_500ms_blind_matrix import controller_model_workload

(contract_path, manifest_path, output, controllers_raw, seed, rate,
 schedule_seed, previous_plan, previous_report) = sys.argv[1:]
contract = load_contract(pathlib.Path(contract_path))
manifest = json.loads(pathlib.Path(manifest_path).read_text())
controllers = [item.strip() for item in controllers_raw.split(",") if item.strip()]
if len(controllers) != len(set(controllers)) or not controllers:
    raise SystemExit("pilot controllers must be non-empty and unique")
allowed_controllers = set(contract["matrix"]["workload_controllers"])
if not set(controllers) <= allowed_controllers:
    raise SystemExit("pilot controller is outside frozen attack contract")
trial = {"seed": int(seed), "rate_per_second": int(rate)}
if trial not in contract["matrix"]["trials"]:
    raise SystemExit("pilot trial is outside frozen attack contract")
for controller in controllers:
    controller_model_workload(manifest, controller)
schedule = [
    {"workload_controller": controller, "scenario": scenario, **trial}
    for controller in controllers
    for scenario in contract["matrix"]["scenarios"]
]
random.Random(int(schedule_seed)).shuffle(schedule)
completed = []
if previous_plan:
    prior_plan = json.loads(pathlib.Path(previous_plan).read_text())
    if prior_plan.get("schema") != "sentinel-pulse-attack-latency-pilot-plan-v1":
        raise SystemExit("previous pilot plan schema is invalid")
    completed.extend(prior_plan.get("previous_completed_trials_excluded_without_rerun", []))
if previous_report:
    previous = json.loads(pathlib.Path(previous_report).read_text())
    completed.extend(previous.get("trials", []))
if completed:
    unique_completed = {}
    for item in completed:
        key = (
            str(item["workload_controller"]), str(item["scenario"]),
            int(item["seed"]), int(item["rate_per_second"]),
        )
        unique_completed[key] = item
    completed = list(unique_completed.values())
    completed_keys = {
        (str(item["workload_controller"]), str(item["scenario"]),
         int(item["seed"]), int(item["rate_per_second"]))
        for item in completed
    }
    full_keys = {
        (item["workload_controller"], item["scenario"],
         item["seed"], item["rate_per_second"])
        for item in schedule
    }
    if not completed_keys <= full_keys:
        raise SystemExit("previous completed trial is outside this frozen pilot plan")
    schedule = [
        item for item in schedule
        if (item["workload_controller"], item["scenario"],
            item["seed"], item["rate_per_second"]) not in completed_keys
    ]
document = {
    "schema": "sentinel-pulse-attack-latency-pilot-plan-v1",
    "evidence_class": "nonformal_attack_latency_pilot",
    "selection_time": "before_any_attack_in_this_run",
    "selection_basis": "one stateless, one database and one streaming workload; all five frozen scenarios; one frozen mid-rate trial",
    "accuracy_claim_allowed": False,
    "automatic_promotion": False,
    "schedule_seed": int(schedule_seed),
    "previous_completed_trials_excluded_without_rerun": [
        {
            "workload_controller": item["workload_controller"],
            "scenario": item["scenario"],
            "seed": int(item["seed"]),
            "rate_per_second": int(item["rate_per_second"]),
            "detected": bool(item.get("detected")),
            "injection_id": item.get("injection_id"),
        }
        for item in completed
    ],
    "schedule": schedule,
}
pathlib.Path(output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
PY
pilot_plan_sha=$(sha256sum "$EVIDENCE_ROOT/PILOT_PLAN.json" | awk '{print $1}')
expected=$(jq '.schedule | length' "$EVIDENCE_ROOT/PILOT_PLAN.json")
((expected >= 1 && expected <= 15))
if [[ -z $PREVIOUS_PILOT_EVIDENCE ]]; then [[ $expected -eq 15 ]]; fi
chmod 0444 "$EVIDENCE_ROOT/PILOT_PLAN.json"

runtime_index_sha=$(sha256sum "$EVIDENCE_ROOT/RUNTIME_SOURCE_SHA256SUMS" | awk '{print $1}')
"$PYTHON" - "$EVIDENCE_ROOT/BLIND_START.json" "$RUN_ID" "$model_sha" \
  "$policy_sha" "$contract_sha" "$implementation_sha" "$source_sha" \
  "$binary_sha" "$canary_sha" "$pilot_plan_sha" "$runtime_index_sha" \
  "$exec_provenance_policy_sha" \
  "$SCHEDULE_SEED" "$DURATION_SECONDS" "$expected" \
  "$runtime_commit" "$REMOTE_ROOT" \
  "$previous_failure_index_sha" "$previous_plan_sha" \
  "$previous_report_sha" <<'PY'
from datetime import datetime, timezone
import json, pathlib, sys
(output, run_id, model, policy, contract, implementation, source, binary,
 canary, pilot_plan, runtime_index, exec_provenance_policy, schedule_seed, duration, expected, commit,
 remote_root, previous_failure_index, previous_plan, previous_report) = sys.argv[1:]
payload = {
    "schema": "sentinel-pulse-attack-latency-pilot-start-v1",
    "created_at": datetime.now(timezone.utc).isoformat(),
    "run_id": run_id,
    "evidence_class": "nonformal_attack_latency_pilot",
    "accuracy_claim_allowed": False,
    "formal_blind_evidence": False,
    "attack_outcomes_used_for_training_or_tuning": False,
    "automatic_promotion": False,
    "model_manifest_sha256": model,
    "decision_policy_sha256": policy,
    "blind_attack_contract_sha256": contract,
    "attack_implementation_contract_sha256": implementation,
    "runtime_source_sha256": source,
    "runtime_binary_sha256": binary,
    "normal_canary_aggregate_sha256": canary,
    "pilot_plan_sha256": pilot_plan,
    "runtime_source_index_sha256": runtime_index,
    "exec_provenance_policy_sha256": exec_provenance_policy,
    "schedule_seed": int(schedule_seed),
    "collector_duration_seconds": int(duration),
    "expected_injections": int(expected),
    "source_git_commit": commit,
    "remote_source_root": remote_root,
    "continuation_of_failure_index_sha256": previous_failure_index or None,
    "previous_pilot_plan_sha256": previous_plan or None,
    "previous_partial_report_sha256": previous_report or None,
}
pathlib.Path(output).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
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
  remote "$host" "mkdir -p '$REMOTE_ROOT/sentinel_pulse' '$REMOTE_ROOT/model'"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$EVIDENCE_ROOT/staged/sentinel_pulse/" "$SSH_USER@$host:$REMOTE_ROOT/sentinel_pulse/"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$EVIDENCE_ROOT/model/" "$SSH_USER@$host:$REMOTE_ROOT/model/"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$EVIDENCE_ROOT/protocol/decision-policy.json" "$SSH_USER@$host:$REMOTE_ROOT/decision-policy.json"
  started+=("$host")
  remote_sudo "$host" env SOURCE_ROOT="$REMOTE_ROOT" RUN_ID="$RUN_ID" DURATION_SECONDS="$DURATION_SECONDS" "$REMOTE_ROOT/sentinel_pulse/install_500ms_experiment.sh"
  feature="/var/lib/sentinel-pulse-500ms/runs/$RUN_ID/features.jsonl"
  remote_sudo "$host" env SOURCE_ROOT="$REMOTE_ROOT" MODEL_SOURCE="$REMOTE_ROOT/model" DECISION_POLICY_SOURCE="$REMOTE_ROOT/decision-policy.json" FEATURE_SOURCE="$feature" DEPLOYMENT_ID="$RUN_ID" ENABLE_INJECTION_TRACKING=true "$REMOTE_ROOT/sentinel_pulse/install_detector_candidate.sh"
  env_snapshot=$(remote_sudo "$host" cat /etc/sentinel-pulse-detector-candidate.env)
  injection_path=$(sed -n 's/^PULSE_INJECTIONS=//p' <<<"$env_snapshot")
  [[ $injection_path == /var/lib/sentinel-pulse-detector/runs/*/injections.jsonl ]]
  printf '%s %s %s %s\n' "$host" "$node" "$feature" "$injection_path" >>"$EVIDENCE_ROOT/workers.txt"
done

(
  cd "$EVIDENCE_ROOT"
  sha256sum BLIND_START.json PILOT_PLAN.json runtime_attack_blind \
    model/manifest.json protocol/decision-policy.json \
    protocol/blind-attack-contract.json protocol/attack-implementation-contract.json \
    protocol/runtime_attack_blind.c RUNTIME_SOURCE_SHA256SUMS workers.txt
  sha256sum protocol/tetragon-exec-provenance.yaml
) >"$EVIDENCE_ROOT/START_SHA256SUMS"
(cd "$EVIDENCE_ROOT" && sha256sum -c START_SHA256SUMS)
touch "$EVIDENCE_ROOT/ACTIVE"
chmod 0444 "$EVIDENCE_ROOT/BLIND_START.json" "$EVIDENCE_ROOT/workers.txt" \
  "$EVIDENCE_ROOT/START_SHA256SUMS" "$EVIDENCE_ROOT/RUNTIME_SOURCE_SHA256SUMS"
complete=true
printf 'Attack-latency pilot active: run=%s trials=%s evidence=%s\n' "$RUN_ID" "$expected" "$EVIDENCE_ROOT"
