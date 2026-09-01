#!/usr/bin/env bash
# Capture a bounded, normal-only 500 ms dataset on all three workers.
set -Eeuo pipefail

ROOT=${ROOT:-/home/dat/eBPF-project}
PYTHON=${PYTHON:-/home/dat/ml-venv/bin/python}
SSH_USER=${SSH_USER:-dat}
OUTPUT_PARENT=${PULSE_500MS_DATA_OUTPUT_PARENT:-$ROOT/validation-evidence/sentinel-pulse-campaign}
REGIME_SECONDS=${PULSE_500MS_REGIME_SECONDS:-600}
TRANSITION_GAP_SECONDS=${PULSE_500MS_TRANSITION_GAP_SECONDS:-180}
PREPARE_SECONDS=${PULSE_500MS_PREPARE_SECONDS:-180}
FINAL_GRACE_SECONDS=${PULSE_500MS_FINAL_GRACE_SECONDS:-15}
CAMPAIGN_MODE=${PULSE_500MS_CAMPAIGN_MODE:-formal}
: "${SSHPASS:?export SSHPASS for SSH and remote sudo authentication}"

case "$CAMPAIGN_MODE" in
  formal) ;;
  pilot)
    [[ ${PULSE_500MS_PILOT_ACK:-} == nonformal ]] || {
      echo "pilot mode requires PULSE_500MS_PILOT_ACK=nonformal" >&2
      exit 2
    }
    ;;
  *) echo "PULSE_500MS_CAMPAIGN_MODE must be formal or pilot" >&2; exit 2 ;;
esac

test -d "$ROOT/sentinel_pulse"
cd "$ROOT"

worker_hosts=(10.1.16.237 10.1.16.239 10.1.16.238)
worker_nodes=(k8s-worker1.local k8s-worker3.local k8s-worker4.local)
regimes=(steady toolmix burst recovery)

[[ $REGIME_SECONDS =~ ^[0-9]+$ ]] && ((REGIME_SECONDS >= 300))
[[ $TRANSITION_GAP_SECONDS =~ ^[0-9]+$ ]] && ((TRANSITION_GAP_SECONDS >= 30))
[[ $PREPARE_SECONDS =~ ^[0-9]+$ ]] && ((PREPARE_SECONDS >= 150))
experiment_duration=$((
  PREPARE_SECONDS + ${#regimes[@]} * REGIME_SECONDS +
  (${#regimes[@]} - 1) * TRANSITION_GAP_SECONDS + FINAL_GRACE_SECONDS + 60
))
((experiment_duration <= 3600))

campaign_prefix=pulse500-data
[[ $CAMPAIGN_MODE == pilot ]] && campaign_prefix=pulse500-data-pilot
campaign_id="$campaign_prefix-$(date -u +%Y%m%dT%H%M%SZ)"
output_root="$OUTPUT_PARENT/$campaign_id"
contract="$output_root/capture-contract.json"
protocol="$output_root/PROTOCOL.json"
failure_marker="$output_root/FAILED.txt"
campaign_complete=false
current_stage=initializing
collectors_started=false
health_failures=0
HEALTH_FAILURE_LIMIT=${PULSE_500MS_HEALTH_FAILURE_LIMIT:-3}
mkdir -p "$output_root/nodes" "$output_root/dataset"

remote() {
  local host=$1
  shift
  sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 \
    "$SSH_USER@$host" "$@"
}

remote_sudo() {
  local host=$1 command=$2
  printf '%s\n' "$SSHPASS" | sshpass -e ssh \
    -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" \
    "sudo -S -p '' bash -lc $(printf '%q' "$command")"
}

restore() {
  local rc=$?
  "$ROOT/ml-service/set_aims_traffic_regime.sh" steady >/dev/null 2>&1 || true
  for host in "${worker_hosts[@]}"; do
    if remote "$host" \
      "systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service"; then
      remote_sudo "$host" \
        "systemctl stop sentinel-pulse-collector-500ms-experiment.service" || true
    fi
  done
  if [[ $campaign_complete != true ]]; then
    printf 'failed_at=%s\nexit_code=%s\nstage=%s\n' \
      "$(date -u +%FT%TZ)" "$rc" "$current_stage" \
      >"$failure_marker"
  fi
  return "$rc"
}
trap restore EXIT INT TERM

check_cluster_health() {
  local ready bad timestamp host status ssh_rc healthy=true
  local -a statuses=()
  ready=$(kubectl get nodes --no-headers | \
    awk '$2 == "Ready" {count++} END {print count+0}')
  bad=$(kubectl get pods -A -o json | \
    "$PYTHON" -m sentinel_pulse.cluster_health --grace-seconds 300 --count)
  [[ $ready -eq 6 && $bad -eq 0 ]] || healthy=false
  for host in "${worker_hosts[@]}"; do
    set +e
    status=$(remote "$host" \
      "for unit in sentinel-pulse-resolver.service sentinel-pulse-collector.service sentinel-pulse-detector-candidate.service sentinel-pulse-collector-500ms-experiment.service; do printf '%s=' \"\$unit\"; systemctl is-active \"\$unit\" || true; done" 2>&1)
    ssh_rc=$?
    set -e
    statuses+=("host=$host ssh_rc=$ssh_rc $status")
    [[ $ssh_rc -eq 0 ]] || healthy=false
    [[ $status == *"sentinel-pulse-resolver.service=active"* ]] || healthy=false
    [[ $status == *"sentinel-pulse-collector.service=active"* ]] || healthy=false
    [[ $status == *"sentinel-pulse-detector-candidate.service=inactive"* ]] || healthy=false
    if [[ $collectors_started == true ]]; then
      [[ $status == *"sentinel-pulse-collector-500ms-experiment.service=active"* ]] \
        || healthy=false
    fi
  done
  if [[ $healthy == true ]]; then
    health_failures=0
    return 0
  fi
  health_failures=$((health_failures + 1))
  timestamp=$(date -u +%Y%m%dT%H%M%SZ)
  {
    printf 'ready_nodes=%s expected=6 non_running_pods=%s consecutive=%s limit=%s stage=%s\n' \
      "$ready" "$bad" "$health_failures" "$HEALTH_FAILURE_LIMIT" "$current_stage"
    printf '%s\n' "${statuses[@]}"
    kubectl get nodes -o wide
    kubectl get pods -A -o json | \
      "$PYTHON" -m sentinel_pulse.cluster_health --grace-seconds 300
  } >"$output_root/health-warning-$timestamp.txt"
  ((health_failures < HEALTH_FAILURE_LIMIT))
}

wait_until() {
  local target=$1 now remaining
  while :; do
    now=$(date +%s)
    remaining=$((target - now))
    ((remaining <= 0)) && return 0
    if ((remaining > 30)); then
      sleep 30
      check_cluster_health
    else
      sleep "$remaining"
    fi
  done
}

if [[ $CAMPAIGN_MODE == formal ]]; then
  [[ -z $(git -C "$ROOT" status --short) ]]
  [[ $(git -C "$ROOT" rev-parse HEAD) == \
     $(git -C "$ROOT" rev-parse origin/main) ]]
fi
check_cluster_health
current_stage=registering-contract
kubectl get nodes -o wide >"$output_root/nodes-start.txt"
kubectl -n production get pods -o wide >"$output_root/production-pods-start.txt"
kubectl -n production get deploy aims-sentinel-loadgen \
  aims-sentinel-ingress-loadgen aims-sentinel-readmix-loadgen \
  aims-sentinel-dependency-loadgen -o yaml \
  >"$output_root/traffic-generators-start.yaml"

campaign_start=$(( $(date +%s) + PREPARE_SECONDS ))
"$PYTHON" -m sentinel_pulse.prepare_contract \
  --output "$contract" --campaign-id "$campaign_id" --start "$campaign_start" \
  --duration-seconds "$REGIME_SECONDS" \
  --transition-gap-seconds "$TRANSITION_GAP_SECONDS" \
  --node "${worker_nodes[0]}" --node "${worker_nodes[1]}" \
  --node "${worker_nodes[2]}" >/dev/null
campaign_end=$("$PYTHON" - "$contract" <<'PY'
import json, sys
contract = json.load(open(sys.argv[1], encoding="utf-8"))
print(int(max(item["end"] for item in contract["intervals"])))
PY
)

"$PYTHON" - "$protocol" "$campaign_id" "$contract" \
  "$experiment_duration" "${worker_hosts[*]}" "${worker_nodes[*]}" \
  "$ROOT" "$CAMPAIGN_MODE" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
output, campaign, contract = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
root, campaign_mode = Path(sys.argv[7]), sys.argv[8]
sources = [
    root / "sentinel_pulse/run_500ms_dataset_campaign.sh",
    root / "sentinel_pulse/install_500ms_experiment.sh",
    root / "sentinel_pulse/finalize_500ms_experiment.sh",
    root / "sentinel_pulse/finalize_500ms_dataset.py",
    root / "sentinel_pulse/assemble_dataset.py",
    root / "sentinel_pulse/train.py",
    root / "sentinel_pulse/capture.py",
    root / "sentinel_pulse/features.py",
    root / "sentinel_pulse/ebpf/pulse_counter.bpf.c",
    root / "sentinel_pulse/ebpf/pulse_counter_loader.c",
    root / "sentinel_pulse/systemd/sentinel-pulse-collector-500ms-experiment.service",
    root / "ml-service/set_aims_traffic_regime.sh",
]
git_status = subprocess.check_output(
    ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
    text=True,
).splitlines()
head = subprocess.check_output(
    ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
).strip()
origin_main = subprocess.check_output(
    ["git", "-C", str(root), "rev-parse", "origin/main"], text=True
).strip()
git_diff = subprocess.check_output(
    ["git", "-C", str(root), "diff", "--binary", "HEAD"],
)
try:
    contract_reference = str(contract.relative_to(root))
except ValueError:
    contract_reference = str(contract)
payload = {
    "schema": "sentinel-pulse-500ms-dataset-protocol-v1",
    "campaign_id": campaign,
    "registered_at": subprocess.check_output(
        ["date", "-u", "+%FT%TZ"], text=True
    ).strip(),
    "campaign_mode": campaign_mode,
    "evidence_class": (
        "formal_candidate_training_dataset"
        if campaign_mode == "formal"
        else "nonformal_runtime_compatibility_pilot"
    ),
    "git_commit": head,
    "origin_main_commit": origin_main,
    "source_clean": not git_status,
    "head_matches_origin_main": head == origin_main,
    "git_status": git_status,
    "git_diff_sha256": hashlib.sha256(git_diff).hexdigest(),
    "normal_only": True,
    "collector_profile": {
        "interval_ms": 500, "rolling_windows": 10,
        "detector_active": False, "one_second_control_collector": True,
        "registered_duration_seconds": int(sys.argv[4]),
    },
    "workers": [
        {"host": host, "node": node}
        for host, node in zip(sys.argv[5].split(), sys.argv[6].split())
    ],
    "contract": contract_reference,
    "contract_sha256": hashlib.sha256(contract.read_bytes()).hexdigest(),
    "source_sha256": {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sources
    },
    "automatic_model_training": False,
    "automatic_promotion": False,
}
output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
chmod 0444 "$contract" "$protocol"

# Keep worker-side lifecycle scripts byte-identical to the protocol-bound source.
for host in "${worker_hosts[@]}"; do
  current_stage="syncing-worker-$host"
  (
    cd "$ROOT"
    sshpass -e rsync -aR --checksum \
      -e 'ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8' \
      sentinel_pulse/install_500ms_experiment.sh \
      sentinel_pulse/finalize_500ms_experiment.sh \
      sentinel_pulse/record_500ms_metrics.sh \
      sentinel_pulse/systemd/sentinel-pulse-collector-500ms-experiment.service \
      "$SSH_USER@$host:$ROOT/"
  )
done

for index in "${!worker_hosts[@]}"; do
  host=${worker_hosts[$index]}
  node=${worker_nodes[$index]}
  run_id="$campaign_id-$node"
  current_stage="starting-collector-$node"
  remote_sudo "$host" \
    "env SOURCE_ROOT=$ROOT DURATION_SECONDS=$experiment_duration RUN_ID=$run_id $ROOT/sentinel_pulse/install_500ms_experiment.sh"
done
for host in "${worker_hosts[@]}"; do
  remote "$host" \
    "systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service"
done
collectors_started=true

for regime in "${regimes[@]}"; do
  regime_start=$("$PYTHON" - "$contract" "$regime" <<'PY'
import json, sys
contract = json.load(open(sys.argv[1], encoding="utf-8"))
print(int(next(item["start"] for item in contract["intervals"]
               if item["regime"] == sys.argv[2])))
PY
)
  current_stage="rollout-$regime"
  rollout_ok=false
  : >"$output_root/$regime-rollout.log"
  for attempt in 1 2; do
    printf 'attempt=%s started_at=%s\n' "$attempt" "$(date -u +%FT%TZ)" \
      >>"$output_root/$regime-rollout.log"
    if "$ROOT/ml-service/set_aims_traffic_regime.sh" "$regime" \
      >>"$output_root/$regime-rollout.log" 2>&1; then
      rollout_ok=true
      break
    fi
    sleep 5
  done
  [[ $rollout_ok == true ]]
  kubectl -n production get deployment aims-sentinel-loadgen \
    aims-sentinel-ingress-loadgen aims-sentinel-readmix-loadgen \
    aims-sentinel-dependency-loadgen -o json \
    >"$output_root/$regime-deployments.json"
  (( $(date +%s) <= regime_start ))
  current_stage="measuring-$regime"
  wait_until "$regime_start"
  printf 'campaign=%s regime=%s started_at=%s\n' \
    "$campaign_id" "$regime" "$(date -u +%FT%TZ)"
  wait_until "$((regime_start + REGIME_SECONDS))"
done

wait_until "$((campaign_end + FINAL_GRACE_SECONDS))"
current_stage=restoring-steady
"$ROOT/ml-service/set_aims_traffic_regime.sh" steady

capture_args=()
manifest_args=()
for index in "${!worker_hosts[@]}"; do
  host=${worker_hosts[$index]}
  node=${worker_nodes[$index]}
  run_id="$campaign_id-$node"
  current_stage="finalizing-$node"
  remote_sudo "$host" \
    "systemctl stop sentinel-pulse-collector-500ms-experiment.service"
  remote_sudo "$host" \
    "MINIMUM_ROWS_PER_WORKLOAD=100 $ROOT/sentinel_pulse/finalize_500ms_experiment.sh" \
    >"$output_root/nodes/$node-finalize.json"
  node_root="$output_root/nodes/$node"
  mkdir -p "$node_root"
  printf '%s\n' "$SSHPASS" | sshpass -e ssh \
    -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" \
    "sudo -S -p '' tar -C /var/lib/sentinel-pulse-500ms/runs -cf - $run_id" \
    | tar -C "$node_root" --strip-components=1 -xf -
  "$PYTHON" -m sentinel_pulse.finalize_500ms_dataset \
    --capture "$node_root/features.jsonl" --contract "$contract" --node "$node" \
    --final-report "$node_root/FINAL.json" \
    --output "$node_root/capture-manifest.json" >/dev/null
  capture_args+=(--capture "$node=$node_root/features.jsonl")
  manifest_args+=(--capture-manifest "$node=$node_root/capture-manifest.json")
done

dataset="$output_root/dataset/features.jsonl"
current_stage=assembling-dataset
"$PYTHON" -m sentinel_pulse.assemble_dataset --contract "$contract" \
  "${capture_args[@]}" "${manifest_args[@]}" --output "$dataset" \
  >"$output_root/dataset/ASSEMBLY.json"
"$PYTHON" -m sentinel_pulse.validate_capture --capture "$dataset" \
  --minimum-rows-per-workload 100 --interval-min-seconds 0.35 \
  --interval-max-seconds 0.80 --output "$output_root/dataset/VALIDATION.json"

kubectl get nodes -o wide >"$output_root/nodes-final.txt"
kubectl -n production get pods -o wide >"$output_root/production-pods-final.txt"
chmod 0444 "$dataset" "$dataset.manifest.json" \
  "$output_root/dataset/ASSEMBLY.json" "$output_root/dataset/VALIDATION.json"
find "$output_root" -type f ! -name SHA256SUMS ! -name COMPLETE \
  -print0 | sort -z | xargs -0 sha256sum >"$output_root/SHA256SUMS"
touch "$output_root/COMPLETE"
chmod -R a-w "$output_root"
campaign_complete=true
current_stage=complete
trap - EXIT INT TERM
printf 'PULSE_500MS_DATASET_COMPLETE root=%s dataset=%s\n' "$output_root" "$dataset"
