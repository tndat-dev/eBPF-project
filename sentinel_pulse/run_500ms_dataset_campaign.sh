#!/usr/bin/env bash
# Capture a bounded, normal-only 500 ms dataset on all three workers.
set -Eeuo pipefail

ROOT=${ROOT:-/home/dat/eBPF-project}
PYTHON=${PYTHON:-/home/dat/ml-venv/bin/python}
SSH_USER=${SSH_USER:-dat}
OUTPUT_PARENT=${PULSE_500MS_DATA_OUTPUT_PARENT:-$ROOT/validation-evidence/sentinel-pulse-campaign}
REGIME_SECONDS=${PULSE_500MS_REGIME_SECONDS:-600}
TRANSITION_GAP_SECONDS=${PULSE_500MS_TRANSITION_GAP_SECONDS:-60}
PREPARE_SECONDS=${PULSE_500MS_PREPARE_SECONDS:-180}
FINAL_GRACE_SECONDS=${PULSE_500MS_FINAL_GRACE_SECONDS:-15}
: "${SSHPASS:?export SSHPASS for SSH and remote sudo authentication}"

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

campaign_id="pulse500-data-$(date -u +%Y%m%dT%H%M%SZ)"
output_root="$OUTPUT_PARENT/$campaign_id"
contract="$output_root/capture-contract.json"
protocol="$output_root/PROTOCOL.json"
failure_marker="$output_root/FAILED.txt"
campaign_complete=false
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
    printf 'failed_at=%s\nexit_code=%s\n' "$(date -u +%FT%TZ)" "$rc" \
      >"$failure_marker"
  fi
  return "$rc"
}
trap restore EXIT INT TERM

check_cluster_health() {
  local ready bad
  ready=$(kubectl get nodes --no-headers | \
    awk '$2 == "Ready" {count++} END {print count+0}')
  bad=$(kubectl get pods -A -o json | \
    "$PYTHON" -m sentinel_pulse.cluster_health --grace-seconds 300 --count)
  [[ $ready -eq 6 && $bad -eq 0 ]]
  for host in "${worker_hosts[@]}"; do
    remote "$host" "systemctl is-active --quiet sentinel-pulse-resolver.service"
    remote "$host" "systemctl is-active --quiet sentinel-pulse-collector.service"
    ! remote "$host" \
      "systemctl is-active --quiet sentinel-pulse-detector-candidate.service"
  done
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

[[ -z $(git -C "$ROOT" status --short) ]]
[[ $(git -C "$ROOT" rev-parse HEAD) == $(git -C "$ROOT" rev-parse origin/main) ]]
check_cluster_health
kubectl get nodes -o wide >"$output_root/nodes-start.txt"
kubectl -n production get pods -o wide >"$output_root/production-pods-start.txt"
kubectl -n production get deploy aims-sentinel-loadgen \
  aims-sentinel-readmix-loadgen aims-sentinel-dependency-loadgen -o yaml \
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
  "$experiment_duration" "${worker_hosts[*]}" "${worker_nodes[*]}" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
output, campaign, contract = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
root = Path("/home/dat/eBPF-project")
sources = [
    root / "sentinel_pulse/run_500ms_dataset_campaign.sh",
    root / "sentinel_pulse/install_500ms_experiment.sh",
    root / "sentinel_pulse/finalize_500ms_experiment.sh",
    root / "sentinel_pulse/finalize_500ms_dataset.py",
    root / "sentinel_pulse/assemble_dataset.py",
    root / "sentinel_pulse/train.py",
    root / "ml-service/set_aims_traffic_regime.sh",
]
payload = {
    "schema": "sentinel-pulse-500ms-dataset-protocol-v1",
    "campaign_id": campaign,
    "registered_at": subprocess.check_output(
        ["date", "-u", "+%FT%TZ"], text=True
    ).strip(),
    "git_commit": subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip(),
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
    "contract": str(contract.relative_to(root)),
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
  remote_sudo "$host" \
    "env SOURCE_ROOT=$ROOT DURATION_SECONDS=$experiment_duration RUN_ID=$run_id $ROOT/sentinel_pulse/install_500ms_experiment.sh"
done
for host in "${worker_hosts[@]}"; do
  remote "$host" \
    "systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service"
done

for regime in "${regimes[@]}"; do
  regime_start=$("$PYTHON" - "$contract" "$regime" <<'PY'
import json, sys
contract = json.load(open(sys.argv[1], encoding="utf-8"))
print(int(next(item["start"] for item in contract["intervals"]
               if item["regime"] == sys.argv[2])))
PY
)
  "$ROOT/ml-service/set_aims_traffic_regime.sh" "$regime"
  kubectl -n production get deployment aims-sentinel-loadgen \
    aims-sentinel-readmix-loadgen aims-sentinel-dependency-loadgen -o json \
    >"$output_root/$regime-deployments.json"
  (( $(date +%s) <= regime_start ))
  wait_until "$regime_start"
  printf 'campaign=%s regime=%s started_at=%s\n' \
    "$campaign_id" "$regime" "$(date -u +%FT%TZ)"
  wait_until "$((regime_start + REGIME_SECONDS))"
done

wait_until "$((campaign_end + FINAL_GRACE_SECONDS))"
"$ROOT/ml-service/set_aims_traffic_regime.sh" steady

capture_args=()
manifest_args=()
for index in "${!worker_hosts[@]}"; do
  host=${worker_hosts[$index]}
  node=${worker_nodes[$index]}
  run_id="$campaign_id-$node"
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
trap - EXIT INT TERM
printf 'PULSE_500MS_DATASET_COMPLETE root=%s dataset=%s\n' "$output_root" "$dataset"
