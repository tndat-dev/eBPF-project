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
REVISION_EVIDENCE_ROOT=${PULSE_500MS_REVISION_EVIDENCE_ROOT:-}
RAW_TELEMETRY_MINIMUM_AVAILABILITY=${PULSE_500MS_RAW_TELEMETRY_MINIMUM_AVAILABILITY:-0.998}
RAW_TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS=${PULSE_500MS_RAW_TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS:-10.0}
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
regimes=(steady toolmix peak burst recovery)
worker_runtime_sources=(
  sentinel_pulse/__init__.py
  sentinel_pulse/capture.py
  sentinel_pulse/encoding.py
  sentinel_pulse/features.py
  sentinel_pulse/integrity.py
  sentinel_pulse/validate_capture.py
)

[[ $REGIME_SECONDS =~ ^[0-9]+$ ]] && ((REGIME_SECONDS >= 300))
[[ $TRANSITION_GAP_SECONDS =~ ^[0-9]+$ ]] && ((TRANSITION_GAP_SECONDS >= 30))
[[ $PREPARE_SECONDS =~ ^[0-9]+$ ]] && ((PREPARE_SECONDS >= 150))
"$PYTHON" - "$RAW_TELEMETRY_MINIMUM_AVAILABILITY" \
  "$RAW_TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS" <<'PY'
import math, sys
availability, maximum_gap = map(float, sys.argv[1:])
if not all(map(math.isfinite, (availability, maximum_gap))):
    raise SystemExit("raw telemetry contract must be finite")
if not 0 < availability <= 1 or maximum_gap < 0.8:
    raise SystemExit("invalid raw telemetry contract")
PY
experiment_duration=$((
  PREPARE_SECONDS + ${#regimes[@]} * REGIME_SECONDS +
  (${#regimes[@]} - 1) * TRANSITION_GAP_SECONDS + FINAL_GRACE_SECONDS + 60
))
((experiment_duration <= 4500))

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
revision_gate_enabled=false
bound_revision_root=
revision_validation_report="$output_root/revision-evidence-validation.json"
auxiliary_health_log="$output_root/auxiliary-health-observations.jsonl"
last_auxiliary_health_sha=unset

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

if [[ $CAMPAIGN_MODE == formal ]]; then
  : "${REVISION_EVIDENCE_ROOT:?formal campaign requires PULSE_500MS_REVISION_EVIDENCE_ROOT}"
fi
if [[ -n $REVISION_EVIDENCE_ROOT ]]; then
  current_stage=validating-completed-revision-observer
  PYTHONPATH="$ROOT" "$PYTHON" -m sentinel_pulse.revision_evidence \
    --observer-root "$REVISION_EVIDENCE_ROOT" >/dev/null
  bound_revision_root="$output_root/revision-observer"
  mkdir -p "$bound_revision_root"
  cp -a "$REVISION_EVIDENCE_ROOT/runtime" "$bound_revision_root/"
  for artifact in START COMPLETE APPROVED_FINGERPRINT.json \
      final-fingerprint.json OBSERVATIONS.log SOURCE_SHA256SUMS \
      START_SHA256SUMS FINAL_SHA256SUMS; do
    cp -a "$REVISION_EVIDENCE_ROOT/$artifact" "$bound_revision_root/$artifact"
  done
  revision_gate_enabled=true
fi

snapshot_and_validate_revision() {
  local temporary_pods temporary_fingerprint temporary_report
  [[ $revision_gate_enabled == true ]] || return 0
  temporary_pods="$output_root/revision-current-pods.json.tmp"
  temporary_fingerprint="$output_root/revision-current-fingerprint.json.tmp"
  temporary_report="$revision_validation_report.tmp"
  kubectl -n production get pods -o json >"$temporary_pods" \
    2>"$output_root/revision-gate-error.txt" || return 1
  PYTHONPATH="$ROOT" "$PYTHON" -m sentinel_pulse.workload_fingerprint \
    --input "$temporary_pods" --output "$temporary_fingerprint" \
    >/dev/null 2>"$output_root/revision-gate-error.txt" || return 1
  PYTHONPATH="$ROOT" "$PYTHON" -m sentinel_pulse.revision_evidence \
    --observer-root "$bound_revision_root" \
    --current-fingerprint "$temporary_fingerprint" \
    --output "$temporary_report" >/dev/null \
    2>"$output_root/revision-gate-error.txt" || return 1
  mv "$temporary_pods" "$output_root/revision-current-pods.json"
  mv "$temporary_fingerprint" "$output_root/revision-current-fingerprint.json"
  mv "$temporary_report" "$revision_validation_report"
}

check_cluster_health() {
  local ready node_bad production_bad auxiliary_bad auxiliary_rows
  local auxiliary_sha timestamp host status ssh_rc healthy=true
  local -a statuses=()
  ready=$(kubectl get nodes --no-headers | \
    awk '$2 == "Ready" {count++} END {print count+0}')
  node_bad=$(kubectl get nodes -o json | \
    "$PYTHON" -m sentinel_pulse.cluster_health --resource nodes --count)
  production_bad=$(kubectl -n production get pods -o json | \
    "$PYTHON" -m sentinel_pulse.cluster_health --grace-seconds 300 --count)
  auxiliary_rows=$(kubectl get pods -A -o json | jq \
    '{items: [.items[] | select(.metadata.namespace != "production")]}' | \
    "$PYTHON" -m sentinel_pulse.cluster_health --grace-seconds 300)
  auxiliary_bad=$(printf '%s\n' "$auxiliary_rows" | sed '/^$/d' | wc -l)
  auxiliary_sha=$(printf '%s' "$auxiliary_rows" | sha256sum | awk '{print $1}')
  if [[ $auxiliary_sha != "$last_auxiliary_health_sha" ]]; then
    "$PYTHON" - "$auxiliary_health_log" "$current_stage" \
      "$auxiliary_rows" <<'PY'
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

rows = [json.loads(line) for line in sys.argv[3].splitlines() if line]
record = {
    "schema": "sentinel-pulse-auxiliary-health-observation-v1",
    "observed_at": datetime.now(timezone.utc).isoformat(),
    "stage": sys.argv[2],
    "blocking": False,
    "scope": "non-production Kubernetes namespaces",
    "unhealthy_pods": rows,
}
with Path(sys.argv[1]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
    last_auxiliary_health_sha=$auxiliary_sha
  fi
  [[ $ready -eq 6 && $node_bad -eq 0 && $production_bad -eq 0 ]] || \
    healthy=false
  if ! snapshot_and_validate_revision; then
    printf 'revision gate failed closed at %s\n' "$(date -u +%FT%TZ)" \
      >>"$output_root/revision-gate-error.txt"
    return 1
  fi
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
    printf 'ready_nodes=%s expected=6 unhealthy_nodes=%s production_unhealthy_pods=%s auxiliary_unhealthy_pods=%s consecutive=%s limit=%s stage=%s\n' \
      "$ready" "$node_bad" "$production_bad" "$auxiliary_bad" \
      "$health_failures" "$HEALTH_FAILURE_LIMIT" "$current_stage"
    printf '%s\n' "${statuses[@]}"
    kubectl get nodes -o wide
    kubectl -n production get pods -o json | \
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
  "$ROOT" "$CAMPAIGN_MODE" "$revision_validation_report" \
  "$RAW_TELEMETRY_MINIMUM_AVAILABILITY" \
  "$RAW_TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS" <<'PY'
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
    root / "sentinel_pulse/__init__.py",
    root / "sentinel_pulse/capture.py",
    root / "sentinel_pulse/encoding.py",
    root / "sentinel_pulse/features.py",
    root / "sentinel_pulse/integrity.py",
    root / "sentinel_pulse/validate_capture.py",
    root / "sentinel_pulse/cluster_health.py",
    root / "sentinel_pulse/revision_evidence.py",
    root / "sentinel_pulse/workload_fingerprint.py",
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
    "schema": "sentinel-pulse-500ms-dataset-protocol-v2",
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
        "raw_full_span_telemetry_contract": {
            "minimum_availability": float(sys.argv[10]),
            "maximum_single_gap_seconds": float(sys.argv[11]),
        },
        "measured_dataset_telemetry_contract": {
            "minimum_availability": 1.0,
            "minimum_interval_seconds": 0.35,
            "maximum_interval_seconds": 0.80,
            "nominal_interval_seconds": 0.5,
        },
    },
    "workers": [
        {"host": host, "node": node}
        for host, node in zip(sys.argv[5].split(), sys.argv[6].split())
    ],
    "contract": contract_reference,
    "contract_sha256": hashlib.sha256(contract.read_bytes()).hexdigest(),
    "revision_evidence": (
        json.loads(Path(sys.argv[9]).read_text())
        if sys.argv[9] and Path(sys.argv[9]).is_file() else None
    ),
    "health_gate_contract": {
        "blocking_scope": {
            "expected_ready_nodes": 6,
            "all_nodes_pressure_free": True,
            "namespaces": ["production"],
            "pulse_worker_runtime": True,
            "workload_revision_evidence": True,
        },
        "non_production_namespaces": "observed_non_blocking",
        "rationale": (
            "Only health failures on the experiment causal path may reject the "
            "dataset. Auxiliary controllers and bounded batch Jobs are recorded "
            "without being misclassified as model or capture failures."
        ),
    },
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
      "${worker_runtime_sources[@]}" \
      "$SSH_USER@$host:$ROOT/"
  )
  for source in "${worker_runtime_sources[@]}"; do
    remote "$host" "test -f '$ROOT/$source'" || {
      echo "worker runtime sync missing on $host: $source" >&2
      exit 3
    }
  done
done

for index in "${!worker_hosts[@]}"; do
  host=${worker_hosts[$index]}
  node=${worker_nodes[$index]}
  run_id="$campaign_id-$node"
  current_stage="starting-collector-$node"
  remote_sudo "$host" \
    "env SOURCE_ROOT=$ROOT DURATION_SECONDS=$experiment_duration RUN_ID=$run_id TELEMETRY_MINIMUM_AVAILABILITY=$RAW_TELEMETRY_MINIMUM_AVAILABILITY TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS=$RAW_TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS $ROOT/sentinel_pulse/install_500ms_experiment.sh"
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
current_stage=final-health-and-revision-gate
check_cluster_health

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
  --interval-max-seconds 0.80 --nominal-interval-seconds 0.5 \
  --minimum-telemetry-availability 1.0 --maximum-single-gap-seconds 0.80 \
  --output "$output_root/dataset/VALIDATION.json"

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
