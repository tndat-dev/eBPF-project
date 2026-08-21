#!/usr/bin/env bash
# Counterbalanced A/B benchmark: one-second collector fixed, 500 ms collector OFF/ON.
set -Eeuo pipefail

ROOT=${ROOT:-/home/dat/eBPF-project}
PYTHON=${PYTHON:-/home/dat/ml-venv/bin/python}
WORKER_HOST=${WORKER_HOST:-10.1.16.237}
WORKER_NODE=${WORKER_NODE:-k8s-worker1.local}
SSH_USER=${SSH_USER:-dat}
MODE=${PULSE_500MS_AB_MODE:-smoke}
TREATMENT=${PULSE_500MS_AB_TREATMENT:-collector}
OUTPUT_PARENT=${PULSE_500MS_AB_OUTPUT_PARENT:-$ROOT/validation-evidence/sentinel-pulse-campaign}
REMOTE_ROOT=${REMOTE_ROOT:-/home/dat/eBPF-project-pulse-overhead}
: "${SSHPASS:?export SSHPASS for SSH and remote sudo authentication}"

case "$TREATMENT:$MODE" in
  pipeline:full)
    phases=(off on on off off on on off off on on off)
    repeats=5
    duration=60
    stabilization=20
    warmup=10
    threads=4
    connections=50
    CONTRACT=${PIPELINE_OVERHEAD_CONTRACT:-$ROOT/sentinel_pulse/protocol/pipeline-overhead-contract-v1.json}
    BLIND_EVIDENCE_ROOT=${BLIND_EVIDENCE_ROOT:?point to terminal eligible blind evidence}
    CANDIDATE_DECISION=${CANDIDATE_DECISION:-$BLIND_EVIDENCE_ROOT/CANDIDATE_DECISION.json}
    MODEL_SOURCE=${MODEL_SOURCE:-$BLIND_EVIDENCE_ROOT/model}
    DECISION_POLICY_SOURCE=${DECISION_POLICY_SOURCE:-$BLIND_EVIDENCE_ROOT/protocol/decision-policy.json}
    ;;
  collector:smoke)
    phases=(off on)
    repeats=1
    duration=10
    stabilization=5
    warmup=5
    threads=2
    connections=20
    ;;
  collector:full)
    phases=(off on on off on off off on)
    repeats=5
    duration=30
    stabilization=15
    warmup=5
    threads=2
    connections=20
    ;;
  pipeline:smoke)
    echo "pipeline treatment is formal-only; use PULSE_500MS_AB_MODE=full" >&2
    exit 2
    ;;
  *)
    echo "treatment/mode must be collector:(smoke|full) or pipeline:full" >&2
    exit 2
    ;;
esac

case "$MODE" in
  smoke)
    ;;
  full)
    ;;
  *)
    echo "PULSE_500MS_AB_MODE must be smoke or full" >&2
    exit 2
    ;;
esac

campaign_id="pulse500-$TREATMENT-overhead-$MODE-$(date -u +%Y%m%dT%H%M%SZ)"
output_root="$OUTPUT_PARENT/$campaign_id"
protocol="$output_root/PROTOCOL.json"
worker_target="$SSH_USER@$WORKER_HOST"
ssh_command=(sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$worker_target")

mkdir -p "$output_root/treatment-runs"
failure_marker="$output_root/FAILED.txt"
active_run_id=""

remote() {
  "${ssh_command[@]}" "$@"
}

remote_sudo() {
  local command=$1
  printf '%s\n' "$SSHPASS" | "${ssh_command[@]}" "sudo -S -p '' bash -lc $(printf '%q' "$command")"
}

cleanup() {
  local rc=$?
  if remote "systemctl is-active --quiet sentinel-pulse-detector-candidate.service"; then
    remote_sudo "systemctl stop sentinel-pulse-detector-candidate.service" || true
  fi
  remote_sudo "systemctl disable sentinel-pulse-detector-candidate.service" \
    >/dev/null 2>&1 || true
  if remote "systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service"; then
    remote_sudo "systemctl stop sentinel-pulse-collector-500ms-experiment.service" || true
  fi
  if ((rc != 0)); then
    printf 'failed_at=%s\nexit_code=%s\nactive_run_id=%s\n' \
      "$(date -u +%FT%TZ)" "$rc" "$active_run_id" >"$failure_marker"
  fi
  return "$rc"
}
trap cleanup EXIT INT TERM

[[ -x $ROOT/sentinel_pulse/install_500ms_experiment.sh ]]
[[ -x $ROOT/sentinel_pulse/finalize_500ms_experiment.sh ]]
[[ -f $ROOT/sentinel/benchmarks/measure_phase.py ]]
[[ -f $ROOT/sentinel_pulse/aggregate_500ms_overhead.py ]]
[[ -z $(git -C "$ROOT" status --short) ]]
git -C "$ROOT" cat-file -e HEAD^{commit}

if [[ $TREATMENT == pipeline ]]; then
  test -f "$CONTRACT"
  test -f "$CANDIDATE_DECISION"
  test -f "$MODEL_SOURCE/manifest.json"
  test -f "$MODEL_SOURCE/manifest.sha256"
  test -f "$DECISION_POLICY_SOURCE"
  jq -e '.schema == "sentinel-pulse-candidate-decision-v1" and
    .status == "eligible_for_overhead_evaluation" and
    .evidence_complete_for_accuracy_latency == true and
    .automatic_production_promotion == false' "$CANDIDATE_DECISION" >/dev/null
  [[ $(sha256sum "$MODEL_SOURCE/manifest.json" | awk '{print $1}') == \
     $(jq -er '.source_sha256.model_manifest' "$CANDIDATE_DECISION") ]]
  [[ $(sha256sum "$DECISION_POLICY_SOURCE" | awk '{print $1}') == \
     $(jq -er '.source_sha256.decision_policy' "$CANDIDATE_DECISION") ]]
fi

verify_cluster() {
  local label=$1
  [[ $label =~ ^[A-Za-z0-9._-]+$ ]]
  local node_total node_bad pod_bad tetragon_ready longhorn_bad cnpg_bad
  node_total=$(kubectl get nodes -o json | jq '.items | length')
  node_bad=$(kubectl get nodes -o json | PYTHONPATH="$ROOT" "$PYTHON" \
    -m sentinel_pulse.cluster_health --resource nodes --count)
  pod_bad=$(kubectl -n production get pods -o json | PYTHONPATH="$ROOT" "$PYTHON" \
    -m sentinel_pulse.cluster_health --resource pods --grace-seconds 0 --count)
  tetragon_ready=$(kubectl -n kube-system get pods \
    -l app.kubernetes.io/name=tetragon -o json | jq \
    '[.items[] | select(.status.phase == "Running" and
      ([.status.containerStatuses[]?.ready] | all))] | length')
  longhorn_bad=$(kubectl -n longhorn-system get volumes.longhorn.io -o json | jq \
    '[.items[] | select(.status.robustness != "healthy")] | length')
  cnpg_bad=$(kubectl -n production get clusters.postgresql.cnpg.io -o json | jq \
    '[.items[] | select((.status.readyInstances // 0) !=
      (.status.instances // .spec.instances // 0) or
      (.status.phase // "") != "Cluster in healthy state")] | length')
  jq -n --arg checked_at "$(date -u +%FT%TZ)" \
    --argjson node_total "$node_total" --argjson node_bad "$node_bad" \
    --argjson production_pod_bad "$pod_bad" \
    --argjson tetragon_ready "$tetragon_ready" \
    --argjson longhorn_bad "$longhorn_bad" --argjson cnpg_bad "$cnpg_bad" \
    '{checked_at: $checked_at, node_total: $node_total, node_bad: $node_bad,
      production_pod_bad: $production_pod_bad,
      tetragon_ready: $tetragon_ready, longhorn_bad: $longhorn_bad,
      cnpg_bad: $cnpg_bad}' >"$output_root/$label-cluster-health.json"
  [[ $node_total -eq 6 && $node_bad -eq 0 && $pod_bad -eq 0 && \
     $tetragon_ready -eq 6 && $longhorn_bad -eq 0 && $cnpg_bad -eq 0 ]]
}

verify_cluster campaign-start
remote "systemctl is-active --quiet sentinel-pulse-resolver.service"
remote "systemctl is-active --quiet sentinel-pulse-collector.service"
! remote "systemctl is-active --quiet sentinel-pulse-detector-candidate.service"
! remote "systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service"

if [[ $TREATMENT == pipeline ]]; then
  remote "mkdir -p '$REMOTE_ROOT/sentinel_pulse' '$REMOTE_ROOT/model' '$REMOTE_ROOT/protocol'"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$ROOT/sentinel_pulse/" "$SSH_USER@$WORKER_HOST:$REMOTE_ROOT/sentinel_pulse/"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$MODEL_SOURCE/" "$SSH_USER@$WORKER_HOST:$REMOTE_ROOT/model/"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$DECISION_POLICY_SOURCE" "$SSH_USER@$WORKER_HOST:$REMOTE_ROOT/protocol/decision-policy.json"
  mkdir -p "$output_root/detector-runs"
fi

candidate_binding='{}'
if [[ $TREATMENT == pipeline ]]; then
  candidate_binding=$(jq -n \
    --arg candidate_decision_sha256 "$(sha256sum "$CANDIDATE_DECISION" | awk '{print $1}')" \
    --arg model_manifest_sha256 "$(sha256sum "$MODEL_SOURCE/manifest.json" | awk '{print $1}')" \
    --arg decision_policy_sha256 "$(sha256sum "$DECISION_POLICY_SOURCE" | awk '{print $1}')" \
    --arg overhead_contract_sha256 "$(sha256sum "$CONTRACT" | awk '{print $1}')" \
    '{candidate_decision_sha256: $candidate_decision_sha256,
      model_manifest_sha256: $model_manifest_sha256,
      decision_policy_sha256: $decision_policy_sha256,
      overhead_contract_sha256: $overhead_contract_sha256}')
fi

endpoint_record=$(
  kubectl -n istio-ingress get pods \
    -l gateway.networking.k8s.io/gateway-name=aims-ingress \
    -o json | "$PYTHON" -c '
import json, sys
pods = json.load(sys.stdin)["items"]
matches = [p for p in pods if p["spec"].get("nodeName") == sys.argv[1]
           and p.get("status", {}).get("phase") == "Running"]
if len(matches) != 1:
    raise SystemExit(f"expected one ingress pod on {sys.argv[1]}, got {len(matches)}")
p = matches[0]
c = p["status"]["containerStatuses"][0]
print("|".join((p["metadata"]["name"], p["metadata"]["uid"],
                p["status"]["podIP"], c.get("imageID", ""))))
' "$WORKER_NODE"
)
IFS='|' read -r endpoint_pod endpoint_uid endpoint_ip endpoint_image_id <<<"$endpoint_record"
url="http://$endpoint_ip/api/products/"
curl -fsS --max-time 5 "$url" >/dev/null

kubectl get nodes -o wide >"$output_root/nodes-start.txt"
kubectl -n production get pods -o wide >"$output_root/production-pods-start.txt"
kubectl -n production get deploy aims-sentinel-loadgen \
  aims-sentinel-dependency-loadgen -o yaml >"$output_root/traffic-generators.yaml"
kubectl -n istio-ingress get pod "$endpoint_pod" -o yaml \
  >"$output_root/endpoint-pod.yaml"
(
  cd "$ROOT"
  git ls-files -z -- sentinel_pulse sentinel/benchmarks | sort -z | \
    xargs -0 sha256sum
) >"$output_root/SOURCE_SHA256SUMS"

if [[ $TREATMENT == pipeline ]]; then
  mkdir -p "$output_root/frozen-inputs"
  install -m 0444 "$CONTRACT" "$output_root/frozen-inputs/pipeline-overhead-contract.json"
  install -m 0444 "$CANDIDATE_DECISION" "$output_root/frozen-inputs/CANDIDATE_DECISION.json"
  install -m 0444 "$MODEL_SOURCE/manifest.json" "$output_root/frozen-inputs/model-manifest.json"
  install -m 0444 "$MODEL_SOURCE/manifest.sha256" "$output_root/frozen-inputs/model-manifest.sha256"
  install -m 0444 "$DECISION_POLICY_SOURCE" "$output_root/frozen-inputs/decision-policy.json"
fi

phase_json=$(
  printf '%s\n' "${phases[@]}" | "$PYTHON" -c '
import json, sys
campaign = sys.argv[1]
items = []
for index, condition in enumerate((line.strip() for line in sys.stdin if line.strip()), 1):
    name = f"p{index:02d}-{condition}"
    items.append({
        "index": index,
        "name": name,
        "condition": condition,
        "treatment_run_id": f"{campaign}-{name}" if condition == "on" else None,
    })
print(json.dumps(items))
' "$campaign_id"
)

if [[ $TREATMENT == pipeline ]]; then
  observed_order=$(jq '[.[].condition]' <<<"$phase_json")
  jq -e --argjson observed_order "$observed_order" \
    --argjson repeats "$repeats" --argjson duration "$duration" \
    --argjson stabilization "$stabilization" --argjson warmup "$warmup" \
    --argjson threads "$threads" --argjson connections "$connections" '
      .registered_before_blind_outcomes == true and
      .automatic_promotion == false and
      .design.phase_order == $observed_order and
      .design.repetitions_per_phase == $repeats and
      .design.measurement_seconds_per_repetition == $duration and
      .design.stabilization_seconds == $stabilization and
      .design.warmup_seconds == $warmup and
      .design.wrk_threads == $threads and
      .design.wrk_connections == $connections
    ' "$CONTRACT" >/dev/null
fi

"$PYTHON" - "$protocol" "$campaign_id" "$MODE" "$url" \
  "$endpoint_pod" "$endpoint_uid" "$endpoint_ip" "$endpoint_image_id" \
  "$repeats" "$duration" "$stabilization" "$WORKER_NODE" "$phase_json" \
  "$ROOT" "$TREATMENT" "$candidate_binding" "$threads" "$connections" \
  "$warmup" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

path = Path(sys.argv[1])
root = Path(sys.argv[14])
files = [
    root / "sentinel_pulse/install_500ms_experiment.sh",
    root / "sentinel_pulse/finalize_500ms_experiment.sh",
    root / "sentinel_pulse/systemd/sentinel-pulse-collector-500ms-experiment.service",
    root / "sentinel_pulse/aggregate_500ms_overhead.py",
    root / "sentinel/benchmarks/measure_phase.py",
]
environment = {
    name: hashlib.sha256((path.parent / name).read_bytes()).hexdigest()
    for name in (
        "nodes-start.txt", "production-pods-start.txt", "traffic-generators.yaml",
        "endpoint-pod.yaml", "SOURCE_SHA256SUMS",
    )
}
payload = {
    "schema": "sentinel-pulse-500ms-overhead-protocol-v1",
    "campaign_id": sys.argv[2],
    "mode": sys.argv[3],
    "treatment": sys.argv[15],
    "registered_at": subprocess.check_output(
        ["date", "-u", "+%FT%TZ"], text=True
    ).strip(),
    "git_commit": subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip(),
    "endpoint": {
        "url": sys.argv[4], "pod": sys.argv[5], "pod_uid": sys.argv[6],
        "pod_ip": sys.argv[7], "image_id": sys.argv[8],
        "node": sys.argv[12],
    },
    "benchmark": {"tool": "wrk", "threads": int(sys.argv[17]),
                  "concurrency": int(sys.argv[18]),
                  "duration_seconds": int(sys.argv[10]),
                  "warmup_seconds": int(sys.argv[19])},
    "repetitions_per_phase": int(sys.argv[9]),
    "stabilization_seconds": int(sys.argv[11]),
    "phases": json.loads(sys.argv[13]),
    "fixed_background": {
        "one_second_collector": "active",
        "candidate_detector": (
            "treatment-only" if sys.argv[15] == "pipeline" else "inactive"
        ),
        "normal_load_generators": "unchanged",
    },
    "candidate_binding": json.loads(sys.argv[16]),
    "source_sha256": {
        str(item.relative_to(root)): hashlib.sha256(item.read_bytes()).hexdigest()
        for item in files
    },
    "environment_sha256": environment,
    "quality_gate": "zero process/socket/non-2xx errors; endpoint UID/IP immutable",
    "automatic_promotion": False,
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
chmod 0444 "$protocol"

verify_endpoint() {
  local record
  record=$(kubectl -n istio-ingress get pod "$endpoint_pod" \
    -o jsonpath='{.metadata.uid}|{.status.podIP}|{.status.phase}')
  [[ $record == "$endpoint_uid|$endpoint_ip|Running" ]]
  curl -fsS --max-time 5 "$url" >/dev/null
}

for index in "${!phases[@]}"; do
  ordinal=$((index + 1))
  condition=${phases[$index]}
  phase_name=$(printf 'p%02d-%s' "$ordinal" "$condition")
  active_run_id=""
  verify_cluster "$phase_name-before"
  verify_endpoint
  if [[ $condition == on ]]; then
    active_run_id="$campaign_id-$phase_name"
    treatment_source_root=/home/dat/eBPF-project
    [[ $TREATMENT == pipeline ]] && treatment_source_root=$REMOTE_ROOT
    remote_sudo "env SOURCE_ROOT=$treatment_source_root DURATION_SECONDS=3600 RUN_ID=$active_run_id $treatment_source_root/sentinel_pulse/install_500ms_experiment.sh"
    remote "systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service"
    if [[ $TREATMENT == pipeline ]]; then
      feature_source="/var/lib/sentinel-pulse-500ms/runs/$active_run_id/features.jsonl"
      remote_sudo "env SOURCE_ROOT=$REMOTE_ROOT MODEL_SOURCE=$REMOTE_ROOT/model DECISION_POLICY_SOURCE=$REMOTE_ROOT/protocol/decision-policy.json FEATURE_SOURCE=$feature_source DEPLOYMENT_ID=$active_run_id ENABLE_INJECTION_TRACKING=false $REMOTE_ROOT/sentinel_pulse/install_detector_candidate.sh"
      remote "systemctl is-active --quiet sentinel-pulse-detector-candidate.service"
    fi
  else
    ! remote "systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service"
    ! remote "systemctl is-active --quiet sentinel-pulse-detector-candidate.service"
  fi
  sleep "$stabilization"

  measured_unit=sentinel-pulse-collector-500ms-experiment.service
  [[ $TREATMENT == pipeline ]] && measured_unit=sentinel-pulse-detector-candidate.service
  "$PYTHON" "$ROOT/sentinel/benchmarks/measure_phase.py" \
    --phase "$phase_name" --url "$url" --tool wrk --threads "$threads" \
    --concurrency "$connections" --duration "$duration" --repeats "$repeats" \
    --warmup-duration "$warmup" \
    --max-failed-requests 0 --output-root "$output_root" \
    --experiment-id "$campaign_id" \
    --detector-unit "$measured_unit" \
    --systemd-host "$WORKER_HOST" --ssh-user "$SSH_USER" \
    --workload-namespace production \
    --workload-prefix aims-frontend- --workload-prefix api-gateway- \
    --workload-prefix auth-service- --workload-prefix cart-service- \
    --workload-prefix catalog-service- --workload-prefix inventory-service- \
    --workload-prefix order-service- --workload-prefix payment-service-

  verify_endpoint
  verify_cluster "$phase_name-after"
  kubectl top node "$WORKER_NODE" >"$output_root/$phase_name-node-top.txt"
  if [[ $condition == on ]]; then
    if [[ $TREATMENT == pipeline ]]; then
      detector_snapshot=$(remote "systemctl show sentinel-pulse-detector-candidate.service -p ActiveState -p NRestarts -p CPUUsageNSec -p MemoryPeak --no-pager")
      printf '%s\n' "$detector_snapshot" >"$output_root/$phase_name-detector-final.txt"
      [[ $(sed -n 's/^ActiveState=//p' <<<"$detector_snapshot") == active ]]
      [[ $(sed -n 's/^NRestarts=//p' <<<"$detector_snapshot") == 0 ]]
      detector_env=$(remote_sudo "cat /etc/sentinel-pulse-detector-candidate.env")
      decision_path=$(sed -n 's/^PULSE_DECISIONS=//p' <<<"$detector_env")
      alert_path=$(sed -n 's/^PULSE_ALERTS=//p' <<<"$detector_env")
      detector_dir=$(dirname "$decision_path")
      [[ $detector_dir == /var/lib/sentinel-pulse-detector/runs/* ]]
      [[ $(remote_sudo "wc -l < '$alert_path'") -eq 0 ]]
      remote_sudo "systemctl stop sentinel-pulse-detector-candidate.service"
      remote_sudo "systemctl disable sentinel-pulse-detector-candidate.service"
      printf '%s\n' "$SSHPASS" | "${ssh_command[@]}" \
        "sudo -S -p '' tar -C / -cf - '${detector_dir#/}'" | \
        tar -C "$output_root/detector-runs" -xf -
      test -s "$output_root/detector-runs/${decision_path#/}"
      test -f "$output_root/detector-runs/${alert_path#/}"
    fi
    remote_sudo "systemctl stop sentinel-pulse-collector-500ms-experiment.service"
    remote_sudo "MINIMUM_ROWS_PER_WORKLOAD=20 $treatment_source_root/sentinel_pulse/finalize_500ms_experiment.sh" \
      >"$output_root/$phase_name-finalize.json"
    printf '%s\n' "$SSHPASS" | "${ssh_command[@]}" \
      "sudo -S -p '' tar -C /var/lib/sentinel-pulse-500ms/runs -cf - $active_run_id" \
      | tar -C "$output_root/treatment-runs" -xf -
    active_run_id=""
  fi
done

"$PYTHON" -m sentinel_pulse.aggregate_500ms_overhead \
  --root "$output_root" --protocol "$protocol" \
  --output "$output_root/RESULT.json"
verify_endpoint
verify_cluster campaign-final
kubectl get nodes -o wide >"$output_root/nodes-final.txt"
kubectl -n production get pods -o wide >"$output_root/production-pods-final.txt"
find "$output_root" -type f ! -name SHA256SUMS ! -name COMPLETE \
  -print0 | sort -z | xargs -0 sha256sum >"$output_root/SHA256SUMS"
touch "$output_root/COMPLETE"
chmod -R a-w "$output_root"
trap - EXIT INT TERM
printf 'PULSE_500MS_OVERHEAD_COMPLETE mode=%s root=%s\n' "$MODE" "$output_root"
