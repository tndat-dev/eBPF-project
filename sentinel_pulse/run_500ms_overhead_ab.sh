#!/usr/bin/env bash
# Counterbalanced A/B benchmark: one-second collector fixed, 500 ms collector OFF/ON.
set -Eeuo pipefail

ROOT=${ROOT:-/home/dat/eBPF-project}
PYTHON=${PYTHON:-/home/dat/ml-venv/bin/python}
WORKER_HOST=${WORKER_HOST:-10.1.16.237}
WORKER_NODE=${WORKER_NODE:-k8s-worker1.local}
SSH_USER=${SSH_USER:-dat}
MODE=${PULSE_500MS_AB_MODE:-smoke}
OUTPUT_PARENT=${PULSE_500MS_AB_OUTPUT_PARENT:-$ROOT/validation-evidence/sentinel-pulse-campaign}
: "${SSHPASS:?export SSHPASS for SSH and remote sudo authentication}"

case "$MODE" in
  smoke)
    phases=(off on)
    repeats=1
    duration=10
    stabilization=5
    ;;
  full)
    # Four adjacent OFF/ON pairs with balanced order and carry-over direction.
    phases=(off on on off on off off on)
    repeats=5
    duration=30
    stabilization=15
    ;;
  *)
    echo "PULSE_500MS_AB_MODE must be smoke or full" >&2
    exit 2
    ;;
esac

campaign_id="pulse500-overhead-$MODE-$(date -u +%Y%m%dT%H%M%SZ)"
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
[[ $(git -C "$ROOT" rev-parse HEAD) == $(git -C "$ROOT" rev-parse origin/main) ]]

ready_nodes=$(kubectl get nodes --no-headers | awk '$2 == "Ready" {count++} END {print count+0}')
[[ $ready_nodes -eq 6 ]]
[[ -z $(kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded -o name) ]]
remote "systemctl is-active --quiet sentinel-pulse-resolver.service"
remote "systemctl is-active --quiet sentinel-pulse-collector.service"
! remote "systemctl is-active --quiet sentinel-pulse-detector-candidate.service"
! remote "systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service"

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

"$PYTHON" - "$protocol" "$campaign_id" "$MODE" "$url" \
  "$endpoint_pod" "$endpoint_uid" "$endpoint_ip" "$endpoint_image_id" \
  "$repeats" "$duration" "$stabilization" "$WORKER_NODE" "$phase_json" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

path = Path(sys.argv[1])
root = Path("/home/dat/eBPF-project")
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
        "endpoint-pod.yaml",
    )
}
payload = {
    "schema": "sentinel-pulse-500ms-overhead-protocol-v1",
    "campaign_id": sys.argv[2],
    "mode": sys.argv[3],
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
    "benchmark": {"tool": "wrk", "threads": 2, "concurrency": 20,
                  "duration_seconds": int(sys.argv[10])},
    "repetitions_per_phase": int(sys.argv[9]),
    "stabilization_seconds": int(sys.argv[11]),
    "phases": json.loads(sys.argv[13]),
    "fixed_background": {
        "one_second_collector": "active",
        "candidate_detector": "inactive",
        "normal_load_generators": "unchanged",
    },
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
  verify_endpoint
  if [[ $condition == on ]]; then
    active_run_id="$campaign_id-$phase_name"
    remote_sudo "env SOURCE_ROOT=/home/dat/eBPF-project DURATION_SECONDS=3600 RUN_ID=$active_run_id /home/dat/eBPF-project/sentinel_pulse/install_500ms_experiment.sh"
    remote "systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service"
  else
    ! remote "systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service"
  fi
  sleep "$stabilization"

  "$PYTHON" "$ROOT/sentinel/benchmarks/measure_phase.py" \
    --phase "$phase_name" --url "$url" --tool wrk --threads 2 \
    --concurrency 20 --duration "$duration" --repeats "$repeats" \
    --max-failed-requests 0 --output-root "$output_root" \
    --experiment-id "$campaign_id" \
    --detector-unit sentinel-pulse-collector-500ms-experiment.service \
    --systemd-host "$WORKER_HOST" --ssh-user "$SSH_USER" \
    --workload-namespace production \
    --workload-prefix aims-frontend- --workload-prefix api-gateway- \
    --workload-prefix auth-service- --workload-prefix cart-service- \
    --workload-prefix catalog-service- --workload-prefix inventory-service- \
    --workload-prefix order-service- --workload-prefix payment-service-

  verify_endpoint
  kubectl top node "$WORKER_NODE" >"$output_root/$phase_name-node-top.txt"
  if [[ $condition == on ]]; then
    remote_sudo "systemctl stop sentinel-pulse-collector-500ms-experiment.service"
    remote_sudo "MINIMUM_ROWS_PER_WORKLOAD=20 /home/dat/eBPF-project/sentinel_pulse/finalize_500ms_experiment.sh" \
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
kubectl get nodes -o wide >"$output_root/nodes-final.txt"
kubectl -n production get pods -o wide >"$output_root/production-pods-final.txt"
find "$output_root" -type f ! -name SHA256SUMS ! -name COMPLETE \
  -print0 | sort -z | xargs -0 sha256sum >"$output_root/SHA256SUMS"
touch "$output_root/COMPLETE"
chmod -R a-w "$output_root"
trap - EXIT INT TERM
printf 'PULSE_500MS_OVERHEAD_COMPLETE mode=%s root=%s\n' "$MODE" "$output_root"
