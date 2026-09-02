#!/usr/bin/env bash
# Preregister and start a non-promoting 25-hour Pulse live-normal soak.
set -euo pipefail

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
REMOTE_ROOT=${REMOTE_ROOT:-/home/dat/eBPF-project}
MODEL_SOURCE=${MODEL_SOURCE:?MODEL_SOURCE must be an absolute candidate directory}
POLICY_SOURCE=${POLICY_SOURCE:-$LOCAL_ROOT/sentinel_pulse/protocol/decision-policy-semantic-v4.json}
RUN_ID=${RUN_ID:-pulse500-normal-soak-$(date -u +%Y%m%dT%H%M%SZ)}
DURATION_SECONDS=${DURATION_SECONDS:-90000}
MINIMUM_DURATION_HOURS=${MINIMUM_DURATION_HOURS:-24}
PREFLIGHT_STABILITY_SECONDS=${PREFLIGHT_STABILITY_SECONDS:-300}
PREFLIGHT_TIMEOUT_SECONDS=${PREFLIGHT_TIMEOUT_SECONDS:-1800}
# Do not start a multi-hour capture simply because kubelet has not yet set
# DiskPressure.  A3 showed that the eviction signal can arrive after the
# experiment has started; keep enough root filesystem headroom for Longhorn,
# container image GC and immutable raw evidence.
MINIMUM_ROOT_AVAILABLE_BYTES=${MINIMUM_ROOT_AVAILABLE_BYTES:-68719476736}
MAXIMUM_ROOT_USED_PERCENT=${MAXIMUM_ROOT_USED_PERCENT:-80}
SUSPEND_CONTROL_COLLECTOR=${SUSPEND_CONTROL_COLLECTOR:-false}
PYTHON=${PYTHON:-python3}
SSH_USER=${SSH_USER:-dat}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-$LOCAL_ROOT/validation-evidence/sentinel-pulse-campaign/$RUN_ID}
WORKERS=(
  "10.1.16.237|k8s-worker1.local"
  "10.1.16.239|k8s-worker3.local"
  "10.1.16.238|k8s-worker4.local"
)

: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
command -v sshpass >/dev/null
command -v rsync >/dev/null
command -v kubectl >/dev/null
command -v jq >/dev/null
[[ $MODEL_SOURCE == "$LOCAL_ROOT"/* ]] || {
  echo "MODEL_SOURCE must be contained by LOCAL_ROOT" >&2; exit 2;
}
[[ $POLICY_SOURCE == "$LOCAL_ROOT"/* ]] || {
  echo "POLICY_SOURCE must be contained by LOCAL_ROOT" >&2; exit 2;
}
[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "RUN_ID contains unsafe characters" >&2; exit 2;
}
[[ $DURATION_SECONDS =~ ^[0-9]+$ ]] && ((DURATION_SECONDS >= 86400 && DURATION_SECONDS <= 90000)) || {
  echo "formal soak duration must be 86400..90000 seconds" >&2; exit 2;
}
[[ $PREFLIGHT_STABILITY_SECONDS =~ ^[0-9]+$ ]] &&
  ((PREFLIGHT_STABILITY_SECONDS >= 60)) || {
    echo "preflight stability must be at least 60 seconds" >&2; exit 2;
  }
[[ $PREFLIGHT_TIMEOUT_SECONDS =~ ^[0-9]+$ ]] &&
  ((PREFLIGHT_TIMEOUT_SECONDS >= PREFLIGHT_STABILITY_SECONDS)) || {
    echo "preflight timeout must cover the stability interval" >&2; exit 2;
  }
[[ $MINIMUM_ROOT_AVAILABLE_BYTES =~ ^[0-9]+$ ]] &&
  ((MINIMUM_ROOT_AVAILABLE_BYTES >= 34359738368)) || {
    echo "minimum root availability must be at least 32 GiB" >&2; exit 2;
  }
[[ $MAXIMUM_ROOT_USED_PERCENT =~ ^[0-9]+$ ]] &&
  ((MAXIMUM_ROOT_USED_PERCENT >= 1 && MAXIMUM_ROOT_USED_PERCENT <= 99)) || {
  echo "maximum root usage must be a percentage in 1..99" >&2; exit 2;
}
[[ $SUSPEND_CONTROL_COLLECTOR == true || $SUSPEND_CONTROL_COLLECTOR == false ]] || {
  echo "SUSPEND_CONTROL_COLLECTOR must be true or false" >&2; exit 2;
}
test -f "$MODEL_SOURCE/manifest.json"
test -f "$MODEL_SOURCE/manifest.sha256"
test -f "$POLICY_SOURCE"
test ! -e "$EVIDENCE_ROOT"
mkdir -p "$(dirname "$EVIDENCE_ROOT")"

# Reject incomplete archived bundles before suspending a production collector.
PYTHONPATH="$LOCAL_ROOT" "$PYTHON" - "$MODEL_SOURCE" <<'PY'
from pathlib import Path
import sys
from sentinel_pulse.finalize_candidate import verify_model_bundle

verify_model_bundle(Path(sys.argv[1]))
PY

remote() {
  local host=$1; shift
  sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 \
    "$SSH_USER@$host" "$@"
}

remote_sudo() {
  local host=$1; shift
  printf '%s\n' "$SSHPASS" | sshpass -e ssh \
    -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" \
    "sudo -S $*"
}

started_hosts=()
suspended_control_hosts=()
launch_complete=false
cleanup() {
  local rc=$?
  if [[ $launch_complete != true ]]; then
    for host in "${started_hosts[@]}"; do
      remote_sudo "$host" systemctl stop sentinel-pulse-detector-candidate.service \
        sentinel-pulse-collector-500ms-experiment.service >/dev/null 2>&1 || true
    done
    for host in "${suspended_control_hosts[@]}"; do
      remote_sudo "$host" systemctl start sentinel-pulse-collector.service \
        >/dev/null 2>&1 || true
    done
    if [[ -d $EVIDENCE_ROOT ]]; then
      printf 'launch_failed_at=%s\nexit_code=%s\n' "$(date -u +%FT%TZ)" "$rc" \
        >"$EVIDENCE_ROOT/FAILED"
    fi
  fi
}
trap cleanup EXIT
interrupt() {
  # Bash defers a trapped signal while waiting for a foreground child. Exit
  # only after that child returns so EXIT cleanup can quiesce every worker it
  # may have finished mutating.
  exit 130
}
trap interrupt INT TERM

cluster_health_snapshot() {
  local node_bad pod_bad longhorn_bad longhorn_disk_bad
  local longhorn_replica_bad cnpg_bad total
  total=$(kubectl get nodes -o json | jq '.items | length')
  node_bad=$(kubectl get nodes -o json | PYTHONPATH="$LOCAL_ROOT" \
    "$PYTHON" -m sentinel_pulse.cluster_health --resource nodes --count)
  pod_bad=$(kubectl -n production get pods -o json | PYTHONPATH="$LOCAL_ROOT" \
    "$PYTHON" -m sentinel_pulse.cluster_health --resource pods \
      --grace-seconds 0 --count)
  longhorn_bad=$(kubectl -n longhorn-system get volumes.longhorn.io -o json | \
    jq '[.items[] | select(.status.robustness != "healthy")] | length')
  longhorn_disk_bad=$(kubectl -n longhorn-system get nodes.longhorn.io -o json | \
    PYTHONPATH="$LOCAL_ROOT" "$PYTHON" -m sentinel_pulse.storage_health \
      --resource nodes --count)
  longhorn_replica_bad=$(kubectl -n longhorn-system get replicas.longhorn.io -o json | \
    PYTHONPATH="$LOCAL_ROOT" "$PYTHON" -m sentinel_pulse.storage_health \
      --resource replicas --count)
  cnpg_bad=$(kubectl -n production get clusters.postgresql.cnpg.io -o json | \
    jq '[.items[] | select(
      (.status.readyInstances // 0) != (.status.instances // .spec.instances // 0)
      or (.status.phase // "") != "Cluster in healthy state"
    )] | length')
  printf 'nodes=%s node_bad=%s production_pod_bad=%s longhorn_bad=%s longhorn_disk_topology_bad=%s longhorn_replica_topology_bad=%s cnpg_bad=%s\n' \
    "$total" "$node_bad" "$pod_bad" "$longhorn_bad" \
    "$longhorn_disk_bad" "$longhorn_replica_bad" "$cnpg_bad"
  [[ $total -eq 6 && $node_bad -eq 0 && $pod_bad -eq 0 &&
     $longhorn_bad -eq 0 && $longhorn_disk_bad -eq 0 &&
     $longhorn_replica_bad -eq 0 && $cnpg_bad -eq 0 ]]
}

worker_capacity_snapshot() {
  local target host expected_name row available used_percent bad=0
  for target in "${WORKERS[@]}"; do
    IFS='|' read -r host expected_name <<<"$target"
    row=$(remote "$host" "df -B1 --output=avail,pcent / | tail -n 1") || return 1
    read -r available used_percent <<<"$row"
    used_percent=${used_percent%%%}
    [[ $available =~ ^[0-9]+$ && $used_percent =~ ^[0-9]+$ ]] || return 1
    printf 'root_capacity host=%s available_bytes=%s used_percent=%s threshold_available_bytes=%s threshold_used_percent=%s\n' \
      "$host" "$available" "$used_percent" "$MINIMUM_ROOT_AVAILABLE_BYTES" "$MAXIMUM_ROOT_USED_PERCENT"
    ((available >= MINIMUM_ROOT_AVAILABLE_BYTES && used_percent <= MAXIMUM_ROOT_USED_PERCENT)) || bad=1
  done
  ((bad == 0))
}

worker_maintenance_snapshot() {
  local target host expected_name states bad=0
  local units=(
    unattended-upgrades.service
    apt-daily.timer
    apt-daily-upgrade.timer
  )
  for target in "${WORKERS[@]}"; do
    IFS='|' read -r host expected_name <<<"$target"
    states=$(remote "$host" "systemctl is-enabled ${units[*]} 2>/dev/null" || true)
    [[ $(wc -l <<<"$states") -eq ${#units[@]} ]] || return 1
    while read -r state; do
      [[ $state == masked || $state == masked-runtime ]] || bad=1
    done <<<"$states"
    printf 'maintenance_guard host=%s states=%s\n' \
      "$host" "$(tr '\n' ',' <<<"$states" | sed 's/,$//')"
  done
  ((bad == 0))
}

wait_for_stable_cluster() {
  local deadline stable_since=0 now snapshot capacity maintenance
  deadline=$(( $(date +%s) + PREFLIGHT_TIMEOUT_SECONDS ))
  while :; do
    now=$(date +%s)
    snapshot= capacity= maintenance=
    if snapshot=$(cluster_health_snapshot) && \
       capacity=$(worker_capacity_snapshot) && \
       maintenance=$(worker_maintenance_snapshot); then
      if ((stable_since == 0)); then
        stable_since=$now
      fi
      printf 'normal-soak preflight healthy: %s %s stable=%ss/%ss\n' \
        "$snapshot" "$capacity $maintenance" "$((now - stable_since))" "$PREFLIGHT_STABILITY_SECONDS"
      ((now - stable_since >= PREFLIGHT_STABILITY_SECONDS)) && return 0
    else
      stable_since=0
      printf 'normal-soak preflight unhealthy: %s %s %s\n' \
        "${snapshot:-cluster_snapshot_unavailable}" \
        "${capacity:-capacity_snapshot_unavailable}" \
        "${maintenance:-maintenance_snapshot_unavailable}" >&2
    fi
    ((now < deadline)) || {
      echo "cluster did not remain healthy for the preregistered stability interval" >&2
      return 1
    }
    sleep 15
  done
}

model_rel=${MODEL_SOURCE#"$LOCAL_ROOT/"}
policy_rel=${POLICY_SOURCE#"$LOCAL_ROOT/"}
model_sha=$(sha256sum "$MODEL_SOURCE/manifest.json" | awk '{print $1}')
policy_sha=$(sha256sum "$POLICY_SOURCE" | awk '{print $1}')
source_commit=$(git -C "$LOCAL_ROOT" rev-parse HEAD)
source_dirty=$(git -C "$LOCAL_ROOT" status --porcelain --untracked-files=no)
[[ -z $source_dirty ]] || { echo "tracked source worktree is dirty" >&2; exit 3; }

# Stage the exact source/model and install only the dependency-hardened base
# units before the stability interval and before creating the immutable marker.
# daemon-reload updates the dependency graph without interrupting active units.
for target in "${WORKERS[@]}"; do
  IFS='|' read -r host expected_name <<<"$target"
  observed=$(remote "$host" hostname -f)
  [[ $observed == "$expected_name" ]] || {
    echo "hostname mismatch for $host: $observed" >&2; exit 3;
  }
  remote "$host" "mkdir -p '$REMOTE_ROOT/sentinel_pulse' '$REMOTE_ROOT/$(dirname "$model_rel")' '$REMOTE_ROOT/$(dirname "$policy_rel")'"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$LOCAL_ROOT/sentinel_pulse/" "$SSH_USER@$host:$REMOTE_ROOT/sentinel_pulse/"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$MODEL_SOURCE/" "$SSH_USER@$host:$REMOTE_ROOT/$model_rel/"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$POLICY_SOURCE" "$SSH_USER@$host:$REMOTE_ROOT/$policy_rel"
  remote "$host" \
    "cd '$REMOTE_ROOT/$model_rel' && sha256sum -c manifest.sha256"
  [[ $(remote "$host" sha256sum "$REMOTE_ROOT/$policy_rel" | awk '{print $1}') == "$policy_sha" ]]
  remote_sudo "$host" install -m 0644 \
    "$REMOTE_ROOT/sentinel_pulse/systemd/sentinel-pulse-resolver.service" \
    /etc/systemd/system/sentinel-pulse-resolver.service
  remote_sudo "$host" install -m 0644 \
    "$REMOTE_ROOT/sentinel_pulse/systemd/sentinel-pulse-collector.service" \
    /etc/systemd/system/sentinel-pulse-collector.service
  remote_sudo "$host" systemctl daemon-reload
  control_state=$(remote "$host" \
    "systemctl is-active sentinel-pulse-collector.service 2>/dev/null || true")
  if [[ $control_state == active ]]; then
    [[ $SUSPEND_CONTROL_COLLECTOR == true ]] || {
      echo "legacy control collector is active on $host; set SUSPEND_CONTROL_COLLECTOR=true for an isolated formal soak" >&2
      exit 3
    }
    remote_sudo "$host" systemctl stop sentinel-pulse-collector.service
    suspended_control_hosts+=("$host")
  fi
  remote "$host" \
    "systemctl is-active --quiet sentinel-pulse-resolver && ! systemctl is-active --quiet sentinel-pulse-collector && ! systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment && ! systemctl is-active --quiet sentinel-pulse-detector-candidate && ! systemctl show sentinel-pulse-resolver -p Requires --value | grep -qw containerd.service && ! systemctl show sentinel-pulse-collector -p Requires --value | grep -qw sentinel-pulse-resolver.service"
done

# A Ready node may still have DiskPressure=True. Require all node pressure,
# production workload, Longhorn and CloudNativePG gates to remain healthy
# continuously before creating the immutable experiment marker.
wait_for_stable_cluster

# Create the evidence directory only after preflight. An interrupted preflight
# therefore cannot leave a run directory that blocks a safe lifecycle retry.
# mkdir is the final atomic ownership check immediately before preregistration.
mkdir "$EVIDENCE_ROOT"

# The marker exists before any experimental collector or detector starts.
python3 - "$EVIDENCE_ROOT/SOAK_START.json" "$RUN_ID" "$model_sha" \
  "$policy_sha" "$source_commit" "$MINIMUM_DURATION_HOURS" \
  "$MINIMUM_ROOT_AVAILABLE_BYTES" "$MAXIMUM_ROOT_USED_PERCENT" \
  "$(IFS=,; echo "${suspended_control_hosts[*]}")" <<'PY'
from datetime import datetime, timedelta, timezone
import json, pathlib, sys
out, run_id, model, policy, commit, hours, min_root, max_root, suspended = sys.argv[1:]
started = datetime.now(timezone.utc)
payload = {
    "schema": "sentinel-pulse-semantic-soak-start-v7",
    "run_id": run_id,
    "model_manifest_sha256": model,
    "decision_policy_sha256": policy,
    "source_git_commit": commit,
    "blind_evaluation_started": False,
    "automatic_promotion": False,
    "maximum_alerts": 0,
    "minimum_duration_hours_per_workload": float(hours),
    "minimum_coverage_ratio_per_workload": 0.95,
    "minimum_root_available_bytes": int(min_root),
    "maximum_root_used_percent": int(max_root),
    "maintenance_window_guard": {
        "required_state": "masked",
        "units": [
            "unattended-upgrades.service",
            "apt-daily.timer",
            "apt-daily-upgrade.timer",
        ],
    },
    "storage_topology_guard": {
        "duplicate_longhorn_disk_uuids": 0,
        "colocated_running_replicas": 0,
    },
    "legacy_control_collector_required_state": "inactive",
    "control_collector_suspended_hosts": [
        item for item in suspended.split(",") if item
    ],
    "started_not_before": started.isoformat(),
    "eligible_finalize_after": (started + timedelta(hours=float(hours))).isoformat(),
}
pathlib.Path(out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY

for target in "${WORKERS[@]}"; do
  IFS='|' read -r host node <<<"$target"
  started_hosts+=("$host")
  remote_sudo "$host" env SOURCE_ROOT="$REMOTE_ROOT" RUN_ID="$RUN_ID" \
    DURATION_SECONDS="$DURATION_SECONDS" \
    REQUIRE_CONTROL_COLLECTOR=false \
    "$REMOTE_ROOT/sentinel_pulse/install_500ms_experiment.sh"
  feature="/var/lib/sentinel-pulse-500ms/runs/$RUN_ID/features.jsonl"
  remote_sudo "$host" env SOURCE_ROOT="$REMOTE_ROOT" \
    MODEL_SOURCE="$REMOTE_ROOT/$model_rel" FEATURE_SOURCE="$feature" \
    DECISION_POLICY_SOURCE="$REMOTE_ROOT/$policy_rel" \
    DEPLOYMENT_ID="$RUN_ID" \
    REQUIRE_CONTROL_COLLECTOR=false \
    "$REMOTE_ROOT/sentinel_pulse/install_detector_candidate.sh"
  installed_model_sha=$(remote_sudo "$host" sha256sum \
    /opt/sentinel-pulse/models/current/manifest.json | awk '{print $1}')
  installed_policy_sha=$(remote_sudo "$host" sha256sum \
    /opt/sentinel-pulse/policies/current.json | awk '{print $1}')
  [[ $installed_model_sha == "$model_sha" ]]
  [[ $installed_policy_sha == "$policy_sha" ]]
  remote "$host" \
    "grep -Fx 'PULSE_FEATURES=$feature' /etc/sentinel-pulse-detector-candidate.env && systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment sentinel-pulse-detector-candidate"
  printf '%s %s %s\n' "$host" "$node" "$feature" >>"$EVIDENCE_ROOT/workers.txt"
done

sha256sum "$EVIDENCE_ROOT/SOAK_START.json" "$MODEL_SOURCE/manifest.json" \
  "$POLICY_SOURCE" >"$EVIDENCE_ROOT/START_SHA256SUMS"
touch "$EVIDENCE_ROOT/ACTIVE"
launch_complete=true
printf 'formal normal soak active: run=%s duration=%ss evidence=%s\n' \
  "$RUN_ID" "$DURATION_SECONDS" "$EVIDENCE_ROOT"
