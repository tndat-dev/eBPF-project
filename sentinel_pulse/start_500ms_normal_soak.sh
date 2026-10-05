#!/usr/bin/env bash
# Preregister and start a non-promoting 25-hour Pulse live-normal soak.
set -euo pipefail

if [[ -n ${TELEMETRY_RECOVERY_PROFILE_SOURCE:-} ]]; then
  echo 'recovery requires its separate diagnostic launcher; formal integration is not enabled' >&2
  exit 2
fi

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
REMOTE_ROOT=${REMOTE_ROOT:-/home/dat/eBPF-project}
MODEL_SOURCE=${MODEL_SOURCE:?MODEL_SOURCE must be an absolute candidate directory}
POLICY_SOURCE=${POLICY_SOURCE:-$LOCAL_ROOT/sentinel_pulse/protocol/decision-policy-semantic-v4.json}
RUN_ID=${RUN_ID:-pulse500-normal-soak-$(date -u +%Y%m%dT%H%M%SZ)}
DURATION_SECONDS=${DURATION_SECONDS:-90000}
MINIMUM_DURATION_HOURS=${MINIMUM_DURATION_HOURS:-24}
PREFLIGHT_STABILITY_SECONDS=${PREFLIGHT_STABILITY_SECONDS:-300}
PREFLIGHT_TIMEOUT_SECONDS=${PREFLIGHT_TIMEOUT_SECONDS:-1800}
TELEMETRY_NOMINAL_INTERVAL_SECONDS=${TELEMETRY_NOMINAL_INTERVAL_SECONDS:-0.5}
TELEMETRY_MINIMUM_AVAILABILITY=${TELEMETRY_MINIMUM_AVAILABILITY:-0.999}
TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS=${TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS:-10.0}
# Do not start a multi-hour capture simply because kubelet has not yet set
# DiskPressure.  A3 showed that the eviction signal can arrive after the
# experiment has started. Keep the percentage and node-pressure guards;
# a fixed free-byte floor is optional, not a mandatory 64 GiB reserve.
MINIMUM_ROOT_AVAILABLE_BYTES=${MINIMUM_ROOT_AVAILABLE_BYTES:-0}
MAXIMUM_ROOT_USED_PERCENT=${MAXIMUM_ROOT_USED_PERCENT:-80}
SUSPEND_CONTROL_COLLECTOR=${SUSPEND_CONTROL_COLLECTOR:-false}
PYTHON=${PYTHON:-python3}
OPERATIONAL_CONTRACT_SOURCE=${OPERATIONAL_CONTRACT_SOURCE:-}
COLLECTOR_VARIANT=${COLLECTOR_VARIANT:-legacy}
PROJECTED_CANARY_PLAN_SOURCE=${PROJECTED_CANARY_PLAN_SOURCE:-}
operational_binding=
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
[[ $MINIMUM_ROOT_AVAILABLE_BYTES =~ ^[0-9]+$ ]] || {
    echo "minimum root availability must be a non-negative byte count (0 disables the floor)" >&2; exit 2;
  }
[[ $MAXIMUM_ROOT_USED_PERCENT =~ ^[0-9]+$ ]] &&
  ((MAXIMUM_ROOT_USED_PERCENT >= 1 && MAXIMUM_ROOT_USED_PERCENT <= 99)) || {
  echo "maximum root usage must be a percentage in 1..99" >&2; exit 2;
}
[[ $SUSPEND_CONTROL_COLLECTOR == true || $SUSPEND_CONTROL_COLLECTOR == false ]] || {
  echo "SUSPEND_CONTROL_COLLECTOR must be true or false" >&2; exit 2;
}
python3 - "$TELEMETRY_NOMINAL_INTERVAL_SECONDS" \
  "$TELEMETRY_MINIMUM_AVAILABILITY" \
  "$TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS" <<'PY'
import math
import sys

nominal, availability, maximum_gap = map(float, sys.argv[1:])
if not all(map(math.isfinite, (nominal, availability, maximum_gap))):
    raise SystemExit("telemetry availability contract is not finite")
if nominal <= 0 or not 0 < availability <= 1 or maximum_gap < 0.8:
    raise SystemExit("invalid telemetry availability contract")
PY
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
  if [[ -n $operational_binding ]]; then
    PYTHONPATH="$LOCAL_ROOT" "$PYTHON" -m sentinel_pulse.operational_soak \
      snapshot --binding "$operational_binding"
    return $?
  fi
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
collector_args=(--variant "$COLLECTOR_VARIANT" --model-sha "$model_sha" --policy-sha "$policy_sha")
[[ -z $PROJECTED_CANARY_PLAN_SOURCE ]] || collector_args+=(--plan "$PROJECTED_CANARY_PLAN_SOURCE")
collector_binding=$(PYTHONPATH="$LOCAL_ROOT" "$PYTHON" -m sentinel_pulse.collector_contract "${collector_args[@]}")
if [[ $COLLECTOR_VARIANT == projected ]]; then
  unit_sha=$(sha256sum "$LOCAL_ROOT/sentinel_pulse/systemd/sentinel-pulse-collector-500ms-experiment.service" | awk '{print $1}')
  collector_binding=$(jq --arg unit "$unit_sha" '. + {unit_sha256:$unit, artifacts:{}}' <<<"$collector_binding")
fi
if [[ -n $OPERATIONAL_CONTRACT_SOURCE ]]; then
  [[ $OPERATIONAL_CONTRACT_SOURCE == "$LOCAL_ROOT"/* ]] || exit 2
  ((DURATION_SECONDS == 90000)) || {
    echo "operational soak requires the preregistered 25-hour collector bound" >&2; exit 2;
  }
  python3 - "$TELEMETRY_MINIMUM_AVAILABILITY" "$TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS" \
    "$MINIMUM_DURATION_HOURS" "$POLICY_SOURCE" <<'PY'
import json, math, pathlib, sys
minimum, gap, hours = map(float, sys.argv[1:4])
if not all(map(math.isfinite, (minimum, gap, hours))) or minimum < 0.999 or gap > 10 or not 24 <= hours <= 24.5:
    raise SystemExit("invalid operational telemetry/exposure contract")
policy = json.loads(pathlib.Path(sys.argv[4]).read_text())
for section, key in (("bounded_event_time_corroboration", "maximum_evidence_age_seconds"),
                     ("temporal_confirmation", "maximum_gap_seconds")):
    horizon = float((policy.get(section) or {}).get(key, 0))
    if not math.isfinite(horizon) or horizon > 30:
        raise SystemExit("policy horizon exceeds operational recovery exclusion")
PY
  operational_binding=$(PYTHONPATH="$LOCAL_ROOT" "$PYTHON" -m \
    sentinel_pulse.operational_soak bind --contract "$OPERATIONAL_CONTRACT_SOURCE" \
    --model-manifest "$MODEL_SOURCE/manifest.json" \
    --worker-nodes k8s-worker1.local k8s-worker3.local k8s-worker4.local)
fi

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
  if [[ $COLLECTOR_VARIANT == projected ]]; then
    safety_run=$(jq -er --arg host "$host" '.safety_runs[$host]' <<<"$collector_binding")
    selection=$(remote_sudo "$host" env PYTHONPATH="$REMOTE_ROOT" \
      /opt/sentinel-pulse/venv/bin/python -m sentinel_pulse.select_projected_collector \
      --canary-run-dir "$safety_run" --model-manifest "$REMOTE_ROOT/$model_rel/manifest.json")
    collector_binding=$(jq --arg host "$host" --argjson selection "$selection" \
      '.artifacts[$host] = $selection' <<<"$collector_binding")
  fi
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

# A normal-soak result is only meaningful for one immutable deployment state.
# Store template revisions, not pod UIDs, so harmless restarts do not invalidate
# the experiment while an actual Deployment/StatefulSet rollout does.
kubectl -n production get pods -o json >"$EVIDENCE_ROOT/workload-pods-start.json"
PYTHONPATH="$LOCAL_ROOT" "$PYTHON" -m sentinel_pulse.workload_fingerprint \
  --input "$EVIDENCE_ROOT/workload-pods-start.json" \
  --output "$EVIDENCE_ROOT/WORKLOAD_FINGERPRINT.json"

# The marker exists before any experimental collector or detector starts.
PYTHONPATH="$LOCAL_ROOT" python3 - "$EVIDENCE_ROOT/SOAK_START.json" "$RUN_ID" "$model_sha" \
  "$policy_sha" "$source_commit" "$MINIMUM_DURATION_HOURS" \
  "$MINIMUM_ROOT_AVAILABLE_BYTES" "$MAXIMUM_ROOT_USED_PERCENT" \
  "$(IFS=,; echo "${suspended_control_hosts[*]}")" \
  "$TELEMETRY_NOMINAL_INTERVAL_SECONDS" \
  "$TELEMETRY_MINIMUM_AVAILABILITY" \
  "$TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS" "$DURATION_SECONDS" \
  "$operational_binding" "$collector_binding" "$REMOTE_ROOT" <<'PY'
from datetime import datetime, timedelta, timezone
import json, pathlib, sys
(
    out, run_id, model, policy, commit, hours, min_root, max_root, suspended,
    telemetry_nominal, telemetry_availability, telemetry_gap, duration_seconds, operational, collector, remote_root,
) = sys.argv[1:]
started = datetime.now(timezone.utc)
payload = {
    "schema": "sentinel-pulse-semantic-soak-start-v8",
    "run_id": run_id,
    "model_manifest_sha256": model,
    "decision_policy_sha256": policy,
    "source_git_commit": commit,
    "remote_source_root": remote_root,
    "collector_contract": json.loads(collector),
    "blind_evaluation_started": False,
    "automatic_promotion": False,
    "maximum_alerts": 0,
    "minimum_duration_hours_per_workload": float(hours),
    "registered_collector_duration_seconds": int(duration_seconds),
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
    "telemetry_availability_contract": {
        "nominal_interval_seconds": float(telemetry_nominal),
        "minimum_availability": float(telemetry_availability),
        "maximum_single_gap_seconds": float(telemetry_gap),
    },
    "started_not_before": started.isoformat(),
    "eligible_finalize_after": (started + timedelta(hours=float(hours))).isoformat(),
}
if operational:
    from sentinel_pulse.operational_soak import validate_binding
    payload["operational_evaluation_contract"] = validate_binding(json.loads(operational))
    if float(telemetry_availability) < 0.999 or float(telemetry_gap) > 10:
        raise SystemExit("operational contract must not weaken telemetry")
    if float(hours) < 24 or float(hours) * 3600 + 1200 > int(duration_seconds):
        raise SystemExit("insufficient preregistered operational exposure/headroom")
    payload["eligible_finalize_after"] = (started + timedelta(seconds=int(duration_seconds) - 600)).isoformat()
pathlib.Path(out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
if [[ $COLLECTOR_VARIANT == projected ]]; then
  install -m 0444 "$PROJECTED_CANARY_PLAN_SOURCE" "$EVIDENCE_ROOT/PROJECTED_COLLECTOR_PLAN.json"
  [[ $(sha256sum "$EVIDENCE_ROOT/PROJECTED_COLLECTOR_PLAN.json" | awk '{print $1}') == \
     $(jq -er '.plan_sha256' <<<"$collector_binding") ]]
fi

# Cover worker installation too: otherwise the first monitor observation can
# arrive >180s after registration and leave startup health unobserved.
record_operational_startup_health() {
  if [[ -n $operational_binding ]]; then
    PYTHONPATH="$LOCAL_ROOT" "$PYTHON" -m sentinel_pulse.operational_soak \
      observe --marker "$EVIDENCE_ROOT/SOAK_START.json" \
      --log "$EVIDENCE_ROOT/OPERATIONAL_HEALTH.jsonl" \
      >"$EVIDENCE_ROOT/OPERATIONAL_HEALTH_LAST.json"
  fi
}
record_operational_startup_health

for target in "${WORKERS[@]}"; do
  IFS='|' read -r host node <<<"$target"
  started_hosts+=("$host")
  remote_sudo "$host" env SOURCE_ROOT="$REMOTE_ROOT" RUN_ID="$RUN_ID" \
    DURATION_SECONDS="$DURATION_SECONDS" \
    COLLECTOR_VARIANT="$COLLECTOR_VARIANT" \
    PROJECTED_CANARY_RUN_DIR="$(jq -r --arg host "$host" '.safety_runs[$host] // empty' <<<"$collector_binding")" \
    MODEL_MANIFEST_SOURCE="$REMOTE_ROOT/$model_rel/manifest.json" \
    REQUIRE_CONTROL_COLLECTOR=false \
    TELEMETRY_NOMINAL_INTERVAL_SECONDS="$TELEMETRY_NOMINAL_INTERVAL_SECONDS" \
    TELEMETRY_MINIMUM_AVAILABILITY="$TELEMETRY_MINIMUM_AVAILABILITY" \
    TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS="$TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS" \
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
  if [[ $COLLECTOR_VARIANT == projected ]]; then
    rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
      "$EVIDENCE_ROOT/SOAK_START.json" "$SSH_USER@$host:$REMOTE_ROOT/SOAK_START.json"
    remote_sudo "$host" install -m 0444 "$REMOTE_ROOT/SOAK_START.json" \
      "/var/lib/sentinel-pulse-500ms/runs/$RUN_ID/SOAK_START.json"
    remote_sudo "$host" env PYTHONPATH=/opt/sentinel-pulse \
      /opt/sentinel-pulse/runtime-venv/bin/python -m sentinel_pulse.collector_contract \
      --marker "/var/lib/sentinel-pulse-500ms/runs/$RUN_ID/SOAK_START.json" \
      --marker-sha "$(sha256sum "$EVIDENCE_ROOT/SOAK_START.json" | awk '{print $1}')" --runtime-host "$host"
  fi
  remote "$host" \
    "grep -Fx 'PULSE_FEATURES=$feature' /etc/sentinel-pulse-detector-candidate.env && systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment sentinel-pulse-detector-candidate"
  printf '%s %s %s\n' "$host" "$node" "$feature" >>"$EVIDENCE_ROOT/workers.txt"
  record_operational_startup_health
done

sha256sum "$EVIDENCE_ROOT/SOAK_START.json" "$MODEL_SOURCE/manifest.json" \
  "$POLICY_SOURCE" "$EVIDENCE_ROOT/WORKLOAD_FINGERPRINT.json" >"$EVIDENCE_ROOT/START_SHA256SUMS"
if [[ $COLLECTOR_VARIANT == projected ]]; then
  sha256sum "$EVIDENCE_ROOT/PROJECTED_COLLECTOR_PLAN.json" >>"$EVIDENCE_ROOT/START_SHA256SUMS"
fi
touch "$EVIDENCE_ROOT/ACTIVE"
launch_complete=true
printf 'formal normal soak active: run=%s duration=%ss evidence=%s\n' \
  "$RUN_ID" "$DURATION_SECONDS" "$EVIDENCE_ROOT"
