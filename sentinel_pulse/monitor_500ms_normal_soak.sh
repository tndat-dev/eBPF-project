#!/usr/bin/env bash
# Read-only fail-closed monitor for a preregistered Pulse normal soak.
set -u

EVIDENCE_ROOT=${1:?usage: monitor_500ms_normal_soak.sh EVIDENCE_ROOT}
SSH_USER=${SSH_USER:-dat}
POLL_SECONDS=${POLL_SECONDS:-60}
MINIMUM_ROOT_AVAILABLE_BYTES=${MINIMUM_ROOT_AVAILABLE_BYTES:-68719476736}
MAXIMUM_ROOT_USED_PERCENT=${MAXIMUM_ROOT_USED_PERCENT:-80}
LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
PYTHON=${PYTHON:-python3}
: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
MARKER="$EVIDENCE_ROOT/SOAK_START.json"
WORKERS_FILE="$EVIDENCE_ROOT/workers.txt"
LOG="$EVIDENCE_ROOT/MONITOR.jsonl"
test -f "$MARKER" && test -f "$WORKERS_FILE" && test -f "$EVIDENCE_ROOT/ACTIVE" || exit 2
test ! -e "$EVIDENCE_ROOT/FAILED" || exit 2

eligible_epoch=$(python3 - "$MARKER" <<'PY'
from datetime import datetime
import json, pathlib, sys
marker=json.loads(pathlib.Path(sys.argv[1]).read_text())
print(datetime.fromisoformat(marker["eligible_finalize_after"]).timestamp())
PY
)

write_row() {
  python3 - "$LOG" "$@" <<'PY'
import json, pathlib, sys, time
path=pathlib.Path(sys.argv[1])
host, collector, legacy, detector, restarts, decisions, alerts, feature, expected = sys.argv[2:]
row={
    "checked_at_unix": time.time(), "host": host,
    "collector": collector, "legacy_control_collector": legacy,
    "detector": detector,
    "nrestarts": int(restarts), "decisions": int(decisions),
    "alerts": int(alerts), "feature_source": feature,
    "expected_feature_source": expected,
}
with path.open("a", encoding="utf-8") as out:
    out.write(json.dumps(row, separators=(",", ":")) + "\n")
PY
}

fail() {
  local reason=$1 host=${2:-unknown}
  kubectl get nodes -o json >"$EVIDENCE_ROOT/FAILURE_NODES.json" 2>/dev/null || true
  kubectl -n production get pods -o json \
    >"$EVIDENCE_ROOT/FAILURE_PRODUCTION_PODS.json" 2>/dev/null || true
  kubectl -n longhorn-system get volumes.longhorn.io -o json \
    >"$EVIDENCE_ROOT/FAILURE_LONGHORN_VOLUMES.json" 2>/dev/null || true
  kubectl -n longhorn-system get nodes.longhorn.io -o json \
    >"$EVIDENCE_ROOT/FAILURE_LONGHORN_NODES.json" 2>/dev/null || true
  kubectl -n longhorn-system get replicas.longhorn.io -o json \
    >"$EVIDENCE_ROOT/FAILURE_LONGHORN_REPLICAS.json" 2>/dev/null || true
  kubectl -n production get clusters.postgresql.cnpg.io -o json \
    >"$EVIDENCE_ROOT/FAILURE_CNPG_CLUSTERS.json" 2>/dev/null || true
  printf 'failed_at=%s\nreason=%s\nhost=%s\n' \
    "$(date -u +%FT%TZ)" "$reason" "$host" >"$EVIDENCE_ROOT/FAILED"
  rm -f "$EVIDENCE_ROOT/ACTIVE"
  exit 1
}

check_cluster_health() {
  local nodes pods longhorn longhorn_disks longhorn_replicas cnpg
  nodes=$(kubectl get nodes -o json 2>/dev/null | PYTHONPATH="$LOCAL_ROOT" \
    "$PYTHON" -m sentinel_pulse.cluster_health --resource nodes --count) ||
    fail cluster_health_unavailable
  pods=$(kubectl -n production get pods -o json 2>/dev/null | \
    PYTHONPATH="$LOCAL_ROOT" "$PYTHON" -m sentinel_pulse.cluster_health \
      --resource pods --grace-seconds 300 --count) ||
    fail production_health_unavailable
  longhorn=$(kubectl -n longhorn-system get volumes.longhorn.io -o json \
    2>/dev/null | jq '[.items[] | select(.status.robustness != "healthy")] | length') ||
    fail longhorn_health_unavailable
  longhorn_disks=$(kubectl -n longhorn-system get nodes.longhorn.io -o json \
    2>/dev/null | PYTHONPATH="$LOCAL_ROOT" "$PYTHON" \
      -m sentinel_pulse.storage_health --resource nodes --count) ||
    fail longhorn_disk_topology_unavailable
  longhorn_replicas=$(kubectl -n longhorn-system get replicas.longhorn.io -o json \
    2>/dev/null | PYTHONPATH="$LOCAL_ROOT" "$PYTHON" \
      -m sentinel_pulse.storage_health --resource replicas --count) ||
    fail longhorn_replica_topology_unavailable
  cnpg=$(kubectl -n production get clusters.postgresql.cnpg.io -o json \
    2>/dev/null | jq '[.items[] | select(
      (.status.readyInstances // 0) != (.status.instances // .spec.instances // 0)
      or (.status.phase // "") != "Cluster in healthy state"
    )] | length') || fail cnpg_health_unavailable
  ((nodes == 0)) || fail unhealthy_kubernetes_node
  ((pods == 0)) || fail unhealthy_production_pod
  ((longhorn == 0)) || fail unhealthy_longhorn_volume
  ((longhorn_disks == 0)) || fail duplicate_longhorn_disk_uuid
  ((longhorn_replicas == 0)) || fail colocated_longhorn_replicas
  ((cnpg == 0)) || fail unhealthy_cnpg_cluster
}

check_worker_capacity() {
  local host node expected_feature row available used_percent
  while read -r host node expected_feature; do
    row=$(sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 \
      "$SSH_USER@$host" "df -B1 --output=avail,pcent / | tail -n 1" 2>/dev/null) ||
      fail capacity_snapshot_unavailable "$host"
    read -r available used_percent <<<"$row"
    used_percent=${used_percent%%%}
    [[ $available =~ ^[0-9]+$ && $used_percent =~ ^[0-9]+$ ]] ||
      fail invalid_capacity_snapshot "$host"
    if ((available < MINIMUM_ROOT_AVAILABLE_BYTES || used_percent > MAXIMUM_ROOT_USED_PERCENT)); then
      printf 'checked_at=%s\nhost=%s\navailable_bytes=%s\nused_percent=%s\nminimum_available_bytes=%s\nmaximum_used_percent=%s\n' \
        "$(date -u +%FT%TZ)" "$host" "$available" "$used_percent" \
        "$MINIMUM_ROOT_AVAILABLE_BYTES" "$MAXIMUM_ROOT_USED_PERCENT" >"$EVIDENCE_ROOT/FAILURE_CAPACITY.txt"
      fail insufficient_worker_capacity "$host"
    fi
  done <"$WORKERS_FILE"
}

check_worker_maintenance() {
  local host node expected_feature states
  local units=(
    unattended-upgrades.service
    apt-daily.timer
    apt-daily-upgrade.timer
  )
  while read -r host node expected_feature; do
    states=$(sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 \
      "$SSH_USER@$host" "systemctl is-enabled ${units[*]} 2>/dev/null" 2>/dev/null) ||
      fail maintenance_snapshot_unavailable "$host"
    [[ $(wc -l <<<"$states") -eq ${#units[@]} ]] ||
      fail invalid_maintenance_snapshot "$host"
    while read -r state; do
      if [[ $state != masked && $state != masked-runtime ]]; then
        printf 'checked_at=%s\nhost=%s\nunits=%s\nstates=%s\n' \
          "$(date -u +%FT%TZ)" "$host" "${units[*]}" \
          "$(tr '\n' ',' <<<"$states" | sed 's/,$//')" \
          >"$EVIDENCE_ROOT/FAILURE_MAINTENANCE.txt"
        fail package_maintenance_guard_lost "$host"
      fi
    done <<<"$states"
  done <"$WORKERS_FILE"
}

while true; do
  check_cluster_health
  check_worker_capacity
  check_worker_maintenance
  while read -r host _node expected_feature; do
    snapshot=$(printf '%s\n' "$SSHPASS" | sshpass -e ssh \
      -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" \
      "sudo -S bash -c 'source /etc/sentinel-pulse-detector-candidate.env; printf \"collector=%s\\nlegacy=%s\\ndetector=%s\\nrestarts=%s\\ndecisions=%s\\nalerts=%s\\nfeature=%s\\n\" \"\$(systemctl is-active sentinel-pulse-collector-500ms-experiment)\" \"\$(systemctl is-active sentinel-pulse-collector)\" \"\$(systemctl is-active sentinel-pulse-detector-candidate)\" \"\$(systemctl show sentinel-pulse-detector-candidate -p NRestarts --value)\" \"\$(wc -l < \"\$PULSE_DECISIONS\")\" \"\$(wc -l < \"\$PULSE_ALERTS\")\" \"\$PULSE_FEATURES\"'" 2>/dev/null) || fail ssh_unreachable "$host"
    value() { sed -n "s/^$1=//p" <<<"$snapshot"; }
    collector=$(value collector); legacy=$(value legacy); detector=$(value detector)
    restarts=$(value restarts); decisions=$(value decisions)
    alerts=$(value alerts); feature=$(value feature)
    [[ $restarts =~ ^[0-9]+$ && $decisions =~ ^[0-9]+$ && $alerts =~ ^[0-9]+$ ]] || fail invalid_snapshot "$host"
    write_row "$host" "$collector" "$legacy" "$detector" "$restarts" "$decisions" "$alerts" "$feature" "$expected_feature"
    [[ $collector == active ]] || fail collector_inactive "$host"
    [[ $legacy == inactive ]] || fail legacy_control_collector_active "$host"
    [[ $detector == active ]] || fail detector_inactive "$host"
    ((restarts == 0)) || fail detector_restarted "$host"
    ((alerts == 0)) || fail normal_alert_observed "$host"
    [[ $feature == "$expected_feature" ]] || fail feature_source_mismatch "$host"
  done <"$WORKERS_FILE"
  now=$(date +%s)
  if ((now >= ${eligible_epoch%.*})); then
    printf 'ready_at=%s\n' "$(date -u +%FT%TZ)" >"$EVIDENCE_ROOT/READY_TO_FINALIZE"
    exit 0
  fi
  sleep "$POLL_SECONDS"
done
