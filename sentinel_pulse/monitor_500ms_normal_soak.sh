#!/usr/bin/env bash
# Read-only fail-closed monitor for a preregistered Pulse normal soak.
set -u

EVIDENCE_ROOT=${1:?usage: monitor_500ms_normal_soak.sh EVIDENCE_ROOT}
SSH_USER=${SSH_USER:-dat}
POLL_SECONDS=${POLL_SECONDS:-60}
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
host, collector, detector, restarts, decisions, alerts, feature, expected = sys.argv[2:]
row={
    "checked_at_unix": time.time(), "host": host,
    "collector": collector, "detector": detector,
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
  kubectl -n production get clusters.postgresql.cnpg.io -o json \
    >"$EVIDENCE_ROOT/FAILURE_CNPG_CLUSTERS.json" 2>/dev/null || true
  printf 'failed_at=%s\nreason=%s\nhost=%s\n' \
    "$(date -u +%FT%TZ)" "$reason" "$host" >"$EVIDENCE_ROOT/FAILED"
  rm -f "$EVIDENCE_ROOT/ACTIVE"
  exit 1
}

check_cluster_health() {
  local nodes pods longhorn cnpg
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
  cnpg=$(kubectl -n production get clusters.postgresql.cnpg.io -o json \
    2>/dev/null | jq '[.items[] | select(
      (.status.readyInstances // 0) != (.status.instances // .spec.instances // 0)
      or (.status.phase // "") != "Cluster in healthy state"
    )] | length') || fail cnpg_health_unavailable
  ((nodes == 0)) || fail unhealthy_kubernetes_node
  ((pods == 0)) || fail unhealthy_production_pod
  ((longhorn == 0)) || fail unhealthy_longhorn_volume
  ((cnpg == 0)) || fail unhealthy_cnpg_cluster
}

while true; do
  check_cluster_health
  while read -r host _node expected_feature; do
    snapshot=$(printf '%s\n' "$SSHPASS" | sshpass -e ssh \
      -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" \
      "sudo -S bash -c 'source /etc/sentinel-pulse-detector-candidate.env; printf \"collector=%s\\ndetector=%s\\nrestarts=%s\\ndecisions=%s\\nalerts=%s\\nfeature=%s\\n\" \"\$(systemctl is-active sentinel-pulse-collector-500ms-experiment)\" \"\$(systemctl is-active sentinel-pulse-detector-candidate)\" \"\$(systemctl show sentinel-pulse-detector-candidate -p NRestarts --value)\" \"\$(wc -l < \"\$PULSE_DECISIONS\")\" \"\$(wc -l < \"\$PULSE_ALERTS\")\" \"\$PULSE_FEATURES\"'" 2>/dev/null) || fail ssh_unreachable "$host"
    value() { sed -n "s/^$1=//p" <<<"$snapshot"; }
    collector=$(value collector); detector=$(value detector)
    restarts=$(value restarts); decisions=$(value decisions)
    alerts=$(value alerts); feature=$(value feature)
    [[ $restarts =~ ^[0-9]+$ && $decisions =~ ^[0-9]+$ && $alerts =~ ^[0-9]+$ ]] || fail invalid_snapshot "$host"
    write_row "$host" "$collector" "$detector" "$restarts" "$decisions" "$alerts" "$feature" "$expected_feature"
    [[ $collector == active ]] || fail collector_inactive "$host"
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
