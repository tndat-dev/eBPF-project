#!/usr/bin/env bash
# Prove a finite Pulse capture survives the dependency restart that invalidated A2.
set -euo pipefail

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
REMOTE_ROOT=${REMOTE_ROOT:-/home/dat/eBPF-project-pulse-resilience}
SSH_USER=${SSH_USER:-dat}
WORKER_HOST=${WORKER_HOST:-10.1.16.237}
EXPECTED_NODE=${EXPECTED_NODE:-k8s-worker1.local}
DURATION_SECONDS=${DURATION_SECONDS:-180}
RUN_ID=${RUN_ID:-pulse500-containerd-restart-$(date -u +%Y%m%dT%H%M%SZ)}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-$LOCAL_ROOT/validation-evidence/sentinel-pulse-campaign/$RUN_ID}

: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $DURATION_SECONDS =~ ^[0-9]+$ ]] && ((DURATION_SECONDS >= 120 && DURATION_SECONDS <= 600))
test ! -e "$EVIDENCE_ROOT"
mkdir -p "$EVIDENCE_ROOT"

remote() {
  sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 \
    "$SSH_USER@$WORKER_HOST" "$@"
}
remote_sudo() {
  printf '%s\n' "$SSHPASS" | sshpass -e ssh \
    -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$WORKER_HOST" \
    "sudo -S -p '' $*"
}

complete=false
cleanup() {
  local rc=$?
  if [[ $complete != true ]]; then
    remote_sudo systemctl stop sentinel-pulse-collector-500ms-experiment.service \
      >/dev/null 2>&1 || true
    printf 'failed_at=%s\nexit_code=%s\n' "$(date -u +%FT%TZ)" "$rc" \
      >"$EVIDENCE_ROOT/FAILED"
  fi
}
trap cleanup EXIT

[[ $(remote hostname -f) == "$EXPECTED_NODE" ]]
kubectl get nodes -o json >"$EVIDENCE_ROOT/nodes-before.json"
kubectl -n production get pods -o json >"$EVIDENCE_ROOT/pods-before.json"
[[ $(kubectl get nodes -o json | PYTHONPATH="$LOCAL_ROOT" python3 \
  -m sentinel_pulse.cluster_health --resource nodes --count) -eq 0 ]]
[[ $(kubectl -n production get pods -o json | PYTHONPATH="$LOCAL_ROOT" python3 \
  -m sentinel_pulse.cluster_health --resource pods --grace-seconds 0 --count) -eq 0 ]]

remote "mkdir -p '$REMOTE_ROOT/sentinel_pulse'"
rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
  "$LOCAL_ROOT/sentinel_pulse/" "$SSH_USER@$WORKER_HOST:$REMOTE_ROOT/sentinel_pulse/"
remote_sudo install -m 0644 \
  "$REMOTE_ROOT/sentinel_pulse/systemd/sentinel-pulse-resolver.service" \
  /etc/systemd/system/sentinel-pulse-resolver.service
remote_sudo install -m 0644 \
  "$REMOTE_ROOT/sentinel_pulse/systemd/sentinel-pulse-collector.service" \
  /etc/systemd/system/sentinel-pulse-collector.service
remote_sudo systemctl daemon-reload
remote "! systemctl show sentinel-pulse-resolver -p Requires --value | grep -qw containerd.service"
remote "! systemctl show sentinel-pulse-collector -p Requires --value | grep -qw sentinel-pulse-resolver.service"
remote "systemctl is-active --quiet sentinel-pulse-resolver sentinel-pulse-collector && ! systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment"

remote_sudo env SOURCE_ROOT="$REMOTE_ROOT" RUN_ID="$RUN_ID" \
  DURATION_SECONDS="$DURATION_SECONDS" \
  "$REMOTE_ROOT/sentinel_pulse/install_500ms_experiment.sh"
feature="/var/lib/sentinel-pulse-500ms/runs/$RUN_ID/features.jsonl"
sleep 15
rows_before=$(remote_sudo wc -l "$feature" | awk '{print $1}')
[[ $rows_before =~ ^[0-9]+$ ]] && ((rows_before > 0))
remote_sudo systemctl restart containerd.service
sleep 15
remote "systemctl is-active --quiet sentinel-pulse-resolver sentinel-pulse-collector sentinel-pulse-collector-500ms-experiment"
rows_after=$(remote_sudo wc -l "$feature" | awk '{print $1}')
[[ $rows_after =~ ^[0-9]+$ ]] && ((rows_after > rows_before))

deadline=$(( $(date +%s) + DURATION_SECONDS + 90 ))
while remote "systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment"; do
  (( $(date +%s) < deadline ))
  sleep 5
done
remote_sudo env MINIMUM_ROWS_PER_WORKLOAD=20 \
  "$REMOTE_ROOT/sentinel_pulse/finalize_500ms_experiment.sh" \
  >"$EVIDENCE_ROOT/FINAL.json"
remote_sudo journalctl -u containerd.service \
  -u sentinel-pulse-resolver.service -u sentinel-pulse-collector.service \
  -u sentinel-pulse-collector-500ms-experiment.service \
  --since "-10 minutes" --no-pager -o short-iso \
  >"$EVIDENCE_ROOT/journal.txt"
kubectl get nodes -o json >"$EVIDENCE_ROOT/nodes-after.json"
kubectl -n production get pods -o json >"$EVIDENCE_ROOT/pods-after.json"
jq -e '.valid == true and .service_ok == true' "$EVIDENCE_ROOT/FINAL.json" >/dev/null
[[ $(kubectl get nodes -o json | PYTHONPATH="$LOCAL_ROOT" python3 \
  -m sentinel_pulse.cluster_health --resource nodes --count) -eq 0 ]]
[[ $(kubectl -n production get pods -o json | PYTHONPATH="$LOCAL_ROOT" python3 \
  -m sentinel_pulse.cluster_health --resource pods --grace-seconds 0 --count) -eq 0 ]]
python3 - "$EVIDENCE_ROOT/RESULT.json" "$RUN_ID" "$WORKER_HOST" \
  "$rows_before" "$rows_after" <<'PY'
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

out, run_id, host, before, after = sys.argv[1:]
payload = {
    "schema": "sentinel-pulse-dependency-restart-canary-v1",
    "run_id": run_id,
    "worker_host": host,
    "dependency_restarted": "containerd.service",
    "collector_active_after_restart": True,
    "rows_before_restart": int(before),
    "rows_after_restart": int(after),
    "rows_progressed_after_restart": int(after) > int(before),
    "cluster_healthy_after_restart": True,
    "passed": True,
    "automatic_promotion": False,
    "completed_at": datetime.now(timezone.utc).isoformat(),
}
Path(out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
sha256sum "$EVIDENCE_ROOT"/FINAL.json "$EVIDENCE_ROOT"/RESULT.json \
  "$EVIDENCE_ROOT"/journal.txt "$EVIDENCE_ROOT"/nodes-before.json \
  "$EVIDENCE_ROOT"/nodes-after.json "$EVIDENCE_ROOT"/pods-before.json \
  "$EVIDENCE_ROOT"/pods-after.json >"$EVIDENCE_ROOT/SHA256SUMS"
complete=true
printf 'dependency restart canary passed: %s\n' "$EVIDENCE_ROOT"
