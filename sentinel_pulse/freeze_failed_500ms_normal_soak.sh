#!/usr/bin/env bash
# Preserve a terminally failed formal soak without evaluating or tuning it.
set -euo pipefail

EVIDENCE_ROOT=${1:?usage: freeze_failed_500ms_normal_soak.sh EVIDENCE_ROOT}
SSH_USER=${SSH_USER:-dat}
REMOTE_ROOT=${REMOTE_ROOT:-/home/dat/eBPF-project}
MARKER="$EVIDENCE_ROOT/SOAK_START.json"
WORKERS_FILE="$EVIDENCE_ROOT/workers.txt"
FAILURE_ROOT="$EVIDENCE_ROOT/infrastructure-failure"

: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
command -v sshpass >/dev/null
command -v jq >/dev/null
command -v tar >/dev/null
test -f "$MARKER"
test -f "$WORKERS_FILE"
test -f "$EVIDENCE_ROOT/FAILED"
test ! -e "$EVIDENCE_ROOT/ACTIVE"
test ! -e "$EVIDENCE_ROOT/NORMAL_PASS"
test ! -e "$EVIDENCE_ROOT/ARCHIVE_COMPLETE"
mkdir -p "$FAILURE_ROOT/workers"

remote_sudo() {
  local host=$1; shift
  printf '%s\n' "$SSHPASS" | sshpass -e ssh \
    -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" \
    "sudo -S -p '' $*"
}

run_id=$(jq -er '.run_id' "$MARKER")
model_sha=$(jq -er '.model_manifest_sha256' "$MARKER")
policy_sha=$(jq -er '.decision_policy_sha256' "$MARKER")
started_at=$(jq -er '.started_not_before' "$MARKER")

while read -r host node expected_feature; do
  [[ $expected_feature == "/var/lib/sentinel-pulse-500ms/runs/$run_id/features.jsonl" ]]
  capture_dir=${expected_feature%/features.jsonl}
  detector_dir="/var/lib/sentinel-pulse-detector/runs/$model_sha-$policy_sha-$run_id"
  node_root="$FAILURE_ROOT/workers/$host"
  mkdir -p "$node_root"

  # Quiesce first. The raw streams are rejected evidence and must never be fed
  # to training, tuning, normal-gate evaluation, or blind-attack evaluation.
  remote_sudo "$host" systemctl stop sentinel-pulse-detector-candidate.service \
    sentinel-pulse-collector-500ms-experiment.service >/dev/null 2>&1 || true
  remote_sudo "$host" systemctl show \
    sentinel-pulse-resolver.service sentinel-pulse-collector.service \
    sentinel-pulse-collector-500ms-experiment.service \
    sentinel-pulse-detector-candidate.service \
    -p Id -p ActiveState -p SubState -p Result -p NRestarts \
    >"$node_root/systemd-before-reset.txt"
  remote_sudo "$host" journalctl \
    -u containerd.service -u sentinel-pulse-resolver.service \
    -u sentinel-pulse-collector.service \
    -u sentinel-pulse-collector-500ms-experiment.service \
    -u sentinel-pulse-detector-candidate.service \
    --since "$started_at" --no-pager -o short-iso \
    >"$node_root/journal.txt"
  remote_sudo "$host" sh -c \
    "'test ! -f /var/log/unattended-upgrades/unattended-upgrades-dpkg.log || cp /var/log/unattended-upgrades/unattended-upgrades-dpkg.log /tmp/$run_id-unattended.log'"
  sshpass -e scp -q -o StrictHostKeyChecking=no \
    "$SSH_USER@$host:/tmp/$run_id-unattended.log" \
    "$node_root/unattended-upgrades-dpkg.log" 2>/dev/null || true
  remote_sudo "$host" rm -f "/tmp/$run_id-unattended.log" || true

  # The node finalizer deliberately returns non-zero for a failed service but
  # still emits validation and FINAL.json; retain both outcomes as evidence.
  remote_sudo "$host" env MINIMUM_ROWS_PER_WORKLOAD=20 \
    "$REMOTE_ROOT/sentinel_pulse/finalize_500ms_experiment.sh" \
    >"$node_root/node-finalize.json" 2>"$node_root/node-finalize.stderr" || true
  remote_sudo "$host" test -s "$capture_dir/FINAL.json"
  remote_sudo "$host" test -s "$detector_dir/decisions.jsonl"
  remote_sudo "$host" chmod -R a-w "$capture_dir" \
    "$detector_dir"

  # Stream a compressed, self-contained copy; do not delete remote originals.
  # A validated archive is a resume checkpoint after a control-plane process
  # interruption, while a partial .tmp is always overwritten.
  if [[ ! -s "$node_root/raw.tar.gz" ]] || \
     ! tar -tzf "$node_root/raw.tar.gz" >/dev/null 2>&1; then
    printf '%s\n' "$SSHPASS" | sshpass -e ssh \
      -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" \
      "sudo -S -p '' tar -C / -czf - '${capture_dir#/}' '${detector_dir#/}'" \
      >"$node_root/raw.tar.gz.tmp"
    mv "$node_root/raw.tar.gz.tmp" "$node_root/raw.tar.gz"
  fi
  tar -tzf "$node_root/raw.tar.gz" >/dev/null
  remote_sudo "$host" systemctl reset-failed \
    sentinel-pulse-collector-500ms-experiment.service \
    sentinel-pulse-detector-candidate.service || true
done <"$WORKERS_FILE"

python3 - "$EVIDENCE_ROOT" "$FAILURE_ROOT/DISPOSITION.json" <<'PY'
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

root = Path(sys.argv[1])
out = Path(sys.argv[2])
marker = json.loads((root / "SOAK_START.json").read_text(encoding="utf-8"))
failed = dict(
    line.split("=", 1)
    for line in (root / "FAILED").read_text(encoding="utf-8").splitlines()
    if "=" in line
)
last = {}
for line in (root / "MONITOR.jsonl").read_text(encoding="utf-8").splitlines():
    row = json.loads(line)
    last[row["host"]] = row
payload = {
    "schema": "sentinel-pulse-failed-soak-disposition-v1",
    "run_id": marker["run_id"],
    "terminal_run_status": "rejected_infrastructure_failure",
    "candidate_status": "not_evaluated_by_this_run",
    "failed": failed,
    "last_monitor_snapshot_by_host": last,
    "observed_alerts_before_failure": sum(row["alerts"] for row in last.values()),
    "root_cause": {
        "class": "dependency_restart_propagation",
        "trigger": "unattended-upgrades restarted containerd.service",
        "mechanism": "hard systemd dependencies stopped the finite collector",
    },
    "data_use": {
        "normal_gate": False,
        "training": False,
        "tuning": False,
        "blind_attack": False,
    },
    "archived_at": datetime.now(timezone.utc).isoformat(),
}
out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

(
  cd "$EVIDENCE_ROOT"
  # Runtime log is intentionally outside the immutable evidence index because
  # stdout keeps appending until after this script exits. Temporary streams are
  # likewise never evidence.
  find . -type f ! -name RAW_SHA256SUMS ! -name ARCHIVE_COMPLETE \
    ! -name archive.log ! -name '*.tmp' \
    -print0 | sort -z | xargs -0 sha256sum
) >"$EVIDENCE_ROOT/RAW_SHA256SUMS"
(cd "$EVIDENCE_ROOT" && sha256sum -c RAW_SHA256SUMS)
printf 'archived_at=%s\nautomatic_promotion=false\n' "$(date -u +%FT%TZ)" \
  >"$EVIDENCE_ROOT/ARCHIVE_COMPLETE"
printf 'failed soak archived without evaluation: %s\n' "$EVIDENCE_ROOT"
