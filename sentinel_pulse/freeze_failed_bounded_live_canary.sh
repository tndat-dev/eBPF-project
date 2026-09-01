#!/usr/bin/env bash
# Stop and checksum-archive a bounded normal run that has already violated its gate.
set -Eeuo pipefail

EVIDENCE_ROOT=${1:?usage: freeze_failed_bounded_live_canary.sh EVIDENCE_ROOT}
LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
SSH_USER=${SSH_USER:-dat}
: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"

test -f "$EVIDENCE_ROOT/ACTIVE"
test -f "$EVIDENCE_ROOT/START.json"
test -f "$EVIDENCE_ROOT/workers.txt"
test ! -e "$EVIDENCE_ROOT/FAILED_COMPLETE"
(cd "$EVIDENCE_ROOT" && sha256sum -c START_SHA256SUMS)

RUN_ID=$(jq -er '.run_id' "$EVIDENCE_ROOT/START.json")
[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
remote() { local host=$1; shift; sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" "$@"; }
remote_sudo() { local host=$1; shift; printf '%s\n' "$SSHPASS" | sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" "sudo -S -p '' $*"; }

mkdir -p "$EVIDENCE_ROOT/nodes"
while read -r host node unit; do
  remote_sudo "$host" systemctl stop sentinel-pulse-collector-500ms-experiment.service
  deadline=$(( $(date +%s) + 300 ))
  while :; do
    if remote_sudo "$host" "test ! -e '/var/lib/sentinel-pulse-500ms/runs/$RUN_ID/CANARY_COMPLETE' -a ! -e '/var/lib/sentinel-pulse-500ms/runs/$RUN_ID/CANARY_FAILED.txt'"; then
      (( $(date +%s) < deadline )) || {
        echo "worker finalizer did not become terminal: $node" >&2
        exit 1
      }
      sleep 2
      continue
    fi
    break
  done
  remote_sudo "$host" systemctl stop sentinel-pulse-detector-candidate.service
  remote_sudo "$host" systemctl disable sentinel-pulse-detector-candidate.service
  remote_sudo "$host" sh -c \
    "'! systemctl is-active --quiet sentinel-pulse-detector-candidate.service sentinel-pulse-collector-500ms-experiment.service'"
  destination="$EVIDENCE_ROOT/nodes/$node"
  mkdir -p "$destination"
  printf '%s\n' "$SSHPASS" | sshpass -e ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=8 "$SSH_USER@$host" \
    "sudo -S -p '' tar -C '/var/lib/sentinel-pulse-500ms/runs/$RUN_ID' -cf - ." | \
    tar -C "$destination" -xf -
done <"$EVIDENCE_ROOT/workers.txt"

PYTHONPATH="$LOCAL_ROOT" /home/dat/ml-venv/bin/python - \
  "$EVIDENCE_ROOT" <<'PY'
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
start = json.loads((root / "START.json").read_text(encoding="utf-8"))
nodes = {}
total_alerts = 0
total_decisions = 0
for node_root in sorted((root / "nodes").iterdir()):
    decisions_path = node_root / "decisions.jsonl"
    alerts_path = node_root / "alerts.jsonl"
    decisions = sum(1 for line in decisions_path.open() if line.strip())
    alerts = sum(1 for line in alerts_path.open() if line.strip())
    terminal = (
        "failed_gate" if (node_root / "CANARY_FAILED.txt").exists()
        else "complete" if (node_root / "CANARY_COMPLETE").exists()
        else "missing"
    )
    if terminal == "missing":
        raise ValueError(f"node has no terminal canary marker: {node_root.name}")
    nodes[node_root.name] = {
        "terminal": terminal,
        "decisions": decisions,
        "alerts": alerts,
    }
    total_decisions += decisions
    total_alerts += alerts
if total_alerts:
    failure_class = "normal_alert_observed"
    candidate_status = "rejected_normal_gate"
    disposition = "development normal failure; candidate must not be promoted"
else:
    failure_class = "infrastructure_or_evidence_failure"
    candidate_status = "not_evaluated_by_this_run"
    disposition = (
        "terminal infrastructure/evidence failure without an observed alert; "
        "candidate must not be evaluated or promoted from this run"
    )
report = {
    "schema": "sentinel-pulse-bounded-normal-failure-v1",
    "created_at": datetime.now(timezone.utc).isoformat(),
    "run_id": start["run_id"],
    "model_manifest_sha256": start["model_manifest_sha256"],
    "decision_policy_sha256": start["decision_policy_sha256"],
    "normal_only": True,
    "failure_class": failure_class,
    "candidate_status": candidate_status,
    "valid_zero_alert_gate": False if total_alerts else None,
    "accuracy_claim_allowed": False,
    "automatic_promotion": False,
    "decisions": total_decisions,
    "alerts": total_alerts,
    "nodes": nodes,
    "disposition": disposition,
}
(root / "FAILED_SUMMARY.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

(
  cd "$EVIDENCE_ROOT"
  find nodes -type f -print0 | sort -z | xargs -0 sha256sum
  sha256sum FAILED_SUMMARY.json START.json workers.txt START_SHA256SUMS
) >"$EVIDENCE_ROOT/FAILED_FINAL_SHA256SUMS"
(cd "$EVIDENCE_ROOT" && sha256sum -c FAILED_FINAL_SHA256SUMS)
touch "$EVIDENCE_ROOT/FAILED_COMPLETE"
rm -f "$EVIDENCE_ROOT/ACTIVE"
chmod 0444 "$EVIDENCE_ROOT/FAILED_SUMMARY.json" \
  "$EVIDENCE_ROOT/FAILED_FINAL_SHA256SUMS" "$EVIDENCE_ROOT/FAILED_COMPLETE"
printf 'failed bounded normal run archived: %s\n' "$EVIDENCE_ROOT"
