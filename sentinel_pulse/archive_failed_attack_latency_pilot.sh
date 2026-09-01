#!/usr/bin/env bash
# Archive raw worker streams after a terminal pilot infrastructure failure.
set -Eeuo pipefail

EVIDENCE_ROOT=${1:?usage: archive_failed_attack_latency_pilot.sh EVIDENCE_ROOT}
SSH_USER=${SSH_USER:-dat}
: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
for command in sshpass tar jq sha256sum; do command -v "$command" >/dev/null; done
test -f "$EVIDENCE_ROOT/FAILURE_TERMINAL.json"
test -f "$EVIDENCE_ROOT/FAILURE_SHA256SUMS"
test -f "$EVIDENCE_ROOT/workers.txt"
test ! -e "$EVIDENCE_ROOT/ACTIVE"
test ! -e "$EVIDENCE_ROOT/FAILURE_ARCHIVE.json"
(cd "$EVIDENCE_ROOT" && sha256sum -c FAILURE_SHA256SUMS)

remote_root=$(jq -er '.remote_source_root' "$EVIDENCE_ROOT/BLIND_START.json")
[[ $remote_root == /home/dat/sentinel-pulse-attack-pilot-* ]]

remote_sudo() {
  local host=$1; shift
  printf '%s\n' "$SSHPASS" | sshpass -e ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=8 "$SSH_USER@$host" "sudo -S -p '' $*"
}

mkdir -p "$EVIDENCE_ROOT/workers-failure-archive"
while read -r host node feature injections; do
  [[ $feature == /var/lib/sentinel-pulse-500ms/runs/*/features.jsonl ]]
  [[ $injections == /var/lib/sentinel-pulse-detector/runs/*/injections.jsonl ]]
  remote_sudo "$host" bash -c \
    "'! systemctl is-active --quiet sentinel-pulse-detector-candidate.service && ! systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment.service'"
  capture_dir=$(dirname "$feature")
  detector_dir=$(dirname "$injections")
  if ! remote_sudo "$host" test -f "$capture_dir/FINAL.json"; then
    remote_sudo "$host" env MINIMUM_ROWS_PER_WORKLOAD=20 \
      "$remote_root/sentinel_pulse/finalize_500ms_experiment.sh" \
      >"$EVIDENCE_ROOT/workers-failure-archive/$host-node-finalize.json"
  fi
  destination="$EVIDENCE_ROOT/workers-failure-archive/$node/raw"
  mkdir -p "$destination"
  printf '%s\n' "$SSHPASS" | sshpass -e ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=8 "$SSH_USER@$host" \
    "sudo -S -p '' tar -C / -cf - '${capture_dir#/}' '${detector_dir#/}'" | \
    tar -C "$destination" -xf -
  test -s "$destination/${capture_dir#/}/features.jsonl"
  test -s "$destination/${detector_dir#/}/decisions.jsonl"
  test -f "$destination/${detector_dir#/}/alerts.jsonl"
  # A small pilot can legitimately schedule no completed attack on a worker.
  # Preserve the empty detector marker file; only the distributed union must
  # match the controller log for completed trials.
  test -f "$destination/${detector_dir#/}/injections.jsonl"
done <"$EVIDENCE_ROOT/workers.txt"

(
  cd "$EVIDENCE_ROOT"
  find workers-failure-archive -type f -print0 | sort -z | xargs -0 sha256sum
) >"$EVIDENCE_ROOT/FAILURE_RAW_SHA256SUMS"
(cd "$EVIDENCE_ROOT" && sha256sum -c FAILURE_RAW_SHA256SUMS)

python3 - "$EVIDENCE_ROOT" <<'PY'
from datetime import datetime, timezone
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
partial_path = root / "REPORT.partial.json"
partial = json.loads(partial_path.read_text()) if partial_path.exists() else {
    "completed_injections": 0, "detected_injections": 0,
}
marker_path = root / "injections.jsonl"
markers = (
    sum(1 for line in marker_path.open() if line.strip())
    if marker_path.exists() else 0
)
payload = {
    "schema": "sentinel-pulse-attack-latency-pilot-failure-archive-v1",
    "archived_at": datetime.now(timezone.utc).isoformat(),
    "evidence_class": "nonformal_attack_latency_pilot_infrastructure_failure",
    "accuracy_claim_allowed": False,
    "automatic_rerun": False,
    "automatic_promotion": False,
    "completed_injections": int(partial.get("completed_injections", 0)),
    "detected_injections": int(partial.get("detected_injections", 0)),
    "controller_markers": markers,
    "markers_without_completed_attack": markers - int(partial.get("completed_injections", 0)),
    "raw_checksum_index_sha256": hashlib.sha256(
        (root / "FAILURE_RAW_SHA256SUMS").read_bytes()
    ).hexdigest(),
}
(root / "FAILURE_ARCHIVE.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
(
  cd "$EVIDENCE_ROOT"
  sha256sum FAILURE_TERMINAL.json FAILURE_SHA256SUMS \
    FAILURE_RAW_SHA256SUMS FAILURE_ARCHIVE.json > FAILURE_ARCHIVE_SHA256SUMS
)
(cd "$EVIDENCE_ROOT" && sha256sum -c FAILURE_ARCHIVE_SHA256SUMS)
chmod 0444 "$EVIDENCE_ROOT/FAILURE_RAW_SHA256SUMS" \
  "$EVIDENCE_ROOT/FAILURE_ARCHIVE.json" "$EVIDENCE_ROOT/FAILURE_ARCHIVE_SHA256SUMS"
printf 'Failed pilot raw streams archived: %s\n' "$EVIDENCE_ROOT"
