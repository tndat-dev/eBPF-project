#!/usr/bin/env bash
# Freeze one immutable node capture after the preregistered campaign interval.
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "finalize_capture_node.sh must run as root" >&2
  exit 2
fi

: "${CAMPAIGN_ID:?missing CAMPAIGN_ID}"
: "${CAMPAIGN_START_EPOCH:?missing CAMPAIGN_START_EPOCH}"
: "${CAMPAIGN_END_EPOCH:?missing CAMPAIGN_END_EPOCH}"
: "${CONTRACT_SHA256:?missing CONTRACT_SHA256}"
[[ "$CAMPAIGN_ID" =~ ^[A-Za-z0-9._-]+$ ]]
[[ "$CAMPAIGN_START_EPOCH" =~ ^[0-9]+$ ]]
[[ "$CAMPAIGN_END_EPOCH" =~ ^[0-9]+$ ]]
[[ "$CONTRACT_SHA256" =~ ^[0-9a-f]{64}$ ]]
(( CAMPAIGN_END_EPOCH > CAMPAIGN_START_EPOCH ))

FREEZE_GRACE_SECONDS=${FREEZE_GRACE_SECONDS:-10}
STATE_ROOT=${STATE_ROOT:-/var/lib/sentinel-pulse}
ACTIVE_CAPTURE="$STATE_ROOT/features.jsonl"
CAMPAIGN_DIR="$STATE_ROOT/campaigns/$CAMPAIGN_ID"
FROZEN_CAPTURE="$CAMPAIGN_DIR/features.jsonl"
MANIFEST="$CAMPAIGN_DIR/capture-manifest.json"
MARKER="$CAMPAIGN_DIR/CAPTURE_FROZEN"
freeze_at=$((CAMPAIGN_END_EPOCH + FREEZE_GRACE_SECONDS))

mkdir -p "$CAMPAIGN_DIR"
if [[ -s "$MARKER" && -s "$MANIFEST" && -s "$FROZEN_CAPTURE" ]]; then
  exit 0
fi

while (( $(date +%s) < freeze_at )); do
  systemctl is-active --quiet sentinel-pulse-resolver.service
  systemctl is-active --quiet sentinel-pulse-collector.service
  remaining=$((freeze_at - $(date +%s)))
  (( remaining > 60 )) && sleep 60 || sleep "$remaining"
done

collector_stopped=false
restart_collector() {
  if [[ "$collector_stopped" == true ]]; then
    systemctl start sentinel-pulse-collector.service || true
  fi
}
trap restart_collector EXIT

if [[ ! -e "$FROZEN_CAPTURE" ]]; then
  systemctl stop sentinel-pulse-collector.service
  collector_stopped=true
  test -s "$ACTIVE_CAPTURE"
  mv "$ACTIVE_CAPTURE" "$FROZEN_CAPTURE"
  chmod 0444 "$FROZEN_CAPTURE"
  systemctl start sentinel-pulse-collector.service
  collector_stopped=false
fi

systemctl is-active --quiet sentinel-pulse-collector.service
for _attempt in $(seq 1 20); do
  [[ -s "$ACTIVE_CAPTURE" ]] && break
  sleep 1
done
test -s "$ACTIVE_CAPTURE"

python3 - "$FROZEN_CAPTURE" "$MANIFEST" "$CAMPAIGN_ID" \
  "$CAMPAIGN_START_EPOCH" "$CAMPAIGN_END_EPOCH" "$CONTRACT_SHA256" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time

capture = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
campaign_id = sys.argv[3]
start = float(sys.argv[4])
end = float(sys.argv[5])
contract_sha256 = sys.argv[6]

digest = hashlib.sha256()
rows = 0
in_contract_rows = 0
first_end = None
last_end = None
nodes = set()
max_integrity = {}
with capture.open("rb") as raw:
    for block in iter(lambda: raw.read(1024 * 1024), b""):
        digest.update(block)
with capture.open(encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, 1):
        record = json.loads(line)
        if record.get("schema") == "sentinel-pulse-feature-schema-v1":
            continue
        if record.get("schema") != "sentinel-pulse-feature-v1":
            raise SystemExit(f"unsupported record at line {line_number}")
        rows += 1
        window_start = float(record["window_start"])
        window_end = float(record["window_end"])
        first_end = window_end if first_end is None else min(first_end, window_end)
        last_end = window_end if last_end is None else max(last_end, window_end)
        nodes.add(str(record.get("node_name", "")))
        if window_start >= start and window_end <= end:
            in_contract_rows += 1
            for name, value in record.get("collector_stats", {}).items():
                max_integrity[name] = max(max_integrity.get(name, 0), int(value))

hostname = socket.gethostname()
if nodes != {hostname}:
    raise SystemExit(f"capture node identity mismatch: hostname={hostname} rows={nodes}")
if not in_contract_rows:
    raise SystemExit("frozen capture has no in-contract feature row")
if last_end is None or last_end < end:
    raise SystemExit(f"capture ended before contract: last={last_end} end={end}")
bad_integrity = {name: value for name, value in max_integrity.items() if value != 0}
if bad_integrity:
    raise SystemExit(f"non-zero in-contract integrity counters: {bad_integrity}")

manifest = {
    "schema": "sentinel-pulse-node-capture-manifest-v1",
    "campaign_id": campaign_id,
    "contract_sha256": contract_sha256,
    "node_name": hostname,
    "capture": str(capture),
    "capture_sha256": digest.hexdigest(),
    "capture_bytes": capture.stat().st_size,
    "rows": rows,
    "in_contract_rows": in_contract_rows,
    "first_window_end": first_end,
    "last_window_end": last_end,
    "campaign_start": start,
    "campaign_end": end,
    "collector_max_integrity": dict(sorted(max_integrity.items())),
    "frozen_at": time.time(),
}
temporary = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(temporary, manifest_path)
PY

sha256sum "$FROZEN_CAPTURE" >"$CAMPAIGN_DIR/features.jsonl.sha256"
date -u +%FT%TZ >"$MARKER"
chmod 0444 "$MANIFEST" "$CAMPAIGN_DIR/features.jsonl.sha256" "$MARKER"
trap - EXIT
