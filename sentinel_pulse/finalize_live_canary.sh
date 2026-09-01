#!/usr/bin/env bash
# Finalize one bounded, non-formal live normal canary. Never promotes a model.
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "finalize_live_canary.sh must run as root" >&2
  exit 2
fi

: "${RUN_ID:?RUN_ID is required}"
: "${EXPECTED_MODEL_SHA256:?EXPECTED_MODEL_SHA256 is required}"
: "${EXPECTED_POLICY_SHA256:?EXPECTED_POLICY_SHA256 is required}"
SOURCE_ROOT=${SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
WAIT_TIMEOUT_SECONDS=${WAIT_TIMEOUT_SECONDS:-1200}
COLLECTOR=sentinel-pulse-collector-500ms-experiment.service
DETECTOR=sentinel-pulse-detector-candidate.service
DETECTOR_ENV=/etc/sentinel-pulse-detector-candidate.env
RUN_DIR=/var/lib/sentinel-pulse-500ms/runs/$RUN_ID

[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $EXPECTED_MODEL_SHA256 =~ ^[0-9a-f]{64}$ ]]
[[ $EXPECTED_POLICY_SHA256 =~ ^[0-9a-f]{64}$ ]]
[[ $WAIT_TIMEOUT_SECONDS =~ ^[1-9][0-9]*$ ]]
test -d "$RUN_DIR"
test -f "$DETECTOR_ENV"

failure() {
  local rc=$?
  trap - ERR
  printf 'failed_at=%s\nexit_code=%s\nline=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$rc" "${BASH_LINENO[0]:-unknown}" \
    > "$RUN_DIR/CANARY_FAILED.txt"
  chmod 0444 "$RUN_DIR/CANARY_FAILED.txt"
  systemctl stop "$DETECTOR" 2>/dev/null || true
  systemctl disable "$DETECTOR" 2>/dev/null || true
  exit "$rc"
}
trap failure ERR

deadline=$(( $(date +%s) + WAIT_TIMEOUT_SECONDS ))
while systemctl is-active --quiet "$COLLECTOR"; do
  (( $(date +%s) < deadline ))
  sleep 5
done

# Root-owned installer generated this file from validated paths and identifiers.
# shellcheck disable=SC1090
source "$DETECTOR_ENV"
[[ $PULSE_RUN_ID == "$RUN_ID" ]]
[[ $PULSE_FEATURES == "$RUN_DIR/features.jsonl" ]]
case "$PULSE_DECISIONS" in
  /var/lib/sentinel-pulse-detector/runs/*/decisions.jsonl) ;;
  *) echo "unsafe detector decision path" >&2; exit 2 ;;
esac
case "$PULSE_ALERTS" in
  /var/lib/sentinel-pulse-detector/runs/*/alerts.jsonl) ;;
  *) echo "unsafe detector alert path" >&2; exit 2 ;;
esac

systemctl show "$DETECTOR" \
  -p ActiveState -p SubState -p NRestarts -p Result -p ExecMainStatus \
  -p CPUUsageNSec -p MemoryCurrent -p MemoryPeak -p TasksCurrent \
  > "$RUN_DIR/detector-before-stop.systemd"
systemctl stop "$DETECTOR"
systemctl disable "$DETECTOR"
systemctl show "$DETECTOR" \
  -p ActiveState -p SubState -p NRestarts -p Result -p ExecMainStatus \
  -p CPUUsageNSec -p MemoryCurrent -p MemoryPeak -p TasksCurrent \
  > "$RUN_DIR/detector-final.systemd"

install -m 0640 "$PULSE_DECISIONS" "$RUN_DIR/decisions.jsonl"
if [[ -e $PULSE_ALERTS ]]; then
  install -m 0640 "$PULSE_ALERTS" "$RUN_DIR/alerts.jsonl"
else
  install -m 0640 /dev/null "$RUN_DIR/alerts.jsonl"
fi

MINIMUM_ROWS_PER_WORKLOAD=20 \
  bash "$SOURCE_ROOT/sentinel_pulse/finalize_500ms_experiment.sh" \
  > "$RUN_DIR/finalizer-output.json"

/opt/sentinel-pulse/runtime-venv/bin/python - \
  "$RUN_DIR" "$EXPECTED_MODEL_SHA256" "$EXPECTED_POLICY_SHA256" <<'PY'
from collections import Counter
import json
from pathlib import Path
import sys
import numpy as np

root = Path(sys.argv[1])
expected_model, expected_policy = sys.argv[2:]
decisions = []
with (root / "decisions.jsonl").open(encoding="utf-8") as source:
    for line in source:
        decisions.append(json.loads(line))

def distribution(values):
    if not values:
        return {"count": 0, "mean": None, "p50": None, "p95": None,
                "p99": None, "max": None}
    data = np.asarray(values, dtype=np.float64)
    return {
        "count": len(values),
        "mean": float(np.mean(data)),
        "p50": float(np.quantile(data, 0.50)),
        "p95": float(np.quantile(data, 0.95)),
        "p99": float(np.quantile(data, 0.99)),
        "max": float(np.max(data)),
    }

def properties(path):
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            result[key] = value
    return result

final = json.loads((root / "FINAL.json").read_text(encoding="utf-8"))
detector = properties(root / "detector-before-stop.systemd")
statuses = Counter(str(row.get("status")) for row in decisions)
scored = [row for row in decisions if "inference_ms" in row]
node_names = {str(row.get("node_name")) for row in scored if row.get("node_name")}
models = {row.get("model_manifest_sha256") for row in decisions}
policies = {row.get("decision_policy_sha256") for row in decisions}
runs = {row.get("run_id") for row in decisions}
alerts = sum(1 for line in (root / "alerts.jsonl").open() if line.strip())
report = {
    "schema": "sentinel-pulse-live-normal-canary-v1",
    "run_id": root.name,
    "evidence_class": "nonformal_live_normal_canary",
    "accuracy_claim_allowed": False,
    "automatic_promotion": False,
    "collector_valid": final.get("valid") is True,
    "collector_duration_seconds": final.get("duration_seconds"),
    "collector_rows": final.get("rows"),
    "collector_workloads": final.get("workload_count"),
    "collector_window_start_to_emit_seconds": final.get(
        "window_start_to_emit_seconds"
    ),
    "collector_max_drops": final.get("collector_max_drops"),
    "decisions": len(decisions),
    "status_counts": dict(sorted(statuses.items())),
    "alerts": alerts,
    "workloads": sorted({str(row.get("workload_key")) for row in decisions}),
    "node_name": next(iter(node_names)) if len(node_names) == 1 else None,
    "model_manifest_sha256": next(iter(models)) if len(models) == 1 else None,
    "decision_policy_sha256": next(iter(policies)) if len(policies) == 1 else None,
    "inference_ms": distribution([
        float(row["inference_ms"]) for row in decisions if "inference_ms" in row
    ]),
    "post_window_processing_seconds": distribution([
        float(row["post_window_processing_seconds"])
        for row in decisions if "post_window_processing_seconds" in row
    ]),
    "window_start_to_alert_seconds": distribution([
        float(row["alerted_at"]) - float(row["window_start"])
        for row in decisions if "alerted_at" in row and "window_start" in row
    ]),
    "detector_restarts": int(detector.get("NRestarts", "0") or 0),
}
# Backward-compatible alias above is retained for old report consumers. This is
# the correct name: alerted_at is the decision timestamp for every scored row.
report["window_start_to_decision_seconds"] = report[
    "window_start_to_alert_seconds"
]
report["valid"] = bool(
    report["collector_valid"]
    and decisions
    and alerts == 0
    and models == {expected_model}
    and policies == {expected_policy}
    and runs == {root.name}
    and len(node_names) == 1
    and report["detector_restarts"] == 0
)
(root / "CANARY.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
raise SystemExit(0 if report["valid"] else 1)
PY

(
  cd "$RUN_DIR"
  sha256sum decisions.jsonl alerts.jsonl detector-before-stop.systemd \
    detector-final.systemd FINAL.json validation.json CANARY.json \
    > CANARY_SHA256SUMS
)
touch "$RUN_DIR/CANARY_COMPLETE"
chmod 0444 "$RUN_DIR"/*
