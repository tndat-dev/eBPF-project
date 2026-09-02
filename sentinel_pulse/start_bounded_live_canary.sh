#!/usr/bin/env bash
# Start a bounded, non-formal normal canary on all three workers.
set -Eeuo pipefail

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
MODEL_SOURCE=${MODEL_SOURCE:?point to the frozen candidate model directory}
POLICY_SOURCE=${POLICY_SOURCE:?point to the frozen bounded policy}
EVIDENCE_ROOT=${EVIDENCE_ROOT:?choose a new control-plane evidence directory}
RUN_ID=${RUN_ID:-sentinel-pulse-bounded-canary-$(date -u +%Y%m%dT%H%M%SZ)}
DURATION_SECONDS=${DURATION_SECONDS:-900}
SSH_USER=${SSH_USER:-dat}
: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"

[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $DURATION_SECONDS =~ ^[1-9][0-9]*$ ]]
(( DURATION_SECONDS >= 300 && DURATION_SECONDS <= 90000 ))
[[ $EVIDENCE_ROOT == /home/dat/sentinel-pulse-evidence/* ]]
test ! -e "$EVIDENCE_ROOT"
test -f "$MODEL_SOURCE/manifest.json"
test -f "$MODEL_SOURCE/manifest.sha256"
test -f "$POLICY_SOURCE"
for command in jq rsync sshpass sha256sum tar; do command -v "$command" >/dev/null; done

# Verify every model artifact before touching collector services on any worker.
# An archived canary may intentionally retain only manifest metadata and is not
# a deployable model bundle even when its manifest checksum is valid.
PYTHONPATH="$LOCAL_ROOT" /home/dat/ml-venv/bin/python - "$MODEL_SOURCE" <<'PY'
from pathlib import Path
import sys
from sentinel_pulse.finalize_candidate import verify_model_bundle

verify_model_bundle(Path(sys.argv[1]))
PY

MODEL_SHA256=$(awk '$2=="manifest.json" {print $1}' "$MODEL_SOURCE/manifest.sha256")
POLICY_SHA256=$(sha256sum "$POLICY_SOURCE" | awk '{print $1}')
[[ $MODEL_SHA256 =~ ^[0-9a-f]{64}$ ]]
[[ $POLICY_SHA256 =~ ^[0-9a-f]{64}$ ]]
PYTHONPATH="$LOCAL_ROOT" /home/dat/ml-venv/bin/python - "$POLICY_SOURCE" <<'PY'
from pathlib import Path
import sys
from sentinel_pulse.decision_policy import load_decision_policy
policy, _ = load_decision_policy(Path(sys.argv[1]))
assert policy["schema"] == "sentinel-pulse-decision-policy-v3"
assert policy["blind_outcome_used"] is False
assert policy["automatic_promotion"] is False
assert policy["bounded_event_time_corroboration"]["maximum_evidence_age_seconds"] <= 2.0
PY

workers=(
  "10.1.16.237|k8s-worker1.local"
  "10.1.16.239|k8s-worker3.local"
  "10.1.16.238|k8s-worker4.local"
)
REMOTE_ROOT="/home/dat/sentinel-pulse-bounded-canary-$RUN_ID"
remote() { local host=$1; shift; sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" "$@"; }
remote_sudo() { local host=$1; shift; printf '%s\n' "$SSHPASS" | sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" "sudo -S -p '' $*"; }

# Fail before mutation if cluster/workload/worker state is unsuitable.
[[ $(kubectl get nodes --no-headers | awk '$2=="Ready" {n++} END {print n+0}') -eq 6 ]]
[[ $(kubectl get pods -n production --no-headers | awk '$3=="Running" {split($2,a,"/"); if(a[1]==a[2]) n++} END {print n+0}') -eq 42 ]]
for target in "${workers[@]}"; do
  IFS='|' read -r host node <<<"$target"
  [[ $(remote "$host" hostname -f) == "$node" ]]
  remote "$host" "systemctl is-active --quiet sentinel-pulse-resolver sentinel-pulse-collector && ! systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment && ! systemctl is-active --quiet sentinel-pulse-detector-candidate"
done

mkdir -p "$EVIDENCE_ROOT/protocol" "$EVIDENCE_ROOT/model"
install -m 0444 "$POLICY_SOURCE" "$EVIDENCE_ROOT/protocol/decision-policy.json"
install -m 0444 "$MODEL_SOURCE/manifest.json" "$MODEL_SOURCE/manifest.sha256" "$EVIDENCE_ROOT/model/"
printf '%s\n' "${workers[@]}" >"$EVIDENCE_ROOT/workers.plan"
(
  cd "$LOCAL_ROOT"
  find sentinel_pulse -type f ! -path '*/__pycache__/*' ! -name '*.pyc' \
    -print0 | sort -z | xargs -0 sha256sum
) >"$EVIDENCE_ROOT/SOURCE_SHA256SUMS"

START_PATH="$EVIDENCE_ROOT/START.json" RUN_VALUE="$RUN_ID" MODEL_VALUE="$MODEL_SHA256" \
POLICY_VALUE="$POLICY_SHA256" DURATION_VALUE="$DURATION_SECONDS" REMOTE_VALUE="$REMOTE_ROOT" \
/home/dat/ml-venv/bin/python - <<'PY'
from datetime import datetime, timezone
import json, os
from pathlib import Path
payload = {
    "schema": "sentinel-pulse-bounded-live-canary-start-v1",
    "started_at": datetime.now(timezone.utc).isoformat(),
    "run_id": os.environ["RUN_VALUE"],
    "evidence_class": "nonformal_live_normal_canary",
    "normal_only": True,
    "blind_outcome_used": False,
    "automatic_promotion": False,
    "duration_seconds": int(os.environ["DURATION_VALUE"]),
    "model_manifest_sha256": os.environ["MODEL_VALUE"],
    "decision_policy_sha256": os.environ["POLICY_VALUE"],
    "remote_source_root": os.environ["REMOTE_VALUE"],
}
Path(os.environ["START_PATH"]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY

started=()
complete=false
cleanup() {
  local rc=$?
  if [[ $complete != true ]]; then
    for host in "${started[@]}"; do
      remote_sudo "$host" systemctl stop "sentinel-pulse-bounded-canary-finalize-${RUN_ID}.service" sentinel-pulse-detector-candidate.service sentinel-pulse-collector-500ms-experiment.service >/dev/null 2>&1 || true
      remote_sudo "$host" systemctl disable sentinel-pulse-detector-candidate.service >/dev/null 2>&1 || true
      remote_sudo "$host" systemctl start sentinel-pulse-collector.service >/dev/null 2>&1 || true
    done
    printf 'failed_at=%s\nexit_code=%s\n' "$(date -u +%FT%TZ)" "$rc" >"$EVIDENCE_ROOT/START_FAILED"
  fi
}
trap cleanup EXIT

: >"$EVIDENCE_ROOT/workers.txt"
for target in "${workers[@]}"; do
  IFS='|' read -r host node <<<"$target"
  remote "$host" "mkdir -p '$REMOTE_ROOT/sentinel_pulse' '$REMOTE_ROOT/model'"
  rsync -a --checksum --exclude='__pycache__' --exclude='*.pyc' \
    -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$LOCAL_ROOT/sentinel_pulse/" "$SSH_USER@$host:$REMOTE_ROOT/sentinel_pulse/"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$MODEL_SOURCE/" "$SSH_USER@$host:$REMOTE_ROOT/model/"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$POLICY_SOURCE" "$SSH_USER@$host:$REMOTE_ROOT/decision-policy.json"
  started+=("$host")
  remote_sudo "$host" env SOURCE_ROOT="$REMOTE_ROOT" RUN_ID="$RUN_ID" DURATION_SECONDS="$DURATION_SECONDS" "$REMOTE_ROOT/sentinel_pulse/install_500ms_experiment.sh"
  feature="/var/lib/sentinel-pulse-500ms/runs/$RUN_ID/features.jsonl"
  remote_sudo "$host" env SOURCE_ROOT="$REMOTE_ROOT" MODEL_SOURCE="$REMOTE_ROOT/model" DECISION_POLICY_SOURCE="$REMOTE_ROOT/decision-policy.json" FEATURE_SOURCE="$feature" DEPLOYMENT_ID="$RUN_ID" ENABLE_INJECTION_TRACKING=false "$REMOTE_ROOT/sentinel_pulse/install_detector_candidate.sh"
  unit="sentinel-pulse-bounded-canary-finalize-${RUN_ID}"
  printf '%s %s %s\n' "$host" "$node" "$unit" >>"$EVIDENCE_ROOT/workers.txt"
  remote_sudo "$host" systemd-run --no-block --unit="$unit" --property=Type=oneshot env RUN_ID="$RUN_ID" EXPECTED_MODEL_SHA256="$MODEL_SHA256" EXPECTED_POLICY_SHA256="$POLICY_SHA256" SOURCE_ROOT="$REMOTE_ROOT" WAIT_TIMEOUT_SECONDS="$((DURATION_SECONDS + 300))" "$REMOTE_ROOT/sentinel_pulse/finalize_live_canary.sh"
done

(
  cd "$EVIDENCE_ROOT"
  sha256sum START.json workers.plan workers.txt protocol/decision-policy.json \
    model/manifest.json model/manifest.sha256 SOURCE_SHA256SUMS
) >"$EVIDENCE_ROOT/START_SHA256SUMS"
(cd "$EVIDENCE_ROOT" && sha256sum -c START_SHA256SUMS)
touch "$EVIDENCE_ROOT/ACTIVE"
chmod 0444 "$EVIDENCE_ROOT"/START.json "$EVIDENCE_ROOT"/workers.plan \
  "$EVIDENCE_ROOT"/workers.txt "$EVIDENCE_ROOT"/*SHA256SUMS
complete=true
printf 'bounded live canary active: run=%s duration=%ss evidence=%s\n' "$RUN_ID" "$DURATION_SECONDS" "$EVIDENCE_ROOT"
