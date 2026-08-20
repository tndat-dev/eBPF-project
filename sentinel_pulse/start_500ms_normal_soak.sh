#!/usr/bin/env bash
# Preregister and start a non-promoting 25-hour Pulse live-normal soak.
set -euo pipefail

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
REMOTE_ROOT=${REMOTE_ROOT:-/home/dat/eBPF-project}
MODEL_SOURCE=${MODEL_SOURCE:?MODEL_SOURCE must be an absolute candidate directory}
POLICY_SOURCE=${POLICY_SOURCE:-$LOCAL_ROOT/sentinel_pulse/protocol/decision-policy-semantic-v4.json}
RUN_ID=${RUN_ID:-pulse500-normal-soak-$(date -u +%Y%m%dT%H%M%SZ)}
DURATION_SECONDS=${DURATION_SECONDS:-90000}
MINIMUM_DURATION_HOURS=${MINIMUM_DURATION_HOURS:-24}
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
[[ $MODEL_SOURCE == "$LOCAL_ROOT"/* ]] || {
  echo "MODEL_SOURCE must be contained by LOCAL_ROOT" >&2; exit 2;
}
[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "RUN_ID contains unsafe characters" >&2; exit 2;
}
[[ $DURATION_SECONDS =~ ^[0-9]+$ ]] && ((DURATION_SECONDS >= 86400 && DURATION_SECONDS <= 90000)) || {
  echo "formal soak duration must be 86400..90000 seconds" >&2; exit 2;
}
test -f "$MODEL_SOURCE/manifest.json"
test -f "$MODEL_SOURCE/manifest.sha256"
test -f "$POLICY_SOURCE"
test ! -e "$EVIDENCE_ROOT"
mkdir -p "$EVIDENCE_ROOT"

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

ready=$(kubectl get nodes --no-headers | awk '$2 ~ /^Ready/ {n++} END {print n+0}')
total=$(kubectl get nodes --no-headers | wc -l)
[[ $ready -eq 6 && $total -eq 6 ]] || {
  echo "cluster is not 6/6 Ready" >&2; exit 3;
}

model_rel=${MODEL_SOURCE#"$LOCAL_ROOT/"}
model_sha=$(sha256sum "$MODEL_SOURCE/manifest.json" | awk '{print $1}')
policy_sha=$(sha256sum "$POLICY_SOURCE" | awk '{print $1}')
source_commit=$(git -C "$LOCAL_ROOT" rev-parse HEAD)
source_dirty=$(git -C "$LOCAL_ROOT" status --porcelain --untracked-files=no)
[[ -z $source_dirty ]] || { echo "tracked source worktree is dirty" >&2; exit 3; }

for target in "${WORKERS[@]}"; do
  IFS='|' read -r host expected_name <<<"$target"
  observed=$(remote "$host" hostname -f)
  [[ $observed == "$expected_name" ]] || {
    echo "hostname mismatch for $host: $observed" >&2; exit 3;
  }
  remote "$host" \
    "systemctl is-active --quiet sentinel-pulse-resolver sentinel-pulse-collector && ! systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment && ! systemctl is-active --quiet sentinel-pulse-detector-candidate"
done

# The marker exists before any experimental collector or detector starts.
python3 - "$EVIDENCE_ROOT/SOAK_START.json" "$RUN_ID" "$model_sha" \
  "$policy_sha" "$source_commit" "$MINIMUM_DURATION_HOURS" <<'PY'
from datetime import datetime, timedelta, timezone
import json, pathlib, sys
out, run_id, model, policy, commit, hours = sys.argv[1:]
started = datetime.now(timezone.utc)
payload = {
    "schema": "sentinel-pulse-semantic-soak-start-v5",
    "run_id": run_id,
    "model_manifest_sha256": model,
    "decision_policy_sha256": policy,
    "source_git_commit": commit,
    "blind_evaluation_started": False,
    "automatic_promotion": False,
    "maximum_alerts": 0,
    "minimum_duration_hours_per_workload": float(hours),
    "minimum_coverage_ratio_per_workload": 0.95,
    "started_not_before": started.isoformat(),
    "eligible_finalize_after": (started + timedelta(hours=float(hours))).isoformat(),
}
pathlib.Path(out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY

started_hosts=()
launch_complete=false
cleanup() {
  local rc=$?
  if [[ $launch_complete != true ]]; then
    for host in "${started_hosts[@]}"; do
      remote_sudo "$host" systemctl stop sentinel-pulse-detector-candidate.service \
        sentinel-pulse-collector-500ms-experiment.service >/dev/null 2>&1 || true
    done
    printf 'launch_failed_at=%s\nexit_code=%s\n' "$(date -u +%FT%TZ)" "$rc" \
      >"$EVIDENCE_ROOT/FAILED"
  fi
}
trap cleanup EXIT

for target in "${WORKERS[@]}"; do
  IFS='|' read -r host node <<<"$target"
  remote "$host" "mkdir -p '$REMOTE_ROOT/sentinel_pulse' '$REMOTE_ROOT/$(dirname "$model_rel")'"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$LOCAL_ROOT/sentinel_pulse/" "$SSH_USER@$host:$REMOTE_ROOT/sentinel_pulse/"
  rsync -a --checksum -e "sshpass -e ssh -o StrictHostKeyChecking=no" \
    "$MODEL_SOURCE/" "$SSH_USER@$host:$REMOTE_ROOT/$model_rel/"
  remote "$host" \
    "cd '$REMOTE_ROOT/$model_rel' && sha256sum -c manifest.sha256"
  started_hosts+=("$host")
  remote_sudo "$host" env SOURCE_ROOT="$REMOTE_ROOT" RUN_ID="$RUN_ID" \
    DURATION_SECONDS="$DURATION_SECONDS" \
    "$REMOTE_ROOT/sentinel_pulse/install_500ms_experiment.sh"
  feature="/var/lib/sentinel-pulse-500ms/runs/$RUN_ID/features.jsonl"
  remote_sudo "$host" env SOURCE_ROOT="$REMOTE_ROOT" \
    MODEL_SOURCE="$REMOTE_ROOT/$model_rel" FEATURE_SOURCE="$feature" \
    DEPLOYMENT_ID="$RUN_ID" \
    "$REMOTE_ROOT/sentinel_pulse/install_detector_candidate.sh"
  remote "$host" \
    "grep -Fx 'PULSE_FEATURES=$feature' /etc/sentinel-pulse-detector-candidate.env && systemctl is-active --quiet sentinel-pulse-collector-500ms-experiment sentinel-pulse-detector-candidate"
  printf '%s %s %s\n' "$host" "$node" "$feature" >>"$EVIDENCE_ROOT/workers.txt"
done

sha256sum "$EVIDENCE_ROOT/SOAK_START.json" "$MODEL_SOURCE/manifest.json" \
  "$POLICY_SOURCE" >"$EVIDENCE_ROOT/START_SHA256SUMS"
touch "$EVIDENCE_ROOT/ACTIVE"
launch_complete=true
printf 'formal normal soak active: run=%s duration=%ss evidence=%s\n' \
  "$RUN_ID" "$DURATION_SECONDS" "$EVIDENCE_ROOT"
