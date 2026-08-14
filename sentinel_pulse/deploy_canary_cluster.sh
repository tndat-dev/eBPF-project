#!/usr/bin/env bash
# Canary-first collect-only rollout. Run from a terminal with SSH access.
set -euo pipefail

LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
REMOTE_ROOT=${REMOTE_ROOT:-/home/dat/eBPF-project}
SSH_USER=${SSH_USER:-dat}
CANARY_HOST=${CANARY_HOST:-10.1.16.237}
CANARY_NAME=${CANARY_NAME:-k8s-worker1.local}
REMAINING_HOSTS=${REMAINING_HOSTS:-"10.1.16.238 10.1.16.239"}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-$LOCAL_ROOT/validation-evidence/sentinel-pulse-canary}
SSH_OPTIONS=(-o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3)

command -v rsync >/dev/null
command -v ssh >/dev/null
command -v scp >/dev/null
mkdir -p "$EVIDENCE_ROOT"

sync_node() {
  local host=$1
  ssh "${SSH_OPTIONS[@]}" "$SSH_USER@$host" "mkdir -p '$REMOTE_ROOT'"
  rsync -a --checksum \
    -e "ssh ${SSH_OPTIONS[*]}" \
    "$LOCAL_ROOT/sentinel_pulse/" \
    "$SSH_USER@$host:$REMOTE_ROOT/sentinel_pulse/"
}

install_node() {
  local host=$1
  ssh -tt "${SSH_OPTIONS[@]}" "$SSH_USER@$host" \
    "sudo env SOURCE_ROOT='$REMOTE_ROOT' '$REMOTE_ROOT/sentinel_pulse/install_node.sh'"
}

remote_hostname=$(ssh "${SSH_OPTIONS[@]}" "$SSH_USER@$CANARY_HOST" 'hostname -f')
if [[ "$remote_hostname" != "$CANARY_NAME" ]]; then
  printf 'canary hostname mismatch: expected=%s observed=%s\n' \
    "$CANARY_NAME" "$remote_hostname" >&2
  exit 1
fi

sync_node "$CANARY_HOST"
install_node "$CANARY_HOST"
ssh -tt "${SSH_OPTIONS[@]}" "$SSH_USER@$CANARY_HOST" \
  "sudo '$REMOTE_ROOT/sentinel_pulse/smoke_node.sh'"
scp "${SSH_OPTIONS[@]}" \
  "$SSH_USER@$CANARY_HOST:/var/lib/sentinel-pulse/collect-smoke.json" \
  "$EVIDENCE_ROOT/$CANARY_NAME.json"

python3 - "$EVIDENCE_ROOT/$CANARY_NAME.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
if report.get("schema") != "sentinel-pulse-collect-smoke-v1" or report.get("valid") is not True:
    raise SystemExit("canary report is invalid; refusing remaining-worker rollout")
PY

for host in $REMAINING_HOSTS; do
  sync_node "$host"
  install_node "$host"
  case "$host" in
    10.1.16.238) node_name=k8s-worker4.local ;;
    10.1.16.239) node_name=k8s-worker3.local ;;
    *) printf 'unknown remaining worker: %s\n' "$host" >&2; exit 1 ;;
  esac
  ssh -tt "${SSH_OPTIONS[@]}" "$SSH_USER@$host" \
    "sudo '$REMOTE_ROOT/sentinel_pulse/smoke_node.sh'"
  scp "${SSH_OPTIONS[@]}" \
    "$SSH_USER@$host:/var/lib/sentinel-pulse/collect-smoke.json" \
    "$EVIDENCE_ROOT/$node_name.json"
done

(
  cd "$LOCAL_ROOT"
  python3 -m sentinel_pulse.validate_rollout \
    --report "$EVIDENCE_ROOT/k8s-worker1.local.json" \
    --report "$EVIDENCE_ROOT/k8s-worker4.local.json" \
    --report "$EVIDENCE_ROOT/k8s-worker3.local.json" \
    --output "$EVIDENCE_ROOT/rollout-validation.json"
)

printf 'Sentinel Pulse collect-only rollout complete: canary=%s remaining=%s\n' \
  "$CANARY_HOST" "$REMAINING_HOSTS"
