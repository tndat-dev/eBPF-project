#!/usr/bin/env bash
# Collect and aggregate a terminal bounded live canary without promotion.
set -Eeuo pipefail

EVIDENCE_ROOT=${1:?usage: collect_bounded_live_canary.sh EVIDENCE_ROOT}
LOCAL_ROOT=${LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
SSH_USER=${SSH_USER:-dat}
: "${SSHPASS:?export SSHPASS for SSH and sudo authentication}"
test -f "$EVIDENCE_ROOT/ACTIVE"
test -f "$EVIDENCE_ROOT/START.json"
test -f "$EVIDENCE_ROOT/workers.txt"
test ! -e "$EVIDENCE_ROOT/AGGREGATE.json"
(cd "$EVIDENCE_ROOT" && sha256sum -c START_SHA256SUMS)

RUN_ID=$(jq -er '.run_id' "$EVIDENCE_ROOT/START.json")
MODEL_SHA256=$(jq -er '.model_manifest_sha256' "$EVIDENCE_ROOT/START.json")
POLICY_SHA256=$(jq -er '.decision_policy_sha256' "$EVIDENCE_ROOT/START.json")
remote() { local host=$1; shift; sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" "$@"; }
remote_sudo() { local host=$1; shift; printf '%s\n' "$SSHPASS" | sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" "sudo -S -p '' $*"; }

mkdir -p "$EVIDENCE_ROOT/nodes"
node_args=()
while read -r host node unit; do
  remote_sudo "$host" "test -f '/var/lib/sentinel-pulse-500ms/runs/$RUN_ID/CANARY_COMPLETE' && ! systemctl is-active --quiet sentinel-pulse-detector-candidate sentinel-pulse-collector-500ms-experiment"
  destination="$EVIDENCE_ROOT/nodes/$node"
  mkdir -p "$destination"
  printf '%s\n' "$SSHPASS" | sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 "$SSH_USER@$host" \
    "sudo -S -p '' tar -C '/var/lib/sentinel-pulse-500ms/runs/$RUN_ID' -cf - ." | \
    tar -C "$destination" -xf -
  (cd "$destination" && sha256sum -c CANARY_SHA256SUMS)
  node_args+=(--node-root "$node=$destination")
done <"$EVIDENCE_ROOT/workers.txt"

PYTHONPATH="$LOCAL_ROOT" /home/dat/ml-venv/bin/python -m sentinel_pulse.aggregate_live_canary \
  "${node_args[@]}" --expected-model "$MODEL_SHA256" \
  --expected-policy "$POLICY_SHA256" --output "$EVIDENCE_ROOT/AGGREGATE.json"
(
  cd "$EVIDENCE_ROOT"
  find nodes -type f -print0 | sort -z | xargs -0 sha256sum
  sha256sum AGGREGATE.json START.json workers.txt START_SHA256SUMS
) >"$EVIDENCE_ROOT/FINAL_SHA256SUMS"
(cd "$EVIDENCE_ROOT" && sha256sum -c FINAL_SHA256SUMS)
touch "$EVIDENCE_ROOT/CANARY_COMPLETE"
rm -f "$EVIDENCE_ROOT/ACTIVE"
chmod 0444 "$EVIDENCE_ROOT"/AGGREGATE.json "$EVIDENCE_ROOT"/FINAL_SHA256SUMS \
  "$EVIDENCE_ROOT"/CANARY_COMPLETE
printf 'bounded live canary collected: %s\n' "$EVIDENCE_ROOT"
