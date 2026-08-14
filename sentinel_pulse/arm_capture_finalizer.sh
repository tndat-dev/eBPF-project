#!/usr/bin/env bash
# Install and arm the persistent per-node campaign finalizer.
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "arm_capture_finalizer.sh must run as root" >&2
  exit 2
fi
if (( $# != 4 )); then
  echo "usage: arm_capture_finalizer.sh CAMPAIGN_ID START_EPOCH END_EPOCH CONTRACT_SHA256" >&2
  exit 2
fi

CAMPAIGN_ID=$1
CAMPAIGN_START_EPOCH=$2
CAMPAIGN_END_EPOCH=$3
CONTRACT_SHA256=$4
[[ "$CAMPAIGN_ID" =~ ^[A-Za-z0-9._-]+$ ]]
[[ "$CAMPAIGN_START_EPOCH" =~ ^[0-9]+$ ]]
[[ "$CAMPAIGN_END_EPOCH" =~ ^[0-9]+$ ]]
[[ "$CONTRACT_SHA256" =~ ^[0-9a-f]{64}$ ]]

SOURCE_ROOT=${SOURCE_ROOT:-/home/dat/eBPF-project}
PULSE_SOURCE="$SOURCE_ROOT/sentinel_pulse"
CONFIG_ROOT=/etc/sentinel-pulse/campaigns
CONFIG="$CONFIG_ROOT/$CAMPAIGN_ID.env"
UNIT="sentinel-pulse-freeze@$CAMPAIGN_ID.service"

test -x "$PULSE_SOURCE/finalize_capture_node.sh"
install -d -m 0755 /opt/sentinel-pulse/sentinel_pulse "$CONFIG_ROOT"
install -m 0755 "$PULSE_SOURCE/finalize_capture_node.sh" \
  /opt/sentinel-pulse/sentinel_pulse/finalize_capture_node.sh
install -m 0644 "$PULSE_SOURCE/systemd/sentinel-pulse-freeze@.service" \
  /etc/systemd/system/sentinel-pulse-freeze@.service

temporary=$(mktemp "$CONFIG_ROOT/.$CAMPAIGN_ID.env.XXXXXX")
trap 'rm -f "$temporary"' EXIT
{
  printf 'CAMPAIGN_ID=%s\n' "$CAMPAIGN_ID"
  printf 'CAMPAIGN_START_EPOCH=%s\n' "$CAMPAIGN_START_EPOCH"
  printf 'CAMPAIGN_END_EPOCH=%s\n' "$CAMPAIGN_END_EPOCH"
  printf 'CONTRACT_SHA256=%s\n' "$CONTRACT_SHA256"
} >"$temporary"
chmod 0600 "$temporary"
if [[ -e "$CONFIG" ]] && ! cmp -s "$temporary" "$CONFIG"; then
  echo "refusing to replace different campaign config: $CONFIG" >&2
  exit 1
fi
install -m 0600 "$temporary" "$CONFIG"
rm -f "$temporary"
trap - EXIT

systemctl daemon-reload
systemctl enable --now "$UNIT"
systemctl is-active --quiet "$UNIT"
systemctl --no-pager --full status "$UNIT"
