#!/usr/bin/env bash
# Install the boot-persistent controller; credentials are referenced, not embedded.
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'run as root' >&2; exit 2; }
SOURCE_ROOT=${SOURCE_ROOT:?clean controller/worker checkout required}
CONFIG=${CONFIG:?explicit three-worker config required}
NORMAL_ROOT=${NORMAL_ROOT:?completed observation campaign root required}
OUTPUT_ROOT=${OUTPUT_ROOT:?new attack evidence root required}
CREDENTIAL=${CREDENTIAL:?mode-0600 credential file required}
for path in "$SOURCE_ROOT" "$CONFIG" "$NORMAL_ROOT" "$OUTPUT_ROOT" "$CREDENTIAL"; do
  [[ $path =~ ^/home/dat/[A-Za-z0-9._/-]+$ && $path != *'/../'* ]] || exit 2
done
test -f "$CONFIG"
test -f "$NORMAL_ROOT/START.json"
test -f "$NORMAL_ROOT/TERMINAL.json"
test -f "$CREDENTIAL"
[[ $(stat -c %a "$CREDENTIAL") == 600 ]]
if systemctl is-active --quiet sentinel-pulse-observation-attack.service; then
  echo 'attack service is already active; refusing to replace registration' >&2
  exit 3
fi
install -d -m 0750 /etc/sentinel-pulse
env_stage=$(mktemp /etc/sentinel-pulse/.observation-attack.XXXXXX)
trap 'rm -f -- "$env_stage"' EXIT
printf 'PULSE_ATTACK_SOURCE=%s\nPULSE_ATTACK_CONFIG=%s\nPULSE_ATTACK_NORMAL_ROOT=%s\nPULSE_ATTACK_ROOT=%s\nPULSE_ATTACK_CREDENTIAL=%s\n' \
  "$SOURCE_ROOT" "$CONFIG" "$NORMAL_ROOT" "$OUTPUT_ROOT" "$CREDENTIAL" >"$env_stage"
install -m 0640 "$env_stage" /etc/sentinel-pulse/observation-attack.env
install -m 0644 "$SOURCE_ROOT/sentinel_pulse/systemd/sentinel-pulse-observation-attack.service" \
  /etc/systemd/system/sentinel-pulse-observation-attack.service
systemctl daemon-reload
systemctl enable --now --no-block sentinel-pulse-observation-attack.service
