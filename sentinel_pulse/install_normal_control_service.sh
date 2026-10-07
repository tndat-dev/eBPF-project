#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'run as root' >&2; exit 2; }
SOURCE_ROOT=${SOURCE_ROOT:?clean controller checkout required}
CONFIG=${CONFIG:?existing frozen attack config required}
ATTACK_ROOT=${ATTACK_ROOT:?existing attack campaign required}
OUTPUT_ROOT=${OUTPUT_ROOT:?new paired normal control root required}
RESULTS_ROOT=${RESULTS_ROOT:?separate final report root required}
CREDENTIAL=${CREDENTIAL:?private credential file required}
for path in "$SOURCE_ROOT" "$CONFIG" "$ATTACK_ROOT" "$OUTPUT_ROOT" "$RESULTS_ROOT" "$CREDENTIAL"; do
  [[ $path =~ ^/home/dat/[A-Za-z0-9._/-]+$ && $path != *'/../'* ]] || exit 2
done
test -f "$CONFIG"
test -f "$ATTACK_ROOT/START.json"
test -f "$CREDENTIAL"
[[ $(stat -c %a "$CREDENTIAL") == 600 ]]
if systemctl is-active --quiet sentinel-pulse-normal-control.service; then
  echo 'normal control service already running; refusing replacement' >&2
  exit 3
fi
install -d -m 0750 /etc/sentinel-pulse
env_stage=$(mktemp /etc/sentinel-pulse/.normal-control.XXXXXX)
trap 'rm -f -- "$env_stage"' EXIT
printf 'PULSE_CONTROL_SOURCE=%s\nPULSE_CONTROL_CONFIG=%s\nPULSE_CONTROL_ATTACK_ROOT=%s\nPULSE_CONTROL_ROOT=%s\nPULSE_CONTROL_RESULTS=%s\nPULSE_CONTROL_CREDENTIAL=%s\n' \
  "$SOURCE_ROOT" "$CONFIG" "$ATTACK_ROOT" "$OUTPUT_ROOT" "$RESULTS_ROOT" "$CREDENTIAL" >"$env_stage"
install -m 0640 "$env_stage" /etc/sentinel-pulse/normal-control.env
install -m 0644 "$SOURCE_ROOT/sentinel_pulse/systemd/sentinel-pulse-normal-control.service" \
  /etc/systemd/system/sentinel-pulse-normal-control.service
systemctl daemon-reload
systemctl enable --now --no-block sentinel-pulse-normal-control.service
