#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'run as root' >&2; exit 2; }
SOURCE_ROOT=${SOURCE_ROOT:?pinned clean exploratory checkout required}
DATASET=${DATASET:?original normal-only training dataset required}
MODEL=${MODEL:?read-only frozen model required}
ANALYSIS=${ANALYSIS:?verified independent normal analysis required}
OUTPUT_ROOT=${OUTPUT_ROOT:?separate exploratory result root required}
for path in "$SOURCE_ROOT" "$DATASET" "$MODEL" "$ANALYSIS" "$OUTPUT_ROOT"; do
  [[ $path =~ ^/home/dat/[A-Za-z0-9._/-]+$ && $path != *'/../'* ]] || exit 2
done
test -f "$DATASET"
test -f "$MODEL/manifest.json"
test -f "$ANALYSIS"
test -f "$SOURCE_ROOT/sentinel_pulse/support_experiment.py"
[[ -z $(git -C "$SOURCE_ROOT" status --porcelain --untracked-files=all) ]]
if systemctl is-active --quiet sentinel-pulse-support-experiment.service; then
  echo 'experiment already active; refusing replacement' >&2
  exit 3
fi
# A completed/registered experiment can only resume from the same source and
# inputs: START verification happens in the program before loading sequences.
install -d -m 0750 /etc/sentinel-pulse
env_stage=$(mktemp /etc/sentinel-pulse/.support-experiment.XXXXXX)
trap 'rm -f -- "$env_stage"' EXIT
printf 'PULSE_SUPPORT_SOURCE=%s\nPULSE_SUPPORT_DATASET=%s\nPULSE_SUPPORT_MODEL=%s\nPULSE_SUPPORT_ANALYSIS=%s\nPULSE_SUPPORT_ROOT=%s\n' \
  "$SOURCE_ROOT" "$DATASET" "$MODEL" "$ANALYSIS" "$OUTPUT_ROOT" >"$env_stage"
install -m 0640 "$env_stage" /etc/sentinel-pulse/support-experiment.env
install -m 0644 "$SOURCE_ROOT/sentinel_pulse/systemd/sentinel-pulse-support-experiment.service" \
  /etc/systemd/system/sentinel-pulse-support-experiment.service
systemctl daemon-reload
systemctl enable --now --no-block sentinel-pulse-support-experiment.service
