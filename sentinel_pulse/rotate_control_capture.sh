#!/usr/bin/env bash
# Rotate the unbounded one-second control stream without touching frozen runs.
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "rotate_control_capture.sh must run as root" >&2
  exit 2
fi

SERVICE=sentinel-pulse-collector.service
STATE_ROOT=/var/lib/sentinel-pulse
CAPTURE=$STATE_ROOT/features.jsonl
ARCHIVE_ROOT=$STATE_ROOT/archive
MINIMUM_BYTES=${MINIMUM_BYTES:-1048576}

[[ $MINIMUM_BYTES =~ ^[0-9]+$ ]] || {
  echo "MINIMUM_BYTES must be an integer" >&2
  exit 2
}

# A bounded research run owns its source until its finalizer freezes it. Do not
# create an unregistered source boundary while any experiment or detector is on.
for unit in sentinel-pulse-collector-500ms-experiment.service \
  sentinel-pulse-detector-candidate.service; do
  if systemctl is-active --quiet "$unit"; then
    echo "rotation skipped: $unit is active"
    exit 0
  fi
done

systemctl is-active --quiet "$SERVICE"
test -f "$CAPTURE"
bytes=$(stat -c %s "$CAPTURE")
if ((bytes < MINIMUM_BYTES)); then
  echo "rotation skipped: capture is only $bytes bytes"
  exit 0
fi

install -d -m 0750 "$ARCHIVE_ROOT"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
archive="$ARCHIVE_ROOT/features-$stamp.jsonl"
manifest="$ARCHIVE_ROOT/features-$stamp.manifest"
test ! -e "$archive"
test ! -e "$archive.gz"

restore() {
  if ! systemctl is-active --quiet "$SERVICE"; then
    systemctl start "$SERVICE" || true
  fi
}
trap restore EXIT

systemctl stop "$SERVICE"
mv "$CAPTURE" "$archive"
systemctl start "$SERVICE"
for _attempt in $(seq 1 30); do
  if systemctl is-active --quiet "$SERVICE" && test -s "$CAPTURE"; then
    break
  fi
  sleep 1
done
systemctl is-active --quiet "$SERVICE"
test -s "$CAPTURE"

capture_sha=$(sha256sum "$archive" | awk '{print $1}')
{
  printf 'schema=sentinel-pulse-control-archive-v1\n'
  printf 'rotated_at=%s\n' "$(date -u +%FT%TZ)"
  printf 'source=%s\n' "$CAPTURE"
  printf 'uncompressed_bytes=%s\n' "$bytes"
  printf 'uncompressed_sha256=%s\n' "$capture_sha"
} >"$manifest"
gzip -1 "$archive"
gzip_sha=$(sha256sum "$archive.gz" | awk '{print $1}')
printf 'gzip_bytes=%s\ngzip_sha256=%s\n' \
  "$(stat -c %s "$archive.gz")" "$gzip_sha" >>"$manifest"
chmod 0440 "$archive.gz" "$manifest"
trap - EXIT
printf 'rotated=%s archive=%s manifest=%s\n' "$bytes" "$archive.gz" "$manifest"
