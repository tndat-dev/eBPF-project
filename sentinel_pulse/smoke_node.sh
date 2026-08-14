#!/usr/bin/env bash
# Run after install_node.sh on one worker; exits non-zero on any canary gate.
set -euo pipefail

CAPTURE=${CAPTURE:-/var/lib/sentinel-pulse/features.jsonl}
OUTPUT=${OUTPUT:-/var/lib/sentinel-pulse/collect-smoke.json}
WAIT_SECONDS=${WAIT_SECONDS:-125}

systemctl is-active --quiet sentinel-pulse-resolver.service
systemctl is-active --quiet sentinel-pulse-collector.service
sleep "$WAIT_SECONDS"
(
  cd /opt/sentinel-pulse
  /opt/sentinel-pulse/venv/bin/python -m sentinel_pulse.smoke_collect \
    --capture "$CAPTURE" \
    --output "$OUTPUT" \
    --duration-seconds 120 \
    --maximum-age-seconds 5 \
    --maximum-ingest-p99-seconds 0.30 \
    --maximum-snapshot-p99-seconds 0.30
)
cat "$OUTPUT"
