#!/usr/bin/env bash
set -euo pipefail
out="${1:-metrics-$(date -u +%Y%m%dT%H%M%SZ)}.log"
duration="${DURATION_SECONDS:-300}"
end=$(( $(date +%s) + duration ))
while [ "$(date +%s)" -lt "$end" ]; do
  printf '\n# %s\n' "$(date -u +%FT%TZ)" >> "$out"
  kubectl top pods -A --containers >> "$out" 2>&1 || true
  kubectl top nodes >> "$out" 2>&1 || true
  sleep "${INTERVAL_SECONDS:-5}"
done
echo "wrote $out"
