#!/usr/bin/env bash
set -euo pipefail
url="${URL:?set URL, e.g. http://10.1.16.235:30082/}"
if command -v wrk >/dev/null; then
  wrk -t4 -c50 -d30s "$url" | tee "${OUT:-wrk-$(date +%s).txt}"
else
  ab -n 10000 -c 10 -k "$url" | tee "${OUT:-ab-$(date +%s).txt}"
fi
