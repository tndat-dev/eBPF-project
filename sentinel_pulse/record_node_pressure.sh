#!/usr/bin/env bash
# Bounded node-wide scheduler/I/O diagnostics alongside an audit-only canary.
# This observer does not change scheduling, storage, workloads or ML policy.
set -euo pipefail

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'run as root' >&2; exit 2; }
RUN_ID=${RUN_ID:?a unique diagnostic run ID is required}
DURATION_SECONDS=${DURATION_SECONDS:-7800}
[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]]
[[ $DURATION_SECONDS =~ ^[0-9]+$ ]] &&
  ((DURATION_SECONDS >= 60 && DURATION_SECONDS <= 90000))
command -v sar >/dev/null
command -v journalctl >/dev/null
command -v sha256sum >/dev/null

DIAG_ROOT=/var/lib/sentinel-pulse-diagnostics
DIAG_RUN="$DIAG_ROOT/$RUN_ID"
install -d -m 0750 "$DIAG_ROOT"
mkdir -m 0750 "$DIAG_RUN"
STARTED_AT=$(date -u +%FT%TZ)
printf 'run_id=%s\nstarted_at=%s\nhost=%s\nduration_seconds=%s\nsample_seconds=1\n' \
  "$RUN_ID" "$STARTED_AT" "$(hostname -f)" "$DURATION_SECONDS" >"$DIAG_RUN/START.txt"
sar -V >"$DIAG_RUN/sar-version.txt" 2>&1
sha256sum "${BASH_SOURCE[0]}" >"$DIAG_RUN/SOURCE_SHA256SUMS"

snapshot() {
  local tag=$1
  systemctl show sentinel-pulse-collector-500ms-experiment.service \
    sentinel-pulse-detector-candidate.service \
    -p Id -p ActiveState -p NRestarts -p CPUUsageNSec -p MemoryPeak \
    -p CPUQuotaPerSecUSec -p CPUWeight -p MemoryMax \
    >"$DIAG_RUN/services-$tag.txt"
  for kind in cpu io memory; do
    if [[ -r /proc/pressure/$kind ]]; then
      cp "/proc/pressure/$kind" "$DIAG_RUN/pressure-$kind-$tag.txt"
    fi
  done
}

finish() {
  local rc=$?
  trap - EXIT
  set +e
  snapshot final
  journalctl -k --since "$STARTED_AT" --no-pager -o short-iso \
    >"$DIAG_RUN/kernel.txt" 2>"$DIAG_RUN/kernel.stderr"
  local journal_rc=$?
  printf 'finished_at=%s\nexit_code=%s\nkernel_journal_exit_code=%s\n' \
    "$(date -u +%FT%TZ)" "$rc" "$journal_rc" >"$DIAG_RUN/FINAL.txt"
  (cd "$DIAG_RUN" && find . -maxdepth 1 -type f ! -name SHA256SUMS \
    -print0 | sort -z | xargs -0 sha256sum) >"$DIAG_RUN/SHA256SUMS"
  exit "$rc"
}
trap finish EXIT
snapshot start
# Retain native sysstat data, avoiding high-volume text in journald. sar can
# replay CPU, run queue, paging, swap and device I/O around the exact stall.
LC_ALL=C sar -u ALL -r -q -b -B -W -d \
  -o "$DIAG_RUN/sar.bin" 1 "$DURATION_SECONDS" \
  >/dev/null 2>"$DIAG_RUN/sar.stderr"
