#!/usr/bin/env bash
set -euo pipefail

phase_minutes="${PHASE_MINUTES:-7}"

scale() {
  local nginx="$1" redis="$2" postgres="$3"
  kubectl scale deployment/loadgen -n production --replicas="$nginx"
  kubectl scale deployment/redis-loadgen -n production --replicas="$redis"
  kubectl scale deployment/postgres-loadgen -n default --replicas="$postgres"
  printf '%s phase nginx=%s redis=%s postgres=%s\n' \
    "$(date -u +%FT%TZ)" "$nginx" "$redis" "$postgres"
}

restore() {
  scale 1 1 1 || true
}
trap restore EXIT INT TERM

wait_minutes() {
  local count="$1"
  for ((minute=0; minute<count; minute++)); do sleep 60; done
}

# Three legitimate operating regimes. The collector runs independently and
# labels all of these as normal; no attack generator is active in this period.
scale 1 1 1
wait_minutes "$phase_minutes"
scale 2 2 2
wait_minutes "$phase_minutes"
scale 4 2 3
wait_minutes "$phase_minutes"
