#!/usr/bin/env bash
# Run on a control-plane node after all three collect-only services are healthy.
set -euo pipefail

PROJECT_ROOT=${PROJECT_ROOT:-/home/dat/eBPF-project}
CAMPAIGN_ROOT=${CAMPAIGN_ROOT:-/home/dat/sentinel-pulse-evidence}
CAMPAIGN_ID=${CAMPAIGN_ID:-sentinel-pulse-$(date -u +%Y%m%dT%H%M%SZ)}
DURATION_SECONDS=${DURATION_SECONDS:-21600}
TRANSITION_GAP_SECONDS=${TRANSITION_GAP_SECONDS:-180}
PREPARE_SECONDS=${PREPARE_SECONDS:-180}
CONTRACT="$CAMPAIGN_ROOT/$CAMPAIGN_ID/capture-contract.json"
CAMPAIGN_DIR=$(dirname "$CONTRACT")

mkdir -p "$CAMPAIGN_DIR"
test ! -e "$CONTRACT"
start_epoch=$(( $(date +%s) + PREPARE_SECONDS ))

cd "$PROJECT_ROOT"
campaign_complete=false
health_failures=0
HEALTH_FAILURE_LIMIT=${HEALTH_FAILURE_LIMIT:-3}
restore_steady() {
  "$PROJECT_ROOT/ml-service/set_aims_traffic_regime.sh" steady >/dev/null 2>&1 || true
  rm -f "$CAMPAIGN_DIR/CAMPAIGN_ACTIVE"
  if [[ "$campaign_complete" != true ]]; then
    date -u +%FT%TZ >"$CAMPAIGN_DIR/CAMPAIGN_FAILED"
  fi
}
trap restore_steady EXIT

check_cluster_health() {
  local ready bad timestamp
  ready=$(kubectl get nodes --no-headers | awk '$2 == "Ready" {count++} END {print count+0}')
  bad=$(kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded \
    --no-headers 2>/dev/null | wc -l)
  if [[ "$ready" == 6 && "$bad" == 0 ]]; then
    health_failures=0
    return 0
  fi
  health_failures=$((health_failures + 1))
  timestamp=$(date -u +%Y%m%dT%H%M%SZ)
  {
    printf 'ready_nodes=%s expected=6 non_running_pods=%s consecutive=%s\n' \
      "$ready" "$bad" "$health_failures"
    kubectl get nodes
    kubectl get pods -A \
      --field-selector=status.phase!=Running,status.phase!=Succeeded -o wide
  } >"$CAMPAIGN_DIR/health-warning-$timestamp.txt"
  if (( health_failures >= HEALTH_FAILURE_LIMIT )); then
    printf 'cluster health gate failed persistently: ready_nodes=%s non_running_pods=%s checks=%s\n' \
      "$ready" "$bad" "$health_failures" >&2
    return 1
  fi
  printf 'transient cluster health warning: ready_nodes=%s non_running_pods=%s check=%s/%s\n' \
    "$ready" "$bad" "$health_failures" "$HEALTH_FAILURE_LIMIT" >&2
}

for deployment in aims-sentinel-loadgen aims-sentinel-readmix-loadgen \
  aims-sentinel-dependency-loadgen; do
  kubectl -n production get deployment "$deployment" >/dev/null
done
check_cluster_health

python3 -m sentinel_pulse.prepare_contract \
  --output "$CONTRACT" \
  --campaign-id "$CAMPAIGN_ID" \
  --start "$start_epoch" \
  --duration-seconds "$DURATION_SECONDS" \
  --transition-gap-seconds "$TRANSITION_GAP_SECONDS" \
  --node k8s-worker1.local \
  --node k8s-worker3.local \
  --node k8s-worker4.local >/dev/null
sha256sum "$CONTRACT" >"$CONTRACT.sha256"
date -u +%FT%TZ >"$CAMPAIGN_DIR/CAMPAIGN_ACTIVE"

wait_until() {
  local target=$1 now remaining
  while :; do
    now=$(date +%s)
    remaining=$((target - now))
    (( remaining <= 0 )) && return 0
    if (( remaining > 30 )); then
      sleep 30
      check_cluster_health
    else
      sleep "$remaining"
    fi
  done
}

for regime in steady toolmix burst recovery; do
  regime_start=$(python3 - "$CONTRACT" "$regime" <<'PY'
import json, sys
contract = json.load(open(sys.argv[1], encoding="utf-8"))
print(int(next(item["start"] for item in contract["intervals"] if item["regime"] == sys.argv[2])))
PY
)
  "$PROJECT_ROOT/ml-service/set_aims_traffic_regime.sh" "$regime"
  kubectl -n production get deployment \
    aims-sentinel-loadgen aims-sentinel-readmix-loadgen \
    aims-sentinel-dependency-loadgen -o json \
    >"$CAMPAIGN_DIR/$regime-deployments.json"
  now=$(date +%s)
  if (( now > regime_start )); then
    printf 'regime rollout missed preregistered start: regime=%s now=%s start=%s\n' \
      "$regime" "$now" "$regime_start" >&2
    exit 1
  fi
  wait_until "$regime_start"
  printf 'campaign=%s regime=%s started_at=%s contract_sha256=%s\n' \
    "$CAMPAIGN_ID" "$regime" "$(date -u +%FT%TZ)" "$(sha256sum "$CONTRACT" | awk '{print $1}')"
  wait_until "$((regime_start + DURATION_SECONDS))"
done

"$PROJECT_ROOT/ml-service/set_aims_traffic_regime.sh" steady
touch "$CAMPAIGN_ROOT/$CAMPAIGN_ID/CAPTURE_SCHEDULE_COMPLETE"
campaign_complete=true
printf 'campaign=%s schedule_complete_at=%s\n' "$CAMPAIGN_ID" "$(date -u +%FT%TZ)"
