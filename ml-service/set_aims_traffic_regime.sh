#!/usr/bin/env bash
# Reproducibly switch only the Sentinel-owned AIMS traffic generators.
set -euo pipefail

REGIME=${1:?usage: set_aims_traffic_regime.sh steady|burst|recovery|toolmix|idle}
NAMESPACE=${NAMESPACE:-production}

case "$REGIME" in
  steady)   base_replicas=1; mix_replicas=0; dependency_replicas=1; sleep_seconds=1 ;;
  burst)    base_replicas=6; mix_replicas=2; dependency_replicas=3; sleep_seconds=0 ;;
  recovery) base_replicas=1; mix_replicas=0; dependency_replicas=1; sleep_seconds=2 ;;
  toolmix)  base_replicas=2; mix_replicas=4; dependency_replicas=2; sleep_seconds=1 ;;
  idle)     base_replicas=0; mix_replicas=0; dependency_replicas=0; sleep_seconds=2 ;;
  *) printf 'unknown AIMS traffic regime: %s\n' "$REGIME" >&2; exit 2 ;;
esac

kubectl -n "$NAMESPACE" set env deployment/aims-sentinel-loadgen \
  SLEEP_SECONDS="$sleep_seconds" >/dev/null
kubectl -n "$NAMESPACE" set env deployment/aims-sentinel-readmix-loadgen \
  SLEEP_SECONDS="$sleep_seconds" >/dev/null
kubectl -n "$NAMESPACE" set env deployment/aims-sentinel-dependency-loadgen \
  SLEEP_SECONDS="$sleep_seconds" >/dev/null
kubectl -n "$NAMESPACE" scale deployment/aims-sentinel-loadgen \
  --replicas="$base_replicas" >/dev/null
kubectl -n "$NAMESPACE" scale deployment/aims-sentinel-readmix-loadgen \
  --replicas="$mix_replicas" >/dev/null
kubectl -n "$NAMESPACE" scale deployment/aims-sentinel-dependency-loadgen \
  --replicas="$dependency_replicas" >/dev/null
kubectl -n "$NAMESPACE" annotate deployment aims-sentinel-loadgen \
  sentinel.openai.dev/traffic-regime="$REGIME" --overwrite >/dev/null
kubectl -n "$NAMESPACE" annotate deployment aims-sentinel-readmix-loadgen \
  sentinel.openai.dev/traffic-regime="$REGIME" --overwrite >/dev/null
kubectl -n "$NAMESPACE" annotate deployment aims-sentinel-dependency-loadgen \
  sentinel.openai.dev/traffic-regime="$REGIME" --overwrite >/dev/null

kubectl -n "$NAMESPACE" rollout status deployment/aims-sentinel-loadgen \
  --timeout=120s
if (( mix_replicas > 0 )); then
  kubectl -n "$NAMESPACE" rollout status deployment/aims-sentinel-readmix-loadgen \
    --timeout=120s
fi
if (( dependency_replicas > 0 )); then
  kubectl -n "$NAMESPACE" rollout status deployment/aims-sentinel-dependency-loadgen \
    --timeout=120s
fi
printf 'AIMS traffic regime=%s base_replicas=%d readmix_replicas=%d dependency_replicas=%d sleep=%ss\n' \
  "$REGIME" "$base_replicas" "$mix_replicas" "$dependency_replicas" "$sleep_seconds"
