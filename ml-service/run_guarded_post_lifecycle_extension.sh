#!/usr/bin/env bash
# Require a stable production control plane before starting the immutable
# post-lifecycle collection. The inner collector still enforces continuity for
# every sensor stream, so passing this gate cannot hide an interruption later.
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE_PREFIX=${1:?usage: $0 <existing-low-latency-prefix> <lifecycle-dir>}
LIFECYCLE_DIR=${2:?usage: $0 <existing-low-latency-prefix> <lifecycle-dir>}
GATE_SAMPLES=${SENTINEL_STABILITY_SAMPLES:-10}
GATE_INTERVAL=${SENTINEL_STABILITY_INTERVAL_SECONDS:-30}

if [[ -z ${KUBECONFIG:-} && -r /home/dat/.kube/sentinel-ha.conf ]]; then
  export KUBECONFIG=/home/dat/.kube/sentinel-ha.conf
fi

if [[ ${SENTINEL_REQUIRE_EXPERIMENT_LOCK:-true} == "true" ]]; then
  kubectl get validatingadmissionpolicy \
    sentinel-experiment-resource-lock >/dev/null
  kubectl get validatingadmissionpolicybinding \
    sentinel-experiment-resource-lock >/dev/null
fi

for sample in $(seq 1 "$GATE_SAMPLES"); do
  kubectl get --raw=/readyz >/dev/null
  node_count=$(kubectl get nodes --no-headers | wc -l)
  ready_count=$(kubectl get nodes \
    -o jsonpath='{range .items[*]}{range .status.conditions[?(@.type=="Ready")]}{.status}{"\n"}{end}{end}' \
    | grep -c '^True$')
  coverage=$(kubectl -n kube-system get daemonset tetragon \
    -o jsonpath='{.status.desiredNumberScheduled},{.status.numberReady},{.status.numberAvailable}')
  [[ "$node_count" == 6 && "$ready_count" == 6 && "$coverage" == "6,6,6" ]] || {
    printf 'stability gate failed: nodes=%s/%s tetragon=%s\n' \
      "$ready_count" "$node_count" "$coverage" >&2
    exit 10
  }

  if (( sample % 2 == 0 )); then
    nginx_loadgen=$(kubectl get pod -n production -l app=loadgen \
      -o jsonpath='{.items[0].metadata.name}')
    redis_loadgen=$(kubectl get pod -n production -l app=redis-loadgen \
      -o jsonpath='{.items[0].metadata.name}')
    postgres_loadgen=$(kubectl get pod -n default -l app=postgres-loadgen \
      -o jsonpath='{.items[0].metadata.name}')
    kubectl exec -n production "$nginx_loadgen" -- \
      wget -q -O /dev/null http://nginx/healthz
    kubectl exec -n production "$redis_loadgen" -- \
      redis-cli -h redis ping >/dev/null
    kubectl exec -n default "$postgres_loadgen" -- sh -c \
      'PGPASSWORD=keycloak psql -h postgres -U keycloak -d keycloak -tAc "SELECT 1"' \
      | grep -q 1
  fi

  printf '%s stability_sample=%d/%d nodes=%s/%s tetragon=%s traffic=%s\n' \
    "$(date -u +%FT%TZ)" "$sample" "$GATE_SAMPLES" "$ready_count" \
    "$node_count" "$coverage" "$((sample % 2 == 0))"
  if (( sample < GATE_SAMPLES )); then
    sleep "$GATE_INTERVAL"
  fi
done

exec "$ROOT_DIR/run_post_lifecycle_regime_extension.sh" \
  "$BASE_PREFIX" "$LIFECYCLE_DIR"
