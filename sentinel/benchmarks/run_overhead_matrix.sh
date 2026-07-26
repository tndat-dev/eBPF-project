#!/usr/bin/env bash
# Run the production-like overhead matrix as a disconnect-safe systemd job.
set -Eeuo pipefail

cd /home/dat/ml-service
export KUBECONFIG=/home/dat/.kube/config

mode="${1:-all}"
python_bin=/home/dat/ml-venv/bin/python
url=http://10.103.40.121/
experiment_id="${SENTINEL_EXPERIMENT_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
common=(
  --url "$url"
  --tool wrk
  --threads 4
  --concurrency 50
  --duration 30
  --repeats 5
  --output-root overhead-final
  --experiment-id "$experiment_id"
)

restore_runtime() {
  kubectl apply -f tetragon-targeted-policies.yaml >/dev/null 2>&1 || true
  systemctl start sentinel-detector >/dev/null 2>&1 || true
  chown -R dat:dat overhead-final >/dev/null 2>&1 || true
}
trap restore_runtime EXIT INT TERM

if [[ "$mode" == "all" ]]; then
  kubectl apply -f tetragon-targeted-policies.yaml >/dev/null
  systemctl restart sentinel-detector
  echo "SETTLE full_pipeline"
  sleep 30
  "$python_bin" measure_phase.py --phase full_pipeline "${common[@]}"
elif [[ "$mode" != "remaining" ]]; then
  echo "usage: $0 [all|remaining]" >&2
  exit 2
fi

systemctl stop sentinel-detector
echo "SETTLE tetragon_only"
sleep 30
"$python_bin" measure_phase.py --phase tetragon_only "${common[@]}"

kubectl delete tracingpolicynamespaced sentinel-syscalls \
  -n production --ignore-not-found
kubectl delete tracingpolicynamespaced sentinel-syscalls \
  -n default --ignore-not-found
echo "SETTLE no_tracing"
sleep 30
"$python_bin" measure_phase.py --phase no_tracing "${common[@]}"

restore_runtime
trap - EXIT INT TERM
"$python_bin" compare_overhead.py --root overhead-final --tool wrk \
  --experiment-id "$experiment_id" \
  --output "overhead-final/comparison-wrk-${experiment_id}.json"
echo "OVERHEAD_MATRIX_COMPLETE experiment_id=${experiment_id}"
