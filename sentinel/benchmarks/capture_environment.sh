#!/usr/bin/env bash
# Capture immutable software/cluster context for a benchmark release.
set -Eeuo pipefail

cd /home/dat/ml-service
export KUBECONFIG=${KUBECONFIG:-/home/dat/.kube/config}

output="${1:-environment-$(date -u +%Y%m%dT%H%M%SZ).txt}"
temporary="${output}.tmp-$$"
cleanup() { rm -f "$temporary"; }
trap cleanup EXIT INT TERM

{
  date -u --iso-8601=seconds
  uname -a
  kubectl version -o yaml
  kubectl get nodes -o wide
  kubectl get daemonset -n kube-system cilium tetragon -o wide
  kubectl get deployment -A -o wide
  kubectl get tracingpolicynamespaced -A -o yaml
  systemctl cat sentinel-detector.service
  sha256sum \
    anomaly_detector2.py adaptive_threshold.py feature_engineering.py \
    graph_signals.py ml_models.py tetragon_consumer.py \
    tetragon-targeted-policies.yaml /etc/systemd/system/sentinel-detector.service
  if [[ -n "${AIMS_CANDIDATE:-}" ]]; then
    printf 'AIMS_CANDIDATE=%s\n' "$AIMS_CANDIDATE"
    find "$AIMS_CANDIDATE" -maxdepth 1 -type f -print0 \
      | sort -z | xargs -0 sha256sum
    sha256sum "$AIMS_CALIBRATION" "$AIMS_SPLIT_CONTRACT" \
      "$AIMS_RELEASE_CONTRACT" tetragon-aims-policies.yaml \
      sentinel/benchmarks/run_aims_overhead_matrix.sh
    kubectl -n istio-ingress get service aims-ingress-istio -o yaml
  fi
  /home/dat/ml-venv/bin/python - <<'PY'
import platform
import numpy
import scipy
import sklearn
import torch

print("python", platform.python_version())
print("numpy", numpy.__version__)
print("scipy", scipy.__version__)
print("sklearn", sklearn.__version__)
print("torch", torch.__version__)
PY
} >"$temporary"

mv "$temporary" "$output"
trap - EXIT INT TERM
echo "$output"
