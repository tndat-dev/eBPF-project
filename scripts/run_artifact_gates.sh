#!/usr/bin/env bash
# Reproducibility gates for the current Agent Runtime Sentinel artifact.
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}
cd "$ROOT_DIR"

if compgen -G 'tests/test_agent_runtime_*.py' >/dev/null; then
  "$PYTHON_BIN" -m pytest -q tests/test_agent_runtime_*.py
else
  "$PYTHON_BIN" -m pytest -q test_agent_runtime_*.py
fi
"$PYTHON_BIN" -m agent_runtime.benchmark --iterations 10000 --snapshot-every 100
"$PYTHON_BIN" -m agent_runtime.eval.replay_validation
if make -C agent_runtime/ebpf check-deps; then
  make -C agent_runtime/ebpf all
elif [[ "${REQUIRE_EBPF_BUILD:-0}" == "1" ]]; then
  echo "eBPF build is required but the local toolchain is incomplete" >&2
  exit 1
else
  echo "SKIP: eBPF build (set REQUIRE_EBPF_BUILD=1 on a BPF-capable host)" >&2
fi

if command -v kubectl >/dev/null 2>&1; then
  kubectl apply --server-side --dry-run=server -f agent_runtime/k8s/mcp-demo.yaml
  kubectl apply --server-side --dry-run=server -f agent_runtime/k8s/mcp-attack-job.yaml
fi
