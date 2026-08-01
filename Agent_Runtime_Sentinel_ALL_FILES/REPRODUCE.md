# Reproduce the Current V2 Gates

## Local source checks

```bash
./scripts/run_artifact_gates.sh

# Require an actual eBPF build (VM/reviewer host with toolchain):
REQUIRE_EBPF_BUILD=1 ./scripts/run_artifact_gates.sh

# VM venv:
PYTHON_BIN=/home/dat/ml-venv/bin/python REQUIRE_EBPF_BUILD=1 ./scripts/run_artifact_gates.sh

# Equivalent individual commands:
pytest -q tests/test_agent_runtime_*.py
python3 -m agent_runtime.benchmark --iterations 10000 --snapshot-every 100
python3 -m agent_runtime.eval.replay_validation
make -C agent_runtime/ebpf check-deps
```

## VM/cluster checks

```bash
make -C /home/dat/ml-service/agent_runtime/ebpf all
kubectl apply --server-side --dry-run=server -f agent_runtime/k8s/mcp-demo.yaml
kubectl get --raw=/readyz
kubectl get nodes
```

## Expected current gates

- V2 local tests pass; two environment-dependent tests may be skipped.
- Replay normal traffic produces no `pending`/alert; five safety scenarios need
  two windows before confirmed alert.
- eBPF build requires clang, bpftool, BTF and libbpf headers.
- Cluster validation must not create/modify resources when using dry-run.

Do not treat these gates as the final paper evaluation. Follow
`PAPER_READINESS_PLAN.md` for collection, split, baseline, ablation and
statistical evaluation.

## AIMS production syscall candidate

V7 must remain frozen while this candidate is evaluated. On the cluster host,
apply the scoped sensor and Sentinel-owned traffic manifests, then start the
independent normal matrix:

```bash
kubectl apply -f /home/dat/ml-service/tetragon-aims-policies.yaml
kubectl apply -f /home/dat/ml-service/aims-sentinel-loadgen.yaml
/home/dat/ml-service/set_aims_traffic_regime.sh steady

# Default is 4 regimes x 5 independent runs x 72 minutes = 24 hours.
nohup /home/dat/ml-service/run_aims_normal_matrix.sh \
  >/home/dat/ml-service/aims-normal-matrix.log 2>&1 </dev/null &
```

The eligible/excluded workload list and release gates are pinned in
`ml-service/aims_release_contract.json`. Payment and notification currently use
a sandbox runtime and are intentionally outside the host-syscall candidate.
The normal matrix does not authorize promotion; build/train and all blind
attack, baseline, ablation, overhead and confidence-interval gates remain
separate.

After the candidate and threshold are frozen, compile and verify the distinct
blind binary before running its matrix:

```bash
gcc -O2 -Wall -Wextra -Werror -static \
  -o runtime_attack_blind runtime_attack_blind.c
sha256sum runtime_attack_blind.c runtime_attack_blind

python run_aims_blind_matrix.py \
  --model-dir models_aims_candidate-FROZEN \
  --normal-calibration aims-normal-calibration-FROZEN.json \
  --runtime-source runtime_attack_blind.c \
  --runtime-binary runtime_attack_blind
```

The hashes must equal `aims_blind_attack_contract.json`. Never inspect blind
results and then retrain/tune the same candidate; a changed model requires a
new independently frozen blind set.
