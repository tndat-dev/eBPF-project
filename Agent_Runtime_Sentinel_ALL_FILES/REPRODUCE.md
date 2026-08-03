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
sudo install -m 0644 sentinel/systemd/aims-normal-matrix.service \
  /etc/systemd/system/aims-normal-matrix.service
sudo systemctl daemon-reload
sudo systemctl start aims-normal-matrix.service
systemctl status aims-normal-matrix.service --no-pager
journalctl -u aims-normal-matrix.service -f
```

Service lưu active evidence root để resume sau disconnect/failure. Phase đã
pass toàn bộ duration/sensor/digest gate được giữ; phase có stream gap được
chuyển vào `rejected/` và thu lại. Không xóa thư mục `rejected/` vì đó là
negative evidence giải thích vì sao một phase không được dùng để train.

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

## Publication statistics

Tạo lại confusion metrics, Wilson 95% interval và latency CDF/bootstrap từ hai
report bất biến; không dùng file đã tổng hợp làm input vòng hai:

```bash
python3 ml-service/paper_statistics.py \
  --normal validation-evidence/20260801T153648Z/normal_validation_report.json \
  --attack validation-evidence/20260801T153648Z/attack_validation_report.json \
  --output validation-evidence/20260801T153648Z/paper_statistics.json
```

Kết quả 0 false alert vẫn phải báo Wilson upper bound. Sau AIMS matrix, thay
window-level interval bằng block bootstrap theo 20 run độc lập để xử lý tương
quan thời gian.

Sau khi từng baseline/ablation ghi `result.json` theo contract, kiểm tra toàn
bộ matrix dùng cùng dataset/split/blind set/environment/seeds:

```bash
python3 ml-service/evaluation_matrix_validation.py paper-evaluation-results \
  --contract ml-service/evaluation_matrix_contract.json
```

Gate phải fail khi thiếu bất kỳ experiment nào. Không tạo result giả chỉ để
gate xanh; `evaluation_matrix_manifest.json` là index của evidence đã chạy,
không phải generator kết quả.
