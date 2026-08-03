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

Trên VM có các thư mục backup audit chứa test trùng tên, vì vậy chạy suite
canonical bằng đường dẫn tường minh `python -m pytest -q tests`; không chạy
`pytest -q` từ runtime root rồi xóa backup chỉ để tránh import collision.

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

Không chờ đủ 24 giờ rồi đưa toàn bộ dữ liệu vào train. Trước khi candidate đầu
tiên được fit, `ml-service/aims_candidate_split_contract.json` đóng băng vai trò
theo run: run 01 của bốn regime là `candidate_fit`; run 02--03 là
`independent_validation`; run 04--05 là `blind_normal_test`. Builder kiểm tra
đúng thứ tự và đúng tập phase, kiểm tra SHA-256 parent release contract, rồi
fail nếu một phase validation/test bị đưa vào train. Holdout 20% bên trong
run-01 chỉ dùng early stopping/calibration, không được báo cáo như test độc lập.

Sau khi cả bốn phase run-01 đã pass continuity/duration/hash gate, đóng băng và
train candidate riêng như sau (đường dẫn stamp phải được giữ trong artifact):

```bash
root=$(cat /home/dat/ml-service/.aims-normal-matrix-active)
export AIMS_DATASET_DIR=/home/dat/ml-service/training_data_aims_fit-v1-FROZEN
/home/dat/ml-service/run_aims_candidate.sh build \
  "$root/aims-steady-run-01" \
  "$root/aims-burst-run-01" \
  "$root/aims-recovery-run-01" \
  "$root/aims-toolmix-run-01"

/home/dat/ml-service/run_aims_candidate.sh train \
  "$AIMS_DATASET_DIR" \
  /home/dat/ml-service/models_aims_fit-v1-FROZEN
```

Có thể chạy lệnh train bằng systemd transient unit với `Nice=15`, CPU/RAM
limit để không phụ thuộc SSH. Dù offline development gate pass, candidate vẫn
không được promote trước khi chạy nguyên vẹn run 02--05, blind attack, baseline,
ablation và overhead A/B.

Evaluator độc lập không dùng một scoring implementation rút gọn. Nó dựng lại
`FeatureVector` từ vector/metadata row-aligned rồi gọi chính
`AnomalyDetector.handle_feature_vector`, gồm per-workload POT, online clean
calibration, startup grace, event-quality guard, behavior gate và two-window
confirmation. Fast-path warning không được replay trong normal holdout, nên
không thể làm giảm false-positive gate. Cooldown đặt 0 để đếm bảo thủ mọi alert.

Trước evaluator, tạo duy nhất một runtime calibration từ `candidate_fit`.
Builder xác minh lại hash array/metadata run-01, chỉ nhận row không startup,
đủ event, không behavior gate và score dưới frozen baseline threshold. State
chỉ giữ 120 mẫu sạch cuối theo đúng `StreamingThreshold`; run-02--05 tuyệt đối
không được dùng để xây/tune artifact này.

```bash
python build_aims_fit_calibration.py \
  --candidate /home/dat/ml-service/models_aims_fit-v1-FROZEN \
  --output /home/dat/ml-service/aims-fit-v1-calibration.json \
  --report /home/dat/ml-service/aims-fit-v1-calibration.report.json
```

Hai evaluator và blind kernel matrix phải dùng đúng hash calibration này.
Independent report ghi hash; blind report từ chối nếu hash khác prerequisite.

```bash
python evaluate_aims_normal_split.py \
  --evidence-root /home/dat/ml-service/aims-normal-matrix-FROZEN \
  --candidate /home/dat/ml-service/models_aims_fit-v1-FROZEN \
  --role independent_validation \
  --initial-calibration aims-fit-v1-calibration.json \
  --split-contract aims_candidate_split_contract.json \
  --release-contract aims_release_contract.json \
  --output aims-independent-validation-FROZEN.json

# Chỉ chạy sau khi report trên complete và passed=true; candidate hash phải khớp.
python evaluate_aims_normal_split.py \
  --evidence-root /home/dat/ml-service/aims-normal-matrix-FROZEN \
  --candidate /home/dat/ml-service/models_aims_fit-v1-FROZEN \
  --role blind_normal_test \
  --initial-calibration aims-fit-v1-calibration.json \
  --prerequisite-report aims-independent-validation-FROZEN.json \
  --output aims-blind-normal-test-FROZEN.json
```

Nếu phase chưa đủ, evaluator ghi `status=waiting_for_phases`, trả exit 4 và
không load/tune model. Timer systemd chuyển trạng thái chờ này thành success để
thử lại sau 30 phút; lỗi evidence/model thật vẫn làm service fail. Hai role dùng
chung flock có timeout để không replay chồng nhau. Collection mới ghi thêm
SHA-256 metadata; phase cũ được evaluator hash metadata trực tiếp trong result,
và toàn matrix cuối vẫn được khóa bởi `SHA256SUMS`.

After the candidate and threshold are frozen, compile and verify the distinct
blind binary before running its matrix:

```bash
gcc -O2 -Wall -Wextra -Werror -static \
  -o runtime_attack_blind runtime_attack_blind.c
sha256sum runtime_attack_blind.c runtime_attack_blind

python run_aims_blind_matrix.py \
  --model-dir models_aims_candidate-FROZEN \
  --normal-calibration aims-normal-calibration-FROZEN.json \
  --normal-prerequisite aims-blind-normal-test-FROZEN.json \
  --split-contract aims_candidate_split_contract.json \
  --runtime-source runtime_attack_blind.c \
  --runtime-binary runtime_attack_blind
```

The hashes must equal `aims_blind_attack_contract.json`. Never inspect blind
results and then retrain/tune the same candidate; a changed model requires a
new independently frozen blind set.

Runner dài được timer hóa bằng `aims-blind-attack.timer`. Mỗi trial thành công
phải có report hash hợp lệ mới được skip khi resume. Trial lỗi/orphan được move
vào `rejected/` rồi chạy lại; không xóa negative evidence. Header resume khóa
schedule, source/binary, candidate, calibration, split, prerequisite và release
contract. Service không chạy khi normal matrix/training/split evaluator active,
giới hạn CPU/RAM, timeout 12 giờ và không có đường promote.

Behavior gate của candidate mới không so tỷ lệ điểm trực tiếp khi cửa sổ chỉ có
ít event. `evaluate_behavior()` dùng cận dưới Wilson một phía 95%; chỉ khi cận
dưới này vẫn vượt giới hạn workload-conditioned thì kernel evidence mới được
xác nhận. `build_phase_dataset.py` vì vậy lưu
`validation_event_counts` theo đúng thứ tự holdout và `train_candidate.py`
fail-closed nếu thiếu hoặc lệch số hàng. Mọi dataset cũ không có contract này
phải được rebuild từ cùng source phase; không được tự thêm count suy đoán.

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

## AIMS overhead A/B

Không chạy overhead trong khi normal matrix, training hoặc split evaluator đang
active. Harness có interlock và phải trả exit 3 trước mọi mutation trong trường
hợp đó. Sau khi independent/blind-normal gate pass, chạy đủ sáu permutation của
ba phase để giảm order/cache/thermal confound:

```bash
sudo env AIMS_PHASE_ORDER=no_tracing,tetragon_only,full_pipeline \
  SENTINEL_EXPERIMENT_ID=aims-overhead-order-01 \
  /home/dat/ml-service/sentinel/benchmarks/run_aims_overhead_matrix.sh
```

Lặp với năm permutation còn lại và experiment ID riêng. Mỗi phase warm-up rồi
chạy 10 repetition `wrk -t4 -c50 -d30s --latency` vào ingress AIMS thật qua
Istio. Ba treatment là no AIMS tracing, Tetragon policy only, và full frozen
candidate. Script dùng bản sao calibration, không sửa artifact gốc; trap luôn
khôi phục AIMS policy và V7 service. Report chứa throughput, p99, request error,
Tetragon/detector CPU-RAM, tổng CPU-RAM tám workload, bootstrap 95% interval,
phase-order protocol hash và environment hash.
