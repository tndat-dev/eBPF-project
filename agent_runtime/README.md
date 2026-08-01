# Agent Runtime Sentinel V2 extension

Đây là nhánh mở rộng không phá V1. V1 đang chạy **audit/dry-run provisional**:
Tetragon syscall stream → LSTM Autoencoder + Isolation Forest diagnostic →
behavior gate → responder chỉ ghi action. V2 thêm miền AI Agent/MCP theo tài
liệu `Agent_Runtime_Sentinel_ALL_FILES`; chưa lane nào được phép tự cô lập pod.

Các phần đã có trong scaffold này:

- `mcp/graph.py`: parse MCP JSON-RPC 2.0, trích tool/resource, tạo
  sliding-window behavior graph `agent -> tool -> resource`.
- `detector/graph_features.py`: vector hoá graph snapshot để nối vào harness ML
  hiện tại trước khi cài PyTorch Geometric/GAT.
- `detector/online_detector.py`: detector realtime dependency-free, baseline
  per-agent bằng median/MAD, xác nhận nhiều window và cooldown chống alert lặp.
- `detector/evt_pot.py`: adaptive empirical EVT-POT theo agent/pod, chỉ học
  từ score baseline-clean để ngăn threshold poisoning.
- `runtime.py`: đường chạy bounded `MCP payload -> graph -> decision/alert`,
  với envelope alert tương thích responder V1.
- `detector/online_detector.py` và `runtime.py`: pipeline realtime dùng
  baseline median/MAD một phía, xác nhận hai cửa sổ và cooldown. Cơ chế này
  giảm false positive từ một request MCP hiếm nhưng hợp lệ, đồng thời giữ
  alert tương thích với envelope V1.
- `eval/agent_scenarios.py`: 5 kịch bản attack AI-agent thay cho 5 scenario V1.
- `ebpf/mcp_probe.bpf.c`: uprobe `SSL_write`; chỉ copy bytes ra ring buffer,
  không parse JSON trong kernel.
- `mcp/transport.py` và `ring_reader.py`: reassemble plaintext TLS bị phân
  mảnh theo PID, tách HTTP body rồi mới parse MCP; reader không ghi plaintext
  ra file hay echo nó trong output alert.

Trạng thái chủ đích: chạy được unit test và sync lên VM ngay, chưa restart hoặc
thay service V7 đang ổn định. HTTPS MCP pod đã chạy trong namespace lab; bước
tiếp theo là attach probe chỉ vào PID lab có kiểm soát và đánh giá dataset MCP
thật trước khi thay bất kỳ service production nào.

## Kiểm tra hồi quy latency

Chạy benchmark userspace có giới hạn bộ nhớ từ thư mục gốc:

```bash
python3 -m agent_runtime.benchmark --iterations 10000 --snapshot-every 100
```

Lệnh in p50/p95/p99 riêng cho ingest (`JSON-RPC -> event -> graph`) và dựng
snapshot/vector. Nó không gồm latency delivery của kernel hay ML inference;
hai phần này phải được đo trên cluster đang chạy.

Đường detector realtime được kiểm thử bằng `tests/test_agent_runtime_realtime.py`:
traffic bình thường không alert, attack cần hai window xác nhận, và p99 của
payload nhỏ phải dưới 100 ms. Test còn replay 600 request bình thường ở 5 RPS
sau khi sliding window đầy, sau đó inject hai request attack; normal vẫn không
alert và attack vẫn phải qua `pending -> alert`. Đây là guard regression; không
thay thế đánh giá GAT trên dữ liệu MCP thật.

Gate tái lập được cho release V2:

```bash
python3 -m agent_runtime.eval.replay_validation
```

Gate replay bốn normal regime dài, yêu cầu không `pending`/`alert`, rồi kiểm
tra đủ 5 scenario AI-agent phải đi từ `pending` sang `alert`.

## GAT + EVT-POT (optional ML path)

`detector/gat_model.py` dùng `torch-geometric` để train GAT autoencoder trên
snapshot sạch. Score là reconstruction error và threshold là tail quantile có
margin; graph topology, loại node và semantic global features cùng đi vào model.
V1 robust detector vẫn là fallback cho đến khi GAT được train từ capture review.

```bash
python3 -m agent_runtime.eval.gat_benchmark --iterations 100 --epochs 80
```

`eval/train_gat.py` chỉ nhận JSONL snapshot đã review và không chứa raw MCP
payload. Release `.pt` được kèm manifest SHA-256; loader từ chối artifact bị
sửa. Không train/promotion từ traffic synthetic hoặc raw plaintext capture.

`eval/snapshot_collector.py` là bridge capture-to-training: nhận JSONL từ loader
qua pipe và chỉ ghi graph snapshot đã hash resource, sau đó `train_gat.py` dùng
file này làm input.

`systemd/agent-runtime-gat-trainer.timer` chạy train candidate mỗi giờ trên VM.
Nó chỉ bắt đầu khi có tối thiểu 200 snapshot với
`review_status=approved_normal`; collector mặc định tạo `pending_review`, và
file có record thiếu nhãn, chưa review hoặc là attack sẽ bị từ chối. Nó chỉ ghi
candidate + manifest và **không bao giờ promote** candidate sang production.
Lệnh `train_gat.py` cũng áp dụng cùng gate, nên không thể bypass review bằng
cách chạy train thủ công.

Service nền chạy với `Nice=10`, I/O best-effort, giới hạn `CPUQuota=50%` và
`MemoryMax=2G`; training candidate không được phép làm ảnh hưởng latency của
detector V7.

## MCP HTTPS lab trên Kubernetes

`k8s/mcp-demo.yaml` tạo namespace tách biệt `agent-sentinel-lab`, TLS MCP
server không thực thi tool, và normal load generator. Đây là target HTTPS thật
để kiểm tra transport an toàn, không ảnh hưởng namespace `production`:

Manifest pin image theo digest, chạy non-root và enforce Pod Security
`restricted`. Certificate chỉ tồn tại trong memory-backed `emptyDir` của pod.

```bash
kubectl apply -f agent_runtime/k8s/mcp-demo.yaml
kubectl rollout status deployment/mcp-tls-server -n agent-sentinel-lab
kubectl rollout status deployment/mcp-normal-loadgen -n agent-sentinel-lab
```

`k8s/mcp-attack-job.yaml` chỉ gửi hai MCP JSON-RPC `kubectl.delete` tới server
không thực thi, không mount service-account token và tự hết hạn. Nó được dùng
để kiểm thử detection/telemetry, không thay đổi resource production.

Với PID lab đã được kiểm soát và quyền root của node, đường capture có thể pipe
trực tiếp, không ghi plaintext:

```bash
sudo ./mcp_probe_loader --object mcp_probe.bpf.o --libssl /lib/x86_64-linux-gnu/libssl.so.3 \
  --pid <curl-pid> --emit-payload | python3 -m agent_runtime.ring_reader --lab-baseline
```

`--lab-baseline` chỉ dành cho namespace demo; production phải nạp baseline đã
review theo từng agent trước khi reader được chạy. `detector/baseline_store.py`
lưu baseline cùng SHA-256 và agent ID; reader dùng `--baseline-file FILE.json`
để từ chối baseline bị sửa hoặc gán nhầm agent.

Timestamp từ eBPF (`bpf_ktime_get_ns`) là monotonic clock. Reader neo event đầu
vào wall clock một lần rồi dùng delta monotonic cho event sau, vì vậy latency
không bị sai do trừ trực tiếp hai clock base khác nhau.
