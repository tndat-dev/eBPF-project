# V9 Sentinel Pulse: phát hiện bất thường runtime Kubernetes với quyết định ML 1 giây

**Trạng thái tài liệu:** đang cập nhật cùng implementation
**Snapshot cluster:** 14-08-2026
**Mục tiêu latency:** median ≤ 1 giây, p99 kernel-to-alert ≤ 2 giây
**Trạng thái claim:** chưa công bố đạt mục tiêu cho đến khi hoàn thành blind live test

**Checkpoint live mới nhất:** collect-only Pulse đã được build bằng BTF của từng
worker, verifier chấp nhận và chạy trên cả ba worker. Gate smoke 120 giây cùng
gate union workload đều pass. Campaign normal-only bốn chế độ traffic đã được
đăng ký trước và chạy nền; chưa train model và chưa có claim latency ML.

## 1. Động cơ và phạm vi

V9 Sentinel Pulse là nhánh kiến trúc mới, độc lập với evidence V8 đã đóng băng. V8
đạt recall 195/200 với false alert quan sát bằng 0 nhưng ML path sử dụng cửa sổ
10 giây, vì vậy p99 xấp xỉ 10 giây. Pulse thay đổi telemetry và mô hình để giảm
thời gian chờ dữ liệu xuống một giây, không diễn giải lại kết quả V8 thành kết
quả của kiến trúc mới.

Fast path Tetragon vẫn có thể phát early warning, nhưng kết quả fast path và ML
path luôn được báo cáo tách biệt. Mục tiêu 1–2 giây trong tài liệu này áp dụng
cho quyết định ML.

## 2. Testbed production hiện tại

| IP | Hostname | Role | Kubernetes | Phần cứng |
|---|---|---|---|---|
| 10.1.16.234 | k8s-master.local | control plane | v1.34.10 | 32 vCPU, 64 GB RAM, 400 GB disk |
| 10.1.16.235 | k8s-master2.local | control plane | v1.34.10 | 32 vCPU, 64 GB RAM, 400 GB disk |
| 10.1.16.236 | k8s-master3.local | control plane | v1.34.10 | 32 vCPU, 64 GB RAM, 400 GB disk |
| 10.1.16.237 | k8s-worker1.local | worker | v1.34.10 | 32 vCPU, 64 GB RAM, 400 GB disk |
| 10.1.16.238 | k8s-worker4.local | worker | v1.34.10 | 32 vCPU, 64 GB RAM, 400 GB disk |
| 10.1.16.239 | k8s-worker3.local | worker | v1.34.10 | 32 vCPU, 64 GB RAM, 400 GB disk |

Ngày 14-08-2026, 6/6 node Ready. Namespace `production` có đủ 10 workload AIMS
ứng dụng (frontend và chín backend), mỗi workload hai replica. PostgreSQL CNPG
3/3 healthy; Kafka ba broker/controller và hai topic replication factor 3;
RabbitMQ 3/3; Redis 3/3 cùng Sentinel 3/3; MinIO 2/2; Istio ingress và waypoint
đều Programmed. Các PVC đều Bound.

## 3. Kiến trúc

```text
sys_enter trong kernel
  ├─ exact counter theo cgroup + syscall
  ├─ transition counter theo cgroup + process
  └─ sparse sensitive event từ Tetragon
          ↓ mỗi 1 giây
rolling feature 1–5 giây
          ↓
normal-only ExtraTrees temporal predictor
          ↓
conformal calibration theo workload role
          ↓
ML alert + latency evidence
```

Không áp cùng rate limit lên mọi syscall. Capping mỗi loại hai event/giây sẽ làm
`read=5000/s` và `connect=3/s` cùng bị quan sát gần bằng 2/s, phá hỏng tỷ lệ.
Pulse đếm chính xác trong BPF map; rate limit của Tetragon chỉ điều tiết event
chi tiết.

Feature giữ các syscall có ý nghĩa bảo mật dưới dạng cột tường minh, đồng thời
chiếu toàn bộ syscall ID vào 64 syscall hash bin và mọi cặp liên tiếp vào 64
transition bin ổn định. Tổng mỗi nhóm bin bằng một nên phân phối đầy đủ vẫn đi
vào ML; `other` không phải nơi duy nhất giữ syscall ngoài danh sách tường minh.
Hash-bin được tính ngay trong eBPF nên số map key/output mỗi cgroup bị chặn cố
định; pipeline không phải xuất mọi cặp thô và không tăng kích thước theo thời
gian soak.

## 4. Ngân sách latency đăng ký trước

| Thành phần | Mục tiêu p99 |
|---|---:|
| Chờ đủ exact-counter window | 1.000 s |
| Snapshot, resolve cgroup và feature | 0.300 s |
| ExtraTrees inference + calibration | 0.050 s |
| Queue và xuất alert | 0.350 s |
| Tổng kernel-to-alert | ≤ 2.000 s |

## 5. Mô hình ML

Mô hình chính là `ExtraTreesClassifier` self-supervised một đầu ra. Input ghép
ba cửa sổ quá khứ và cửa sổ hiện tại. Lớp normal lấy từ chuỗi normal thật; lớp
đối nghịch là corruption xác định (đổi một phần feature giữa thời điểm và scale
một phần nhỏ) sinh từ chính normal training split. Không có attack thật hoặc
MITRE label trong fit. Score được biến đổi thành conformal p-value bằng normal
calibration split; blind attack không được dùng để chọn feature, model,
threshold hoặc alpha.

Với `alpha=10^-4`, split calibration phải có tối thiểu 9.999 example cho từng
candidate thì conformal p-value nhỏ nhất mới có thể đạt alpha. Trainer hiện
fail-closed nếu không đủ độ phân giải này; không còn tạo model từ vài trăm
window rồi báo detector hoạt động. Đây mới là điều kiện toán học tối thiểu,
không phải bảo đảm false-positive ngoài phân phối bằng 0.

Thiết kế này sử dụng lịch sử thật giữa các cửa sổ, khác LSTM V8 có sequence
length bằng một. Classifier một đầu ra với depth/leaf bị chặn tránh artifact
multi-output quá lớn, inference nhẹ hơn LSTM và không cần chờ cửa sổ tương lai
thứ hai.

## 6. Độ phủ workload

Không dùng chung một threshold cho tất cả role. Các profile dự kiến gồm:

- stateless HTTP service;
- frontend;
- PostgreSQL;
- Kafka broker/controller và entity operator;
- RabbitMQ;
- Redis và Redis Sentinel;
- MinIO;
- Istio gateway/waypoint.

Pod mới resolve về tên controller ổn định bằng cách loại ReplicaSet hash hoặc
StatefulSet ordinal; container leaf được tách riêng để sidecar không làm nhiễu
process chính. Role chỉ phục vụ phân tầng phân tích; runtime không tự fallback
sang model role. Model/threshold tách theo workload và container. Workload chưa
có model chạy ở chế độ collect-only, không tự động kế thừa threshold của
workload khác.

## 7. Tiến độ implementation

| Hạng mục | Trạng thái 14-08-2026 |
|---|---|
| Audit AIMS và dependency | Hoàn thành; application/dependency healthy |
| Xác minh traffic | Đã apply và live-check: HTTP health/ingress, Redis AUTH+PING, MinIO health, PostgreSQL/Kafka/RabbitMQ TCP |
| Feature schema exact counter + transition | Đã implement local, 249 chiều |
| ExtraTrees normal-only + conformal score | Đã implement, chưa fit; chờ campaign normal-only hoàn tất |
| eBPF collector theo cgroup | Đã build/verifier và active trên 3/3 worker |
| Tetragon high-volume rate limit 500 ms | Policy Pulse tên riêng đã staging; V8 vẫn 1 giây; chưa apply, chờ A/B |
| Dataset 1 giây đa workload | Campaign `sentinel-pulse-normal-20260814T075831Z` đang chạy nền |
| Đóng băng capture bất biến | Finalizer đã arm trên 3/3 worker; tự rotate sau contract + 10 giây |
| Blind attack và latency CDF | Chưa chạy |
| Capture integrity/ingest-lag validator | Đã implement local |
| Model artifact integrity | Manifest v2 khóa SHA-256/size/metadata; runtime verify trước unpickle |
| Independent normal-soak evaluator | Đã implement Wilson 95% CI và wall-clock gate theo workload |
| Terminal candidate decision | Đã implement; chỉ mở overhead evaluation, không auto-promote |
| Multi-node dataset provenance | Contract + node-finalizer manifest + source/dataset hash bắt buộc khớp trước assemble |
| Canary-first worker rollout | Hoàn thành; 3/3 node pass smoke và union đủ 18/18 workload |

### 7.1 Kết quả rollout collect-only trên cụm

| Worker | Rows/120 giây | Ingest p99 | Snapshot-read p99 | Integrity | Identity |
|---|---:|---:|---:|---|---|
| k8s-worker1.local | 1.920 | 34,08 ms | 8,74 ms | 0 loss/gap/mismatch | pass |
| k8s-worker4.local | 1.790 | 35,67 ms | 5,73 ms | 0 loss/gap/mismatch | pass |
| k8s-worker3.local | 1.295 | 25,04 ms | 4,46 ms | 0 loss/gap/mismatch | pass |

Rollout validator xác nhận đúng ba node và union đủ 18 workload ứng dụng/hạ
tầng production. Tổng cộng 5.005 feature rows được chấm trong ba slice smoke.
Các số trên chỉ đo đường collector `window_end → feature emitted`; chúng không
bao gồm inference hoặc alert và không được gọi là kernel-to-alert ML.

Canary thực tế đã phát hiện hai lỗi trước rollout: chỉ số mảng không được kernel
6.8 verifier chứng minh bounded và systemd shared runtime directory bị xóa khi
collector restart. Sau khi sửa, verifier pass. Một torn per-CPU map read trên
worker3 cũng bị gate từ chối; loader hiện retry tối đa tám lần và fail-closed
nếu không lấy được snapshot tự nhất quán, thay vì nới integrity threshold.

Evidence local nằm tại `validation-evidence/sentinel-pulse-canary/`; rollout
manifest SHA-256 là
`4a6de27f20e93767d1bb3c6dd654b4b08346b75fab691a7a598cf203ac1ec961`.

### 7.2 Campaign normal-only đang chạy

Contract `sentinel-pulse-normal-20260814T075831Z` có SHA-256
`28eb9a0f1cb945a5ebd86e1f18a6c5916cd7233c63a8ba8ef94280919f3650b8`.
Mỗi regime kéo dài sáu giờ, transition gap ba phút:

| Regime | Bắt đầu (+07) | Kết thúc (+07) |
|---|---|---|
| steady | 14-08 15:01:31 | 14-08 21:01:31 |
| toolmix | 14-08 21:04:31 | 15-08 03:04:31 |
| burst | 15-08 03:07:31 | 15-08 09:07:31 |
| recovery | 15-08 09:10:31 | 15-08 15:10:31 |

Scheduler chạy bằng transient systemd service
`sentinel-pulse-capture-campaign-v3.service`, kiểm 6/6 node Ready và zero bad
pod mỗi 30 giây, debounce ba lần liên tiếp để không reject một pod rollout thoáng
qua, lưu Deployment JSON từng regime, phục hồi steady bằng exit trap và ghi
`CAMPAIGN_FAILED` nếu dừng bất thường. Hai attempt trước được giữ làm audit
trail: attempt đầu fail trước contract do eager NumPy import; attempt v2 fail
trước interval vì health gate một mẫu bắt đúng một pod transient. Package đã
lazy import và v3 mới là contract được dùng cho training.

Để việc kết thúc không phụ thuộc phiên SSH hay thao tác thủ công, service
`sentinel-pulse-freeze@sentinel-pulse-normal-20260814T075831Z` đã được enable
và arm trên cả ba worker. Unit xác minh resolver/collector mỗi phút, đợi tới
`15-08-2026 15:10:41 +07` (contract end + 10 giây), dừng collector trong đoạn
rotate ngắn, chuyển capture sang thư mục campaign rồi khởi động collector mới
ngay. Capture đóng băng có mode chỉ đọc, SHA-256 và manifest riêng theo node;
finalizer từ chối node identity sai, không có row trong contract, capture kết
thúc sớm hoặc bất kỳ integrity counter trong contract khác 0. Tại checkpoint
`14-08-2026 15:20 +07`, cả ba finalizer `active/running`, `NRestarts=0`; ba
collector/resolver đều active và feature mới nhất đều có integrity counter 0.

Capture ghi feature schema và SHA-256 một lần, sau đó dùng vector float32 little
endian nén zlib level 1 và base64. Cách này bỏ việc lặp 249 tên cột/số float
dạng text ở từng giây nhưng vẫn stream/tail được và validator kiểm round-trip,
dimension cùng schema hash trước training.

Microbenchmark local 10.000 vector ngẫu nhiên 249 chiều cho mean encode
0,0528 ms và decode 0,0125 ms/vector. Đây chỉ là kiểm tra chi phí codec trên
laptop, không thay thế p99 ingest-lag đo trên cluster.

Đo latency tách ba đại lượng: inference time, `window_end → decision` processing
lag và true `injected_at → alert`. Chỉ đại lượng cuối, ghép bằng injection ID
độc lập và không đưa marker vào model, được phép dùng cho claim kernel-to-alert.

Collector dùng một fixed-size per-CPU sketch cho mỗi container cgroup; chính map
này đồng thời là allow-list và được đồng bộ khi rollout. Counter update không
cạnh tranh atomic giữa CPU và số key không tăng theo thời gian. Loader cộng các
CPU rồi xuất đúng một record/container/giây. Counter lỗi task-state phải bằng
0; `snapshots == targets` là gate mỗi interval. Timestamp window được lấy sau
toàn bộ map lookup để count đã bao gồm không thể xảy ra sau `window_end`.
Loader dừng fail-closed nếu allow-list đang chạy trở thành rỗng. Mỗi snapshot
ghi thêm thời gian đọc per-CPU map để đo p99 thật. Transition chỉ nối hai syscall
cùng task/cgroup cách nhau không quá năm giây, tránh tạo cạnh giả khi PID được
tái sử dụng hoặc process idle dài.

Identity temporal là tổ hợp `node_name + pod_uid + container_name + cgroup_id`,
không chỉ là cgroup ID. Vì cgroup ID chỉ có ý nghĩa cục bộ theo node và có thể
được kernel tái sử dụng, quy tắc này ngăn việc ghép nhầm capture từ ba worker;
runtime cũng warm-up lại khi pod UID đổi sau rollout.

Hot path chỉ gọi helper insert vào task-state LRU ở syscall đầu tiên của task;
những syscall tiếp theo cập nhật value tại chỗ. Tối ưu này loại helper update
khỏi đường gọi thường xuyên nhưng vẫn giữ exact count và transition order. Mức
giảm overhead thực tế chỉ được công bố sau A/B benchmark trên cluster.

Feature `seccomp_denied` hiện là cột dự phòng và chưa được dùng để claim: kernel
6.8 trên node build không expose tracepoint seccomp tại đường tracefs đã probe.
Candidate đầu tiên chỉ được đánh giá trên exact syscall/transition và sparse
Tetragon; seccomp chỉ được bật sau khi có source được kiểm chứng và test loss.

## 8. Protocol đánh giá và release gate

Candidate chỉ được xem là đạt nếu đồng thời thỏa:

1. normal soak độc lập tối thiểu 24 giờ wall-clock cho từng workload có 0 alert
   quan sát và báo cáo Wilson 95% CI; cộng nhiều replica không được dùng để giả
   đủ thời lượng;
2. recall blind attack không thấp hơn V8 (≥ 0,975), mục tiêu 200/200;
3. median kernel-to-alert ≤ 1 giây và p99 ≤ 2 giây;
4. không có telemetry loss/backpressure trong interval được chấm;
5. đo A/B CPU, RAM, throughput và response-time p50/p95/p99;
6. dataset/model/schema/manifest được khóa SHA-256 trước blind test.

## 9. Nhật ký thay đổi

- 14-08-2026: đặt tên V9 Sentinel Pulse; audit cụm và AIMS; chốt exact counters,
  transition bins, cửa sổ một giây và ExtraTrees temporal predictor; tạo code
  feature/model và tài liệu này.
- 14-08-2026: thêm resolver theo pod/container leaf, đồng bộ allow-list khi pod
  rollout và kiểm tra task-state/snapshot integrity; release gate yêu cầu các
  counter lỗi giữ bằng 0 và target coverage đầy đủ.
- 14-08-2026: bổ sung traffic health hợp lệ cho chín backend và safe handshake
  cho PostgreSQL, Kafka, RabbitMQ, Redis, MinIO; traffic generator bị loại khỏi
  tập cgroup ML để không học hành vi của chính công cụ benchmark.
- 14-08-2026: chuyển collector sang per-CPU fixed sketch và compact snapshot;
  thêm true injection-to-alert evaluator.
- 14-08-2026: thêm manifest model v2 với checksum fail-closed, calibration
  resolution gate, Wilson normal-soak evaluator, identity đa node/pod và
  snapshot read timing. Trainer tự chặn capture có telemetry loss; manifest
  khóa phiên bản Python/NumPy/scikit-learn. Dataset assembler đa node/bốn
  regime, campaign scheduler, blind marker/window identity gate và
  accuracy/latency finalizer không tự promote và canary-first deployer đã hoàn
  thành.
- 14-08-2026: build/verifier eBPF thành công trên ba worker, sửa verifier-bound,
  systemd runtime ownership, deploy-generation restart và torn per-CPU read;
  **46/46 unit test local** pass. Ba-node smoke và 18-workload union gate pass;
  traffic stateful read-only được live-check. Campaign normal-only 24 giờ đang
  chạy nền. Finalizer đóng băng capture bất biến đã arm trên 3/3 worker và không
  restart collector khi cài. Fit ExtraTrees, blind attack, latency ML và
  overhead vẫn pending.
- 14-08-2026: assembler được chuyển sang fail-closed provenance: bắt buộc
  manifest từng node khớp campaign ID, contract hash, node, capture hash/size,
  tổng row, row trong contract và zero integrity; capture còn quyền ghi bị từ
  chối. Bản contract cùng snapshot Deployment pha steady đã được kéo về local,
  chmod chỉ đọc và đối chiếu hash `28eb9a0f...` thành công.
- 14-08-2026: temporal loader tách sequence khi khoảng cách hai window lớn hơn
  1,5 giây hoặc khi đổi traffic regime. Vì vậy lịch sử không thể nối giả qua
  transition gap ba phút. Checkpoint campaign 17:08 +07 đạt 8,78%, vẫn steady,
  6/6 node Ready, zero bad pod/warning/restart. Full regression đạt **287
  passed, 7 skipped**.
- 14-08-2026: refactor đường nạp dataset nhiều triệu row: không giữ toàn bộ
  JSON record và Python-float list trong RAM; mỗi source chỉ giữ timestamp,
  regime và vector rồi compact thành contiguous NumPy `float32` theo sequence.
  Model input/temporal split không đổi; full regression vẫn **287 passed, 7
  skipped**.
- 14-08-2026: giới hạn peak RAM trong model fit: temporal context được
  preallocate, corruption và calibration prediction chia batch 8.192 row,
  scale factor chỉ sinh cho phần tử được chọn và giữ `float32`. Report model ghi
  `fit_matrix_bytes`; full regression đạt **289 passed, 7 skipped**.
