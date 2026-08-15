# Sentinel Pulse: phát hiện bất thường runtime Kubernetes với quyết định ML 1 giây

**Trạng thái tài liệu:** đang cập nhật cùng implementation
**Snapshot cluster:** 15-08-2026
**Mục tiêu latency:** median ≤ 1 giây, p99 kernel-to-alert ≤ 2 giây
**Trạng thái claim:** chưa công bố đạt mục tiêu cho đến khi hoàn thành blind live test

**Checkpoint live mới nhất:** campaign normal-only bốn chế độ traffic đã
terminal thành công. Dataset 5,55 GB gồm 3.594.513 window hợp lệ đã
khóa SHA-256; 20/20 ExtraTrees candidate đã train, verify checksum và
load lại thành công, không có workload collect-only. Replay normal tươi ngay
sau training có 1.631 decision, 0 alert; inference p99 30,83 ms. Đây là
bounded smoke. Raw one-window candidate sau đó **fail live canary** do 1 alert
normal Redis trong 2.175 scored decision và đã bị dừng, không rollout. Candidate
composite mới giữ nguyên model nhưng khóa same-window semantic policy
`79564746...`; development replay 5.000 row có 2 raw anomaly được ghi
`suppressed`, 0 alert. Canary độc lập mới pass 4.719 normal, 1 suppressed,
0 alert; soak `semantic-soak-a1` đã active trên 3/3 worker và đủ 20
workload. Chưa đủ 24 giờ/blind 450 trial, nên chưa công bố đạt gate.

## 1. Động cơ và phạm vi

Sentinel Pulse là nhánh kiến trúc mới, độc lập với evidence V8 đã đóng băng. V8
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

Ngày 15-08-2026, 6/6 node Ready. Namespace `production` có đủ 10 workload AIMS
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

| Hạng mục | Trạng thái 15-08-2026 |
|---|---|
| Audit AIMS và dependency | Hoàn thành; application/dependency healthy |
| Xác minh traffic | Đã apply và live-check: HTTP health/ingress, Redis AUTH+PING, MinIO health, PostgreSQL/Kafka/RabbitMQ TCP |
| Feature schema exact counter + transition | Đã implement local, 249 chiều |
| ExtraTrees normal-only + conformal score | 20/20 model fit/load pass; raw decision policy fail canary, semantic-policy candidate đang canary lại |
| eBPF collector theo cgroup | Đã build/verifier và active trên 3/3 worker |
| Tetragon high-volume rate limit 500 ms | Policy Pulse tên riêng đã staging; V8 vẫn 1 giây; chưa apply, chờ A/B |
| Dataset 1 giây đa workload | Terminal: 3.594.513 row, 20 workload/container, 4 traffic regime, integrity 0 |
| Đóng băng capture bất biến | Finalizer đã arm trên 3/3 worker; tự rotate sau contract + 10 giây |
| Blind attack và latency CDF | Chưa chạy |
| Capture integrity/ingest-lag validator | Đã implement local |
| Model artifact integrity | Manifest v2 khóa SHA-256/size/metadata; runtime verify trước unpickle |
| Independent normal-soak evaluator | Đã implement; run `semantic-soak-a1` active 3/3 worker từ 15-08 21:50:19 +07 |
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

### 7.2 Campaign normal-only và dataset terminal

Contract `sentinel-pulse-normal-20260814T075831Z` có SHA-256
`28eb9a0f1cb945a5ebd86e1f18a6c5916cd7233c63a8ba8ef94280919f3650b8`.
Mỗi regime kéo dài sáu giờ, transition gap ba phút:

| Regime | Bắt đầu (+07) | Kết thúc (+07) |
|---|---|---|
| steady | 14-08 15:01:31 | 14-08 21:01:31 |
| toolmix | 14-08 21:04:31 | 15-08 03:04:31 |
| burst | 15-08 03:07:31 | 15-08 09:07:31 |
| recovery | 15-08 09:10:31 | 15-08 15:10:31 |

Scheduler đã chạy bằng transient systemd service
`sentinel-pulse-capture-campaign-v3.service`, kiểm 6/6 node Ready và zero bad
pod mỗi 30 giây, debounce ba lần liên tiếp để không reject một pod rollout thoáng
qua, lưu Deployment JSON từng regime, phục hồi steady bằng exit trap và ghi
`CAMPAIGN_FAILED` nếu dừng bất thường. V3 terminal `success` lúc
15:10:34 +07 và trả traffic về steady `1/0/1`. Hai attempt trước được giữ làm audit
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
thúc sớm hoặc bất kỳ integrity counter trong contract khác 0. Cả ba
finalizer terminal `success`, khóa capture mode `0444`; checksum đích khớp
manifest và mọi integrity counter bằng 0. Collector sau rotate khởi động lại
trên inode live mới và hiện vẫn active.

Assembler chỉ nhận row nằm hoàn toàn trong bốn measured interval, loại
93.702 row thuộc transition gap/ngoài contract. Dataset terminal có
3.594.513 row: steady 896.469, toolmix 902.522, burst 904.702 và recovery
890.820. File 5.548.144.482 byte có SHA-256
`40a97f55338e64c50ab929247ded386a9afcd83c795c4c20cdfdb9138f93dd16`.
Full validator trả `valid=true`, 249 feature, 20 workload/container, zero
loss/integrity; ingest lag p99 38,55 ms và snapshot-read p99 6,01 ms.

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

### 7.3 Candidate model terminal và live-normal smoke

Training unit terminal `success`, exit code 0 và không restart. Bundle có
20/20 `PulseExtraTrees` candidate, 0 collect-only, 2.472.376 train example và
1.064.315 calibration example. Workload ít nhất có 25.845 calibration
example, vượt gate 9.999 của `alpha=10^-4`. Tổng artifact là
181.555.755 byte. Manifest SHA-256 là
`b7e603fdd23bb61b71ba09e171116ac6f05bf74699c2a62e51f5e719d50718cc`;
detached checksum, hash/size từng artifact, software provenance và runtime load
20/20 đều pass. Tất cả file bundle đã đổi sang mode `0444`.

Một bounded replay dùng 1.800 feature row live thu sau khi training hoàn tất,
không nằm trong dataset fit. Kết quả bao phủ 20 workload: 1.631 normal,
169 warm-up, **0 alert và 0 parsing/runtime error**. Inference p50/p95/p99/max
là 17,72/26,04/30,83/35,24 ms. Kết quả này chỉ chứng minh bundle có thể
load và score live data trong budget 50 ms; nó không được gọi là soak 24
giờ, bằng chứng zero false-positive, recall hay kernel-to-alert terminal.
Evidence checksum-bound nằm trong
`validation-evidence/sentinel-pulse-campaign/sentinel-pulse-normal-20260814T075831Z/model-candidate/`.

### 7.4 Raw candidate fail và same-window semantic candidate

Canary realtime đầu tiên trên `k8s-worker1.local` không được rollout sang
worker khác. Trong span 135,41 giây, detector ghi 2.175 normal, 48 warm-up
và **1 alert normal** trên `production/aims-redis:aims-redis`; vì vậy report
`valid=false` và service được disable/stop. Raw alert có score 0,60958,
conformal p-value 1,2897e-5, inference 13,99 ms và processing lag 289,70 ms.
Toàn canary có inference p99 39,78 ms, processing p99 426,87 ms, nhưng
latency tốt không bù được false alert.

Context ±8 window cho thấy alert là spike đơn lẻ không có syscall bảo mật;
window kế tiếp có health/probe process burst lớn hơn nhưng model chấm normal.
Ba integrity counter của collector vẫn 0, nên không được reject như
infrastructure failure. Evidence này được giữ nguyên tại
`.../canary-failed-b7e603fd/`; raw candidate được xem là failed.

Trước khi chạy bất kỳ blind outcome nào, decision policy mới được
khóa SHA-256
`795647467c2aeb5b09494bfb0b7254f931a72a4495244fdf4e1ec49ec07c6a1a`.
Nó chỉ alert khi cùng một window thỏa `raw ML anomaly` và có generic
security activity như connect, clone, exec, identity/capability, namespace hay
seccomp. Không đợi window thứ hai; raw anomaly không corroborated được ghi
rõ là `suppressed` cùng score/p-value, không bị xóa. Development replay
5.000 normal row ghi 4.950 normal, 48 warm-up, 2 suppressed, 0 alert/0 error;
inference p99 31,20 ms. Kết quả này chỉ dùng để tạo candidate policy;
normal canary/soak sau thời điểm freeze phải là evidence độc lập mới.

Bounded live canary mới trên worker1 sau policy freeze chạy 294,87 giây:
4.719 normal, 48 warm-up, 1 raw anomaly suppressed, 0 alert. Inference p99
38,94 ms, processing p99 431,23 ms, model/policy identity đều pass; report
`valid=true`. Sau gate này, candidate được rollout audit-only trên cả ba
worker. Union preflight có 4.066 decision, 0 alert, 3/3 service active,
`NRestarts=0`, cùng model/policy/run identity và đủ 20/20 workload.

Soak chính thức dùng run ID thời gian-trung-lập `semantic-soak-a1`, mốc
bắt đầu bảo thủ `15-08-2026 21:50:19 +07`; sớm nhất được finalize
là `16-08-2026 21:50:19 +07`. Marker khóa model SHA, policy SHA, duration
24 giờ/workload, coverage 95%, alert budget 0 và xác nhận blind evaluation
chưa khởi động. Slice staging mang nhãn timestamp trước đó chỉ được
giữ là rollout audit, không tính vào 24 giờ.

## 8. Protocol đánh giá và release gate

Candidate chỉ được xem là đạt nếu đồng thời thỏa:

1. normal soak độc lập tối thiểu 24 giờ wall-clock cho từng workload có 0 alert
   quan sát và báo cáo Wilson 95% CI; cộng nhiều replica không được dùng để giả
   đủ thời lượng;
2. recall blind attack không thấp hơn V8 (≥ 0,975), mục tiêu 450/450 trên ma
   trận Pulse 18 workload × 5 scenario × 5 trial;
3. median kernel-to-alert ≤ 1 giây và p99 ≤ 2 giây;
4. không có telemetry loss/backpressure trong interval được chấm;
5. đo A/B CPU, RAM, throughput và response-time p50/p95/p99;
6. dataset/model/schema/manifest được khóa SHA-256 trước blind test.

## 9. Nhật ký thay đổi

- 14-08-2026: khởi tạo nhánh Sentinel Pulse; audit cụm và AIMS; chốt exact counters,
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
- 14-08-2026: checkpoint 19:56 +07 đạt 20,33% campaign, vẫn steady; 6/6 node
  Ready và zero bad pod/warning/restart. Ba collector/resolver/finalizer đều
  active; record cuối integrity 0, emit lag 15–34 ms. Capture hiện khoảng
  456/407/302 MB và worker ít trống nhất còn 57 GiB.
- 14-08-2026: detector JSONL follower nhận biết atomic inode replacement và
  truncation, tự mở capture mới từ đầu thay vì đứng vĩnh viễn ở EOF inode cũ.
  Checkpoint 20:33 +07 đạt 22,89%; steady replica đúng contract `1/0/1`, zero
  bad pod/warning/restart. Full regression đạt **291 passed, 7 skipped**.
- 14-08-2026: transition toolmix thành công; measured interval bắt đầu 21:04:31
  +07 sau đúng gap ba phút. Replica base/readmix/dependency đạt `2/4/2`, mọi
  observed generation khớp, 6/6 node Ready và integrity ba worker bằng 0.
  Snapshot read-only SHA-256 `b9590c1a...`; campaign đạt 35,94% lúc 23:42 +07.
- 15-08-2026: đồng nhất temporal boundary giữa train và live detector. Runtime
  xóa history/warm-up khi gap lớn hơn 1,5 giây hoặc đổi traffic regime, và
  fail-closed với window timestamp không tăng; do đó không ghép score qua
  transition không tồn tại trong training. Full regression đạt **293 passed,
  7 skipped**. Checkpoint 00:07 +07 đạt 37,66%, toolmix vẫn khỏe; 6/6 node
  Ready, zero bad pod/restart/integrity error, traffic giữ đúng `2/4/2`.
- 15-08-2026: khóa `max_contiguous_gap_seconds=1.5` trong model manifest dưới
  detached SHA-256. Runtime dùng đúng contract của artifact và runtime/finalizer
  đều từ chối giá trị thiếu, không hữu hạn hoặc không dương. Regression giữ
  nguyên **293 passed, 7 skipped**.
- 15-08-2026: thêm model-identity chain: mỗi decision mang manifest SHA-256;
  normal/blind evaluator fail với identity thiếu hoặc bị trộn; finalizer bắt
  cả hai report khớp đúng bundle đang review. Negative tests khóa mixed model
  và cross-model report; full regression đạt **295 passed, 7 skipped**.
- 15-08-2026: normal-soak gate chuyển sang unique one-second bucket/workload,
  yêu cầu span 24 giờ và coverage ≥95%, nên replica count hay vài timestamp
  endpoint không thể giả đủ wall-clock. Finalizer khóa protocol 86.400 window,
  24 giờ/workload, 95% coverage, 0 alert và từ chối report dùng threshold yếu
  hơn. Full regression đạt **297 passed, 7 skipped**. Checkpoint 00:16 +07 đạt
  38,27%; campaign/toolmix và traffic `2/4/2` vẫn khỏe.
- 15-08-2026: preregister blind contract riêng cho Pulse, SHA-256
  `b47cb7f91fc4b1e83475917e700d9c0adc41b596af0f624ba52c92fc77bc5751`.
  Ma trận đầy đủ gồm 18 workload × 5 scenario × 5 seed/rate = 450 injection;
  đây không phải diễn giải lại 200 trial V8. Trainer khóa contract hash vào
  model manifest; latency evaluator và finalizer yêu cầu đủ đúng Cartesian
  matrix, safety contract và test-set selection policy. Full regression đạt
  **299 passed, 7 skipped**.
- 15-08-2026: blind marker phải khóa đồng thời controller, full workload key,
  container và cgroup ID; evaluator đối chiếu `production/controller:container`
  trước khi chấp nhận matrix row. Cross-workload relabel bị fail-closed. Full
  regression đạt **300 passed, 7 skipped**.
- 15-08-2026: campaign chuyển sang burst đúng profile `6/2/3`; checkpoint 08:04
  +07 đạt 70,61%. Ba collector/resolver/finalizer active, integrity 0,
  window-to-emit 19,52–25,62 ms. Giữ nguyên một transient warning do Trivy và
  Velero Job cùng `ContainerCreating` tại một sample; hai Job sau đó Completed,
  warning không lặp đủ failure threshold và campaign vẫn active. Burst snapshot
  SHA-256 `b42c0690...`, warning SHA-256 `b55cf49b...`.
- 15-08-2026: refactor health gate cho campaign sau: pod mới có grace 300 giây,
  Failed/Unknown bị chặn ngay, Pending hoặc Running-unready quá grace bị chặn.
  Cách này loại warning giả từ Job vừa tạo và bắt được CrashLoop/unready mà
  phase-only filter cũ bỏ sót. Campaign hiện tại không hot reload thay đổi.
  Full regression đạt **303 passed, 7 skipped**.
- 15-08-2026: chuẩn bị venv train riêng trên control plane; khóa Python 3.12.3,
  NumPy 2.5.2, scikit-learn 1.9.0, SciPy 1.18.0, joblib 1.5.3,
  threadpoolctl 3.6.0 và narwhals 2.24.0. Manifest/runtime/finalizer đối chiếu
  đầy đủ software provenance; chưa fit trước khi normal capture đóng băng.
- 15-08-2026: post-capture preflight lúc 08:10 +07 pass: health classifier trả
  zero unhealthy pod, control plane còn 245 GiB disk/54 GiB RAM available và
  ba CLI assemble/validate/train chạy được trong locked venv. Campaign vẫn ở
  burst `6/2/3`; chưa assemble/train trước final freeze.
- 15-08-2026: recovery bắt đầu đúng 09:10:31 +07 sau rollout đóng 09:07:34;
  traffic đạt `1/0/1`, checkpoint 09:35 đạt 76,87%. Ba collector/resolver/
  finalizer active, integrity 0, emit 16,02–28,42 ms. Giữ một legacy transient
  warning lúc 09:09:35 nhưng pod đã biến mất trước detail query; không lặp,
  hiện age-aware health trả zero unhealthy. Recovery snapshot SHA-256
  `9a124272...`, warning SHA-256 `f83ad598...`.
- 15-08-2026: schedule/finalizer terminal success; ba frozen capture read-only
  tổng 5,39 GB, SHA-256 đích khớp manifest và integrity 0. Assemble đầu tiên
  fail-closed do node-manifest v1 đếm full campaign span nhưng assembler đếm
  disjoint measured intervals. Sửa compatibility không đổi evidence: v1 field
  được verify như `campaign_span_rows`; finalizer tương lai phát manifest v2.
  Regression đạt **304 passed, 7 skipped**.
- 15-08-2026: dataset terminal 5,55 GB, SHA-256 `40a97f55...`, gồm 3.594.513
  measured row gần cân bằng bốn regime; 93.702 row ngoài measured intervals bị
  loại. Full validation pass: 0 error/loss, 249 feature, 20 workload/container,
  ingest-lag p99 38,55 ms và snapshot-read p99 6,01 ms. Candidate training đã
  chạy nền với quota 16 core/48 GiB; chưa có model/latency claim.
- 15-08-2026: candidate training terminal `success`: 20/20 model, 0 collect-only,
  manifest `b7e603fd...`, bundle read-only và runtime load gate pass. Fresh
  live-normal smoke 1.800 row bao phủ 20 workload có 0 alert/0 error;
  inference p99 30,83 ms. Soak 24 giờ, blind 450 trial, true kernel-to-alert
  và overhead A/B vẫn pending, nên chưa promote/claim terminal.
- 15-08-2026: raw one-window model fail canary do 1 normal Redis alert/2.175
  scored decision; evidence được giữ và service dừng trước rollout. Khóa
  same-window semantic policy `79564746...` trước blind evaluation;
  development replay 5.000 row có 2 suppressed raw anomaly và 0 alert. Full
  regression sau policy/provenance hardening đạt 353 passed, 2 warning.
- 15-08-2026: semantic live canary 294,87 giây pass với 4.719 normal,
  1 suppressed, 0 alert; inference/processing p99 38,94 ms/431,23 ms. Rollout
  3/3 worker union đủ 20 workload. Soak `semantic-soak-a1` bắt đầu bảo
  thủ 21:50:19 +07, finalize sớm nhất sau 21:50:19 +07 ngày 16-08;
  blind evaluation vẫn chưa chạy.
