# Sentinel Pulse: phát hiện bất thường runtime Kubernetes với quyết định ML 1 giây

**Trạng thái tài liệu:** đang cập nhật cùng implementation
**Snapshot cluster:** 17-08-2026
**Mục tiêu latency:** median ≤ 1 giây, p99 kernel-to-alert ≤ 2 giây
**Trạng thái claim:** chưa công bố đạt mục tiêu cho đến khi hoàn thành blind live test

**Checkpoint live mới nhất:** model ExtraTrees và dataset normal-only
3.594.513 window vẫn giữ nguyên checksum. Policy V3 `382e4562...` fail normal
soak sau 1.985.317 decision với 8 alert tập trung trong probe-storm 5,95 giây;
evidence 2,7 GB đã freeze, blind chưa chạy. Policy V4 `272e9119...` được dựng
chỉ từ normal development evidence có checksum. Full replay V3 cho 0 projected
alert; regression 367 test pass. Canary V4 351,05 giây có 5.599 scored,
1 suppressed, 0 alert/restart; inference p99 39,68 ms và
window-start-to-decision p99 1,433 giây. Independent soak
`semantic-envelope-soak-d1` đã terminal fail sau 1.386.260 decision vì 2 normal
alert trên MinIO sidecar và auth-service; detector candidate đã dừng, evidence
2,1 GB đã freeze và blind 450 trial chưa được mở.

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

| Hạng mục | Trạng thái 16-08-2026 |
|---|---|
| Audit AIMS và dependency | Hoàn thành; application/dependency healthy |
| Xác minh traffic | Đã apply và live-check: HTTP health/ingress, Redis AUTH+PING, MinIO health, PostgreSQL/Kafka/RabbitMQ TCP |
| Feature schema exact counter + transition | Đã implement local, 249 chiều |
| ExtraTrees normal-only + conformal score | 20/20 model fit/load pass; model giữ nguyên; semantic V1/V2/V3 fail normal gate; extended-envelope V4 pass canary và đang soak độc lập |
| eBPF collector theo cgroup | Đã build/verifier và active trên 3/3 worker |
| Tetragon high-volume rate limit 500 ms | Policy Pulse tên riêng đã staging; V8 vẫn 1 giây; chưa apply, chờ A/B |
| Dataset 1 giây đa workload | Terminal: 3.594.513 row, 20 workload/container, 4 traffic regime, integrity 0 |
| Đóng băng capture bất biến | Finalizer đã arm trên 3/3 worker; tự rotate sau contract + 10 giây |
| Blind attack và latency CDF | Chưa chạy |
| Capture integrity/ingest-lag validator | Đã implement local |
| Model artifact integrity | Manifest v2 khóa SHA-256/size/metadata; runtime verify trước unpickle |
| Independent normal-soak evaluator | Đã implement; V1/V2/V3/V4 đều terminal fail và frozen; không có soak active |
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

Run tiếp theo dùng ID thời gian-trung-lập `semantic-soak-a1`, bắt đầu bảo thủ
`15-08-2026 21:50:19 +07`. Marker đã khóa model SHA, policy SHA, duration
24 giờ/workload, coverage 95%, alert budget 0 và xác nhận blind evaluation
chưa khởi động. Tuy nhiên run này fail trước terminal gate; evidence và bản
sửa kế tiếp được mô tả tại Mục 7.8. Slice staging mang nhãn timestamp trước đó
chỉ được giữ là rollout audit, không tính vào bất kỳ soak terminal nào.

### 7.8 Soak v1 thất bại và candidate calibration-margin v2

Run `semantic-soak-a1` không được để chạy đủ 24 giờ sau khi điều kiện
`maximum_alerts=0` đã bị phá. Snapshot bất biến trên control plane giữ 31.744,
31.344 và 22.761 record tương ứng worker1/worker4/worker3; tổng cộng 2 alert,
6 suppressed và không có dòng decision JSON hỏng. Hai alert normal là
`production/catalog-service:app` (score 0,622303) và
`production/aims-postgres-cnpg:postgres` (score 0,555267). Journal worker4
chứng minh crash tại `json.loads` trên một fragment JSON chưa kết thúc; systemd
tự phục hồi sau khoảng 5 giây. Đây là lỗi reader concurrency, không phải lỗi
collector integrity, nên run bị đánh dấu failed thay vì loại evidence.

Policy v2 không sửa model, alpha, dataset hay blind contract. Với mỗi workload,
runtime lấy score lớn nhất đã nằm sẵn trong normal calibration artifact và chỉ
cho semantic gate tạo alert khi score hiện tại còn vượt mức đó ít nhất 0,01.
Hai FP phát triển có excess lần lượt 0,001955 và -0,052929, vì vậy replay dưới
policy mới ghi `suppressed`; report replay SHA-256 là `2a9587ea...`. Mọi raw
anomaly, score, p-value, calibration max và excess vẫn được ghi để không che
giấu lỗi model. Không có second-window wait nên ngân sách latency 1–2 giây
không đổi.

Canary v2 dùng PID duy nhất, `NRestarts=0`, span 327,92 giây, 5.296 record gồm
5.248 decision có schema và 48 warm-up; 0 alert/0 raw anomaly. Inference
p50/p95/p99 là 18,89/31,31/39,26 ms; `window_end → decision` p50/p95/p99 là
212,42/372,58/421,17 ms. Full regression sau sửa đạt **357 passed, 2 warning**.
Soak mới khóa model SHA `b7e603fd...`, policy SHA `71c6ed92...`, run ID
`semantic-margin-soak-b1`, bắt đầu bảo thủ `2026-08-15 22:39:55 +07` và không
được finalize trước `2026-08-16 22:39:55 +07`. Blind marker vẫn false.

### 7.9 Workload-normal semantic envelope v3

Run `semantic-margin-soak-b1` fail-fast ở 10 giờ 23 phút với 1.560.418
decision: 5 alert, 171 suppressed, 0 JSON hỏng và 0 detector restart. Bốn alert
là Redis Sentinel có 10–12 socket/connect mỗi giây; alert còn lại là Kafka
Topic Operator có một clone cùng một mprotect. Đây đều nằm trong normal
behavior của dependency, không phải infrastructure failure. Failure summary
SHA-256 là `099b1a70...`; blind marker vẫn false.

CLI `calibrate_semantic_envelope` quét toàn bộ 3.594.513 normal window và dựng
normal maximum cho năm nhóm đã ánh xạ từ threat contract: socket beacon,
process fanout, identity transition, credential open và namespace probe. Scan
107,84 giây cho 20/20 workload; report SHA-256 `0ef72330...`. Policy v3 chỉ
corroborate raw ML anomaly nếu nhóm hiện tại vượt workload normal max ít nhất
4 operation; namespace primitive có normal max 0 nên dùng excess 1. Score vẫn
phải vượt calibration max 0,01 và không chờ window thứ hai. Replay bằng exact
feature của 5 FP cho 0 alert/5 suppressed, report SHA-256 `cfac018d...`.

Canary v3 span 331,93 giây có 5.346 record, 5.298 scored, một raw anomaly
suppressed, 0 alert và `NRestarts=0`. Inference p50/p95/p99 là
18,84/31,46/39,04 ms; processing p50/p95/p99 là
210,25/372,52/425,78 ms. Full regression đạt **362 passed, 2 warning**, gồm cả
test calibrator/provenance. Run
`semantic-envelope-soak-c1` khóa model `b7e603fd...`, policy `382e4562...`, bắt
đầu `2026-08-16 09:21:12 +07`, chỉ được finalize từ
`2026-08-17 09:21:12 +07`. Blind 450 trial tiếp tục bị interlock.

### 7.10 Probe-storm failure V3 và extended-normal envelope V4

V3 không đạt normal gate. Fail-fast checkpoint giữ nguyên 1.985.317 decision
trong 47.873,49 giây: 1.948.138 normal, 317 suppressed, 36.854 warming,
8 alert, 0 JSON lỗi và 0 restart. Tám alert nằm trong một span 5,95 giây trên
Kafka, Redis, Redis Sentinel và catalog. Cùng thời điểm đó, Kubernetes ghi bảy
probe timeout trên worker1; Kafka worker4 tăng reconnect khi broker worker1
chậm. Marker bắt đầu là `2026-08-16 09:21:12,568834 +07`; cửa sổ alert đầu
tiên là `2026-08-16 22:22:11,215323 +07`, chênh chính xác 13 giờ 00 phút
58,646 giây. Đây chỉ là tương quan thời gian, chưa chứng minh probe timeout hay
reconnect là nguyên nhân của alert. Kết luận được phép là canary 331,93 giây đã
không quan sát thấy sự cố xuất hiện muộn này. Run V3 vẫn terminal `failed`;
blind marker vẫn false.

Full evidence 2,7 GB được sao chép trước khi phân tích và chuyển mode `0444`.
Failure summary SHA-256 `8bfc68bc...`. Audit độc lập ngày 16-08 phát hiện
index gốc SHA-256 `9d226a22...` có một dòng thừa `./SHA256SUMS.tmp`: file tạm
đang được ghi đã bị atomic rename thành `SHA256SUMS`. Không có evidence data
nào đổi hoặc sai hash. Index sửa bất biến `SHA256SUMS.v2` kiểm đủ 18/18 file,
SHA-256 `3e9b8fb9...`; correction record SHA-256 `ca797d15...` giữ lại cả hash
index gốc và mô tả lỗi. V4 vẫn tham chiếu hash index gốc để không viết lại lịch
sử; correction là provenance bổ sung, không đổi model, threshold hay decision
semantics nên independent soak không bị khởi động lại. Bundle còn giữ cluster
events, pod/node snapshot, Redis probe spec và Prometheus incident window. Bản
local giữ summary, marker, tám alert, extension report và correction index;
decision log đầy đủ nằm trên control plane để tránh đưa 2,7 GB vào Git.

`extend_semantic_envelope.py` kiểm toàn bộ target trong checksum index tồn tại,
kiểm checksum từng source, summary `failed`,
model/policy/run identity, row/alert totals và cấm mọi attack marker. Nó dùng
1.948.463 scored normal row làm development evidence cho policy mới, không tái
gán V3 thành pass. Extension thay maxima tại 10/20 workload, report SHA-256
`80d8a008...`. V4 giữ model `b7e603fd...`, score margin 0,01, năm semantic
group và quyết định một cửa sổ; policy SHA-256 `272e9119...`. Full development
replay cho 1.948.138 normal, 325 suppressed, 36.854 warming, 0 alert; report
SHA-256 `635ceb09...`. Primitive namespace (`mount`, `unshare`, `setns`,
`ptrace`, `pivot_root`, `execveat`) vẫn trigger từ một event trên workload có
normal max bằng 0. Full suite đạt 367 pass, 2 cảnh báo deprecation Torch.

Canary V4 worker1 span 351,05 giây ghi 5.647 row, 5.599 scored, 1 suppressed,
0 alert/restart. Inference p50/p95/p99 là 19,53/31,82/39,68 ms;
post-window processing p99 429,26 ms; window-start-to-decision p50/p95/p99 là
1,219/1,381/1,433 giây. Report `valid=true`, SHA-256 `a3ee8fbd...`.
Worker4/worker3 preflight tiếp theo có 1.071/817 decision và 0 alert/restart.

Independent soak `semantic-envelope-soak-d1` bắt đầu bảo thủ lúc
`2026-08-16 23:04:35 +07`, model/policy được khóa trong marker SHA-256
`c7a065c7...`. Preflight phút đầu trên ba worker có 4.714 decision, 0 alert,
0 restart; cluster 6/6 Ready và zero unhealthy pod. Gate sớm nhất là
`2026-08-17 23:04:35 +07`, yêu cầu 24 giờ/workload, coverage ≥95%, alert budget
0 và identity/integrity pass. Không được chạy blind 450 trial trước gate này.

Checkpoint audit khoảng `2026-08-16 23:21 +07` đọc trực tiếp ba decision log:
worker1 16.434, worker4 15.192 và worker3 11.153, tổng 42.779 decision; 0/3
alert log có record, detector cùng run-id còn sống, 6/6 node Ready và 0 pod
ngoài `Running/Succeeded`. Đây là trạng thái trung gian, chưa phải kết quả 24
giờ.

### 7.11 V4 terminal fail và hardening normal-soak provenance

Audit trực tiếp ngày 17-08 phát hiện worker1 đã ghi hai alert vào
`semantic-envelope-soak-d1`. Alert đầu ở `2026-08-17 04:41:38 +07`, sau marker
5 giờ 37 phút 03,080 giây; alert thứ hai sau đó 3,224 giây. Candidate bị dừng
fail-fast trên cả ba worker, trong khi collector, resolver và workload
production tiếp tục chạy. Run có 1.386.260 decision: 1.359.677 normal, 672
suppressed, 25.909 warming, 2 alert, 0 JSON lỗi và 20 workload. Khoảng quan sát
từ marker tới record cuối là 33.385,25 giây, chỉ 9,27 giờ; 1.344 scored record
trước marker bảo thủ bị ghi riêng và không được tính vào protocol.

Hai alert thuộc `aims-minio-pool-0:sidecar` (`socket=3`, `connect=3`) và
`auth-service:app` (`clone3=11`). Trong cửa sổ incident 60 giây có 809 decision,
93 raw anomaly, 91 suppressed và 2 alert; post-window processing max tăng tới
8,531 giây. Prometheus cùng khoảng thời gian ghi worker1 load1 từ 3,63 tới
25,10 và CPU từ 46,52% tới 78,87%. Đây là tương quan, không chứng minh node
pressure gây alert và không được dùng để xóa/relabel failure.

Bundle thất bại 2,1 GB giữ đầy đủ ba decision/alert log, journal, cluster
snapshot, model artifacts và policy runtime. Tất cả 36/36 file xác minh hash
trước khi chuyển read-only. Failure summary SHA-256 `c7ce30eb...`, bundle index
`c45c3cdc...`; incident analysis SHA-256 `6da74326...`, analysis index
`51dc99d0...`. Marker tiếp tục `blind_evaluation_started=false`.

Audit code đồng thời phát hiện evaluator cũ chưa bắt buộc bind
`SOAK_START.json`. Evaluator mới loại record trước `started_not_before`, kiểm
`eligible_finalize_after`, run/model/policy identity và marker hash. Candidate
finalizer fail-closed nếu thiếu marker bất biến. Việc hardening provenance này
không thay đổi hoặc hồi sinh V4 đã fail. Full regression sau sửa đạt **370
passed, 2 warning** deprecation Torch.

### 7.12 Temporal-confirmation development ablation

`evaluate_temporal_confirmation.py` là evaluator development-only, không phải
runtime policy và không có quyền mở blind. Cấu hình ablation yêu cầu hai cửa
sổ ML+semantic liên tiếp cùng signal group trong tối đa 1,75 giây; nhóm
`namespace_probe` bypass ngay vì normal maximum bằng 0. Source được bind với
marker/model/policy/run identity và record trước marker bị loại.

Replay toàn bộ ba frozen V4 log có 1.359.007 scored row hợp lệ, loại đúng 1.344
row trước marker. Hai alert V4 đều là candidate semantic cô lập nên projected
thành suppressed và còn 0 projected alert. Report SHA-256 `fb069997...`, index
`e5f1e1e8...`.

Kết quả này chỉ chứng minh temporal rule xử lý được development-normal evidence
đã biết. Nó không chứng minh recall, precision hay latency trên attack. Với
window một giây, confirmation thêm một window có nguy cơ đẩy p99 vượt 2 giây;
vì vậy chưa deploy candidate mới. Bước kế tiếp phải benchmark rolling/overlap
hoặc semantic telemetry giàu ngữ cảnh rồi mới khóa policy trước blind.
Full regression gồm evaluator mới đạt **376 passed, 2 warning** deprecation
Torch.

### 7.13 Operational-latency tail trên toàn bộ V4 normal evidence

Evaluator marker-bound mới quét 1.359.007 scored row hợp lệ của ba worker và
không gọi normal timing là attack latency. Inference p50/p95/p99/p99.9 là
17,79/29,77/36,83/47,39 ms, nhưng max 4.069,98 ms. Post-window processing
p50/p95/p99/p99.9 là 0,178/0,329/0,390/0,468 giây, max 8,531 giây.
Window-start-to-decision p50/p95/p99/p99.9 là
1,181/1,332/1,393/1,471 giây, max 9,533 giây; 366 window vượt 2 giây, tỷ lệ
0,0269%.

Report SHA-256 `2da2e5a3...`, index `c03f9780...`. Số liệu xác nhận đường đi
thông thường đạt p99 dưới 2 giây nhưng rare node-pressure tail chưa được kiểm
soát. Cộng thẳng một window cho temporal confirmation sẽ đưa p99 ước tính lên
khoảng 2,39 giây, nên phương án đó không được rollout nguyên trạng. Đây vẫn
không phải true injection-to-alert latency; blind markers là bắt buộc.
Full regression hiện tại đạt **377 passed, 2 warning** deprecation Torch.

Source unit cho candidate kế tiếp đổi profile từ lowered-priority sang
`Nice=0`, `CPUWeight=200`, `CPUQuota=200%`, `MemoryHigh=768M`, `MemoryMax=1G`
và `TasksMax=128`. Mục tiêu là giảm scheduler starvation nhưng vẫn chặn
resource runaway. Profile này **chưa deploy** và phải qua counterbalanced A/B
overhead/latency trước khi được dùng cho claim.

### 7.14 Canary telemetry 500 ms cô lập

Để kiểm tra khả năng giảm phần chờ telemetry mà không sửa hoặc hồi sinh V4,
nhánh Pulse bổ sung một collector **collect-only** chạy song song trên worker1.
Unit dùng exact eBPF counters với interval 500 ms, giữ context năm giây bằng
10 rolling window, ghi vào run directory riêng, có thời lượng hữu hạn, không
`enable` lúc boot, không nạp model và không phát alert.

Hai lỗi lifecycle được giữ lại thay vì xóa evidence. Run đầu dừng sau khoảng
ba giây vì installer hiểu nhầm trạng thái systemd `static` là `enabled`. Run
300 giây tiếp theo bị finalizer đánh trượt vì SIGTERM làm loader xuất cohort
cuối dài 165 ms; đồng thời CPU/memory counter đã bị systemd thu hồi trước lúc
đọc. Guard sau đó phân biệt rõ `static` với `enabled`; loader kiểm cờ thoát ngay
sau `usleep` để không snapshot cửa sổ shutdown; `ExecStopPost` đóng băng cgroup
metrics trước khi unit biến mất.

Lifecycle canary cuối `pulse500-lifecycle-20260817T023631Z` chạy đúng 120 giây
và pass fail-closed validation: 3.449 feature row, 249 chiều, 14 workload trên
worker1, không JSON/integrity/drop error. Interval p50/p95/p99/max là
502,78/505,53/507,85/509,35 ms; ingest lag là
12,34/23,10/29,26/39,08 ms; window-start-to-feature là
515,35/526,56/532,88/543,02 ms. Snapshot read p99 5,75 ms.

Tiến trình thử nghiệm dùng 6,329 CPU-second trong 120 giây, tương đương
0,0527 CPU core trung bình, và memory peak 38,43 MB. Collector một giây đang
chạy song song dùng 2,746 CPU-second trong cùng interval. Đây chỉ là accounting
của service collector, chưa bao gồm toàn bộ chi phí eBPF có thể được hạch toán
cho workload và chưa phải counterbalanced application-overhead A/B.

Analysis report SHA-256 `58ea38a7...`; bundle index SHA-256 `23604e7f...`.
Kết quả chứng minh telemetry 500 ms khả thi trên một worker và đưa p99 từ đầu
window tới feature xuống 0,533 giây. Nó **không** chứng minh ML recall,
precision hay kernel-to-alert 1–2 giây: model hiện tại được train trên window
một giây, vì vậy phải thu dataset 500 ms độc lập, train/calibrate candidate mới,
chạy normal soak, blind attack và A/B overhead trước khi rollout ba worker.
Full regression sau thay đổi đạt **380 passed, 2 warning** deprecation Torch.

### 7.15 Smoke protocol counterbalanced overhead 500 ms

Runner A/B mới giữ collector một giây và normal load generator cố định, chỉ
bật/tắt collector 500 ms trên worker1. Endpoint được khóa theo UID/IP của
ingress pod cùng node; mỗi phase fail nếu pod drift, cluster không còn 6 node
Ready hoặc wrk có socket/non-2xx error. Full protocol đăng ký trước chuỗi bốn
cặp `OFF-ON, ON-OFF, ON-OFF, OFF-ON`; không có automatic promotion.

Smoke một cặp ngày 17-08 bind commit `5944b97...` và pass machinery với zero
request error. OFF đạt 59,60 RPS, p99 836,64 ms; ON đạt 56,57 RPS, p99
704,89 ms. Phép tính thô tương ứng throughput loss 5,08% và p99 change
-15,75%, nhưng report bắt buộc `inferential=false`: một cặp ngắn không tách
được treatment effect khỏi traffic/scheduler noise và không được dùng làm
overhead claim. Smoke SHA256SUMS `3ab10e24...`. Sentinel Pulse suite đạt
**102 passed**; full regression tương ứng **383 passed, 2 warning** legacy
Torch.

### 7.16 Pilot A/B overhead 500 ms đầy đủ

Campaign `pulse500-overhead-full-20260817T083911Z` hoàn tất đủ tám phase và
40 lần chạy wrk theo bốn cặp counterbalanced đã đăng ký trước. Cả 40 lần đều
không có request lỗi; UID/IP/image của ingress pod, topology 6/6 node Ready và
trạng thái collector điều khiển đều qua fail-closed gate. Toàn bộ 124 artifact
khớp checksum; SHA-256 của frozen index là `f3cdc5b3...`.

Hiệu ứng ghép cặp có median throughput loss **-0,61%** (treatment đạt throughput
cao hơn nhẹ) và median p99 response-time increase **+2,26%**. Exact two-sided
sign-flip test hậu nghiệm cho throughput có `p=0,125`, cho p99 có `p=0,625`;
không khác biệt nào đạt mức ý nghĩa 0,05. Kết quả này không được diễn giải là
"zero overhead" hoặc equivalence: chỉ có bốn cặp trên một worker, một endpoint,
một cluster-day, nên statistical power còn thấp và kiểm định được thêm sau
campaign.

Bốn treatment phase sinh tổng 21.324 feature row. Collector dùng median
0,0532 CPU core và memory peak median 41.146.368 byte (39,24 MiB); interval p99
nằm trong 507,22–507,97 ms, ingest-lag p99 trong 35,81–40,21 ms. Tất cả gate
integrity/drop đều bằng 0. Evidence phân tích được lưu ngoài frozen campaign để
không sửa dữ liệu gốc và đánh dấu `exploratory_posthoc=true`; analysis/index
SHA-256 lần lượt là `9869c4fd...`/`a78019cc...`. Bước tiếp theo là
replication đăng ký trước trên ngày/worker/endpoint độc lập và chốt equivalence
margin; chưa rollout 500 ms, chưa train model 500 ms và chưa có claim
kernel-to-alert hoặc attack recall. Sau khi thêm validator/phân tích pilot,
Sentinel Pulse suite đạt **104 passed** và full regression đạt **385 passed,
2 warning** deprecation Torch.

### 7.17 Replication A/B cross-day và cross-worker

Replication `pulse500-overhead-full-20260820T035802Z` chạy trên
`k8s-worker4.local` (`10.1.16.238`) và ingress pod UID khác pilot ngày 17-08.
Campaign hoàn tất 8/8 phase, 40/40 wrk run, zero request error, không có
`FAILED.txt`; 124/124 artifact khớp frozen index SHA-256 `9d307107...`.
Riêng ngày hai, median throughput loss là **-2,73%**, median p99 change
**-0,10%**; exact sign-flip lần lượt `p=0,25` và `p=0,875`.

Phân tích gộp hai ngày gồm tám cặp trên hai worker và hai ingress pod UID. Median
throughput loss là **-1,58%** (mean -2,46%, `p=0,015625`), tức treatment 500 ms
có RPS cao hơn trong mẫu. Median p99 latency increase là **+1,78%**
(mean +1,14%, `p=0,4921875`). Kết quả throughput có ý nghĩa theo exact
sign-flip test nhưng không được diễn giải thành collector làm ứng dụng nhanh
hơn: statistical synthesis được hoàn thiện khi replication thứ hai đang chạy,
cả hai run vẫn thuộc cùng một cluster và chưa có equivalence margin/power
calculation đăng ký trước. `equivalence_established` vì vậy vẫn là `false`.

Tám treatment phase sinh tổng **40.276 row**, median collector CPU 0,0528 core,
memory peak median 40.675.328 byte (38,79 MiB), interval p99 median 507,69 ms
và ingest-lag p99 median 37,50 ms; mọi integrity/drop gate bằng 0. Day-two
analysis/index SHA-256 là `31e79b61...`/`963df205...`; cross-day
analysis/index là `4a82ea02...`/`129bb84e...`.

Hai replication đủ để **pass có điều kiện gate an toàn cho thu dataset 500 ms**,
không đủ để rollout detector production hoặc claim overhead equivalence. Bước
kế tiếp là capture bốn traffic regime trên ba worker, train/calibrate model
500 ms riêng, normal soak và blind attack có marker để đo true
kernel-to-alert. Full regression sau replication đạt **387 passed, 2 warning**
deprecation Torch.

### 7.18 Pipeline capture và train profile 500 ms

Đã bổ sung campaign runner normal-only cho ba worker và bốn regime `steady`,
`toolmix`, `burst`, `recovery`. Runner khóa contract/commit/source checksum trước
khi thu, giữ collector một giây làm control, chạy collector 500 ms song song,
bắt buộc detector inactive, kiểm tra 6/6 node Ready và tự trả traffic về steady
khi lỗi. Mỗi node được finalizer cũ kiểm tra interval/zero-drop rồi được node
manifest mới bind với contract, node identity, capture hash, campaign span và
row theo regime trước khi assembler tạo dataset bất biến.

Trainer nay nhận `--window-seconds 0.5`: validation interval đổi thành
0,35–0,80 giây, sequence-gap thành 1,25 giây và model manifest ghi đúng window
0,5 giây; profile một giây giữ nguyên 0,80–1,50/2,50 giây. Campaign không tự
train và không tự promote. Code gate đạt **391 passed, 2 warning**; tại thời
điểm khóa mục này dataset campaign chưa chạy nên chưa có model/accuracy/latency
claim mới.

### 7.19 Dataset campaign đầu tiên fail-closed

Run `pulse500-data-20260820T043610Z` thu đủ `steady`, `toolmix`, `burst` nhưng
không phát marker bắt đầu measured interval `recovery`; runner dừng lúc
05:12:03 UTC, trả traffic về steady và dừng cả ba collector thử nghiệm. Dataset
này bị loại toàn bộ (`training_eligible=false`), không assemble và không train.
Cluster sau cleanup có 6/6 node Ready, zero pod lỗi và ba collector một giây vẫn
active.

Evidence cho thấy snapshot deployment recovery được ghi lúc 05:11:23 UTC, sớm
hơn mốc recovery đã khóa 55,04 giây; chạy lại riêng traffic setter sau failure
trả `rc=0`. Runner phiên bản cũ không lưu health predicate trả mã 1, vì vậy
không đủ bằng chứng gán nguyên nhân hẹp hơn
`undetermined-health-check-predicate`. Failed bundle/index SHA-256 là
`68d5cd63...`/`ba45d577...`.

Runner được harden trước rerun: transition gap 180 giây, tối đa hai lần rollout
idempotent có log riêng, stage marker và health-warning lưu node/pod/service;
chỉ fail sau ba health check liên tiếp. Đây là infrastructure failure có
evidence, nên được phép rerun theo protocol; dữ liệu failed run tuyệt đối không
được tái sử dụng để tune model.

### 7.20 Dataset 500 ms hợp lệ và candidate contract A1

Campaign rerun `pulse500-data-20260820T055150Z` đã đóng `COMPLETE`, không có
`FAILED` hay health warning. Toàn bộ **67/67** checksum trong frozen index khớp;
cụm hậu kiểm có **6/6 node Ready**, không có pod lỗi. Dataset sau khi lọc đúng
measured interval gồm **178.636 cửa sổ**, **249 feature**, **20 workload** và
bốn chế độ traffic: steady 43.065, toolmix 44.864, burst 48.290, recovery
42.417. Phân bố theo node là worker1 70.847, worker3 43.800 và worker4 63.989;
55.248 row ngoài interval đã đăng ký bị loại.

Validation thống nhất bằng source hiện hành đạt `valid=true`, mọi drop/integrity
counter bằng 0. Interval p50/p95/p99/max lần lượt là
0,502599/0,505684/0,507923/0,520758 giây; ingest-lag p99 0,039432 giây và
window-start-to-emit p99 0,543261 giây, max 0,590696 giây. Dataset SHA-256 là
`5ee30ee49c1b0fc75c23878a2eeb7a640c8579702df484e03e69ff25804b5cc7`,
manifest `a101e6fa...`, validation `c520ace9...`, frozen index `61801dd3...`.

Audit phát hiện validator cũ trên worker1 khác source hiện hành, nhưng capture,
loader và BPF object trên cả ba worker có checksum giống nhau. Raw capture được
revalidate bằng cùng validator hiện hành và cả ba đều pass zero-drop; audit
đánh dấu `training_eligible_after_uniform_revalidation=true`. Validator worker1
đã được đồng bộ mà không restart collector production. Software-audit/index
SHA-256 là `69862b77...`/`df6167ec...`.

Candidate phát triển A1 được preregister trước training bằng contract bất biến:
cửa sổ 0,5 giây, history 3, ExtraTrees per-workload và calibration
`alpha=0,001`. Mức alpha này được chọn vì workload ít nhất chỉ có 4.766 cửa sổ,
không đủ calibration sample để biểu diễn alpha `1e-4`. Contract bind dataset,
blind-attack matrix, tham số và cấm auto-promotion. Đây chưa phải model stable;
normal soak, blind recall và kernel-to-alert vẫn phải được đo độc lập.

### 7.21 Candidate A1 và benchmark inference

Trainer chạy từ commit `dba5858...` trong môi trường đã khóa version, hoàn tất
20/20 workload, không có workload `collect-only`. Tổng số temporal example train
là 122.697 và calibration là 53.102; calibration nhỏ nhất/lớn nhất
1.376/4.298, đều vượt ngưỡng 999 của alpha 0,001. Tổng thời gian fit do từng
model báo cáo là 83,80 giây. Model manifest SHA-256 là `c4683505...`; 20/20
artifact đã được kiểm tra lại kích thước và checksum.

Benchmark tái lập cân bằng 500 scored window cho mỗi workload (10.000 inference)
đạt p50 16,83 ms, p95 26,52 ms, p99 **32,09 ms**, max 41,75 ms; throughput replay
53,90 scored window/giây trên một inference thread, max RSS 202.100 KiB. Báo cáo
benchmark SHA-256 `66dec375...`. Đây là replay **in-sample**, chỉ chứng minh
runtime inference nằm dưới budget 50 ms; `accuracy_evidence=false`, không được
dùng để claim precision, recall hoặc false-positive rate. Ba raw anomaly trong
replay đều bị semantic policy suppress; normal soak độc lập mới là evidence
hợp lệ cho false positive.

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
- 15-08-2026: `semantic-soak-a1` fail-fast sau 85.849 decision vì 2 normal
  alert (catalog/PostgreSQL); worker4 còn restart một lần do follower đọc
  fragment JSON chưa kết thúc. Evidence fail được đóng băng, blind vẫn chưa
  chạy. Follower nay chờ newline; policy v2 `71c6ed92...` thêm operational
  margin 0,01 trên per-workload calibration max. Replay 2 FP trả 2 suppressed;
  canary 327,92 giây đạt 5.248 scored/0 alert/0 restart, inference p99 39,26 ms,
  processing p99 421,17 ms. Run `semantic-margin-soak-b1` mở lúc 22:39:55 +07,
  đủ điều kiện finalize sớm nhất 22:39:55 +07 ngày 16-08.
- 16-08-2026: policy v2 fail soak sau 10 giờ 23 phút với 5 normal alert trên
  1.560.418 decision; evidence được freeze, blind chưa chạy. Normal-envelope v3
  calibrate từ 3.594.513 window, replay 5/5 FP thành suppressed và pass canary
  331,93 giây với 0 alert/0 restart. Soak `semantic-envelope-soak-c1` mở
  09:21:12 +07, sớm nhất finalize 09:21:12 +07 ngày 17-08.
- 16-08-2026: V3 fail-fast sau 1.985.317 decision với 8 normal alert trong
  probe-storm 5,95 giây; bundle 2,7 GB được freeze, blind chưa chạy. V4 mở rộng
  envelope từ checksum-bound failed-normal evidence, full replay 0 alert và
  regression 367 pass. Canary 351,05 giây đạt 5.599 scored/0 alert/0 restart,
  p99 window-to-decision 1,433 giây. Soak `semantic-envelope-soak-d1` mở
  23:04:35 +07, finalize sớm nhất 23:04:35 +07 ngày 17-08.
- 17-08-2026: V4 terminal fail sau 1.386.260 decision/9,27 giờ vì 2 normal
  alert trên worker1. Bundle 2,1 GB và incident analysis được hash/freeze;
  blind vẫn chưa chạy. Normal evaluator/finalizer được harden để bắt buộc bind
  marker, loại 1.344 scored record trước marker và chặn finalize sớm.
- 17-08-2026: temporal-confirmation ablation marker-bound replay 1.359.007
  scored row, chuyển 2/2 alert V4 thành suppressed và 0 projected alert;
  artifact `fb069997...`. Chưa deploy vì normal replay không cho biết blind
  recall và thêm một window có thể vi phạm p99 2 giây.
- 17-08-2026: operational-latency report trên 1.359.007 row có p99/p99.9
  window-start-to-decision 1,393/1,471 giây, 366 row vượt 2 giây và max 9,533
  giây. Artifact `2da2e5a3...`; full regression 377 pass.
- 17-08-2026: hoàn tất lifecycle canary collect-only 500 ms trên worker1.
  Run hợp lệ 120 giây có 3.449 row/14 workload, zero telemetry loss,
  window-start-to-feature p99 0,533 giây, 0,0527 CPU core và 38,43 MB peak.
  Hai run hạ tầng trước đó được giữ failed/aborted; bundle index
  `23604e7f...`. Chưa chạy model hoặc attack trên dữ liệu 500 ms.
- 20-08-2026: audit lại pilot A/B 500 ms đầy đủ: 8/8 phase, 40/40 wrk run,
  zero request error và 124/124 checksum hợp lệ. Median paired throughput loss
  -0,61%, p99 increase +2,26%; exact sign-flip `p=0,125/0,625`. Đây là pilot
  low-power, không phải bằng chứng equivalence; replication độc lập vẫn là gate.
- 20-08-2026: replication trên worker4/ingress UID mới hoàn tất 8/8 phase,
  40/40 wrk và 124/124 checksum. Gộp hai ngày/tám cặp cho throughput loss
  median -1,58% (`p=0,015625`) và p99 increase +1,78% (`p=0,4921875`);
  40.276 treatment row không có telemetry drop. Cho phép chuyển sang capture
  dataset 500 ms, chưa cho phép rollout/model latency claim.
- 20-08-2026: hoàn thành runner capture 500 ms ba worker/bốn regime,
  contract-bound node finalizer và trainer profile `window_seconds=0.5`;
  regression 391 pass. Pipeline không auto-train/promote và đang chờ campaign
  normal-only đầu tiên.
- 20-08-2026: dataset campaign đầu fail trước measured recovery; toàn bộ run bị
  reject và đóng băng (`training_eligible=false`). Root cause hẹp không xác định
  vì runner cũ thiếu failing-predicate log. Bổ sung stage/health evidence,
  3-check tolerance, rollout log/retry và transition gap 180 giây trước rerun.
