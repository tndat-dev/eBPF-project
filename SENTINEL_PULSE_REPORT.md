# Sentinel Pulse: phát hiện bất thường runtime Kubernetes với quyết định ML 1 giây

**Trạng thái tài liệu:** đang cập nhật cùng implementation
**Snapshot cluster:** 05-09-2026
**Mục tiêu latency:** median ≤ 1 giây, p99 kernel-to-alert ≤ 2 giây
**Trạng thái claim:** formal normal B3 R6 bị loại vì một false positive
PostgreSQL; B4 tiếp tục bị loại ở live-normal gate vì một false alert Kafka.
Blind B4 chưa mở. B5 pass canary nhưng bị loại ở formal normal gate. B6 đã
khóa policy/contract mới, pass canary normal-only và đang chạy formal normal
soak 25 giờ; chưa có claim production/formal

**Checkpoint development lịch sử:** model ExtraTrees và dataset normal-only
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

**Checkpoint formal hiện tại:** Run A5 (`pulse500-normal-soak-a5-20260827T070900Z`)
bị infrastructure-reject lúc 2026-08-28 06:01:32 UTC (21 giờ 53 phút, 91,2%
của gate 24 giờ), khi pod `notification-service-85955489ff-v5tmq` tạm thời
unready sau container exit 255. Snapshot cuối hợp lệ có **5.699.660 decision**,
0 alert và 0 candidate-detector restart. Đây không phải normal-pass, không cho
phép claim accuracy/false-positive rate và A5 bị cấm dùng train/tune. Ba raw
worker archive vẫn kiểm tra SHA-256 thành công, nhưng periodic checker cũ đã
ghi thêm vào `SOAK_PERIODIC_CHECKS.log` sau khi archive, khiến top-level
`RAW_SHA256SUMS` lệch đúng file phụ này. Timer gây ghi đã bị disable; sự cố
integrity phải được lưu amendment, không được mô tả là bundle bất biến hoàn
toàn. A6 chưa tạo `SOAK_START.json`: preflight thiếu capacity trên worker3 rồi
bị dừng, do đó không phải một formal run.

**Checkpoint formal mới nhất:** B3 R6
`sentinel-pulse-formal-normal-b3-r6-20260902T154252Z` đã terminal sau khoảng 3
giờ 24 phút với 882.176 decision và một false positive trên PostgreSQL. Đây là
`rejected_normal_gate`, không phải infrastructure reject. Candidate đã dừng,
control collector đã phục hồi và C3 vẫn có 0 file.

**Checkpoint tương thích 30-08-2026:** A7 dừng ở production traffic preflight,
trước `SOAK_START.json`, vì AIMS có HTTP 503; do đó A7 không phải formal soak
và không sinh evidence false-positive/model. Root cause là payment và
notification dùng gVisor trong khi Istio ambient in-pod redirection cần
ztunnel listener trong workload network namespace. Hai workload đã chuyển sang
native containerd bằng operational Argo override; source AIMS đã sửa cục bộ
nhưng chưa merge vào repo GitOps. Traffic hậu kiểm đạt east-west 900/900 HTTP
200 và north-south 300/300 thành công.

Runtime identity vì vậy đổi từ `payment/notification:pod-slice` trong model A1
sang `payment/notification:app`. A1 được giữ bất biến nhưng không còn đủ
coverage cho formal run mới. Ba capture smoke 500 ms đã freeze hợp lệ với tổng
4.236 row, union 20 workload/container và mọi loss counter bằng 0; p99
`window_start -> emitted` lớn nhất là 0,534 giây. Pilot normal-only A2 R3
`pulse500-data-pilot-20260830T094554Z` đã terminal trên ba worker. Protocol
ghi rõ `nonformal_runtime_compatibility_pilot`, source dirty được hash,
`automatic_model_training=false` và `automatic_promotion=false`. Chưa có claim
recall, false-positive hay kernel-to-alert mới.

Calibration audit R3 tại alpha `0,001` đủ tối thiểu 999 calibration example
cho 16/20 key, nhưng frontend, waypoint và hai Kafka entity-operator chỉ có
713–716; alpha không bị hạ để ép train. Extended R4 bị infrastructure-reject
trước measured interval vì sparse BPF map trên worker4 trả `ENOMEM`. BPF map đã
được đổi sang preallocated 1.024 entry và smoke hậu sửa pass đồng thời 3/3.
Extended R5 `pulse500-data-pilot-20260830T163059Z` đã terminal hợp lệ với
178.991 window, 20 workload/container, bốn regime và zero loss/integrity
counter. Calibration ở `alpha=0,001` đạt 20/20 key; training pilot hoàn tất
20/20 `PulseExtraTrees`, 0 collect-only. Model manifest SHA-256 là
`2e37ffd1ef4476b09e123315b467e47814613b9ff22dfd0b4e28fbb375952a81`.
Canary normal non-formal 15 phút trên ba worker đã terminal với 63.076 decision,
0 alert quan sát, 0 restart; p99 window-start-to-decision gộp là 841,42 ms và
inference p99 29,31 ms. Candidate không auto-promote. Pilot attack-latency
non-formal sau đó đã terminal đủ 15 trial lineage với 10 alert và 5 miss; riêng
9 alert R6 có p50 0,718 giây nhưng p99 5,332 giây. Đây là kết quả fail
engineering gate, không phải accuracy claim và không được dùng để tune A2.




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
| 10.1.16.234 | k8s-master.local | control plane | v1.34.10 | 24 vCPU, 128 GB RAM, 600 GB disk |
| 10.1.16.235 | k8s-master2.local | control plane | v1.34.10 | 24 vCPU, 128 GB RAM, 600 GB disk |
| 10.1.16.236 | k8s-master3.local | control plane | v1.34.10 | 24 vCPU, 128 GB RAM, 600 GB disk |
| 10.1.16.237 | k8s-worker1.local | worker | v1.34.10 | 24 vCPU, 128 GB RAM, 600 GB disk |
| 10.1.16.238 | k8s-worker4.local | worker | v1.34.10 | 24 vCPU, 128 GB RAM, 600 GB disk |
| 10.1.16.239 | k8s-worker3.local | worker | v1.34.10 | 24 vCPU, 128 GB RAM, 600 GB disk |

Ngày 30-08-2026, audit trực tiếp xác nhận 6/6 node Ready. Mỗi VM thấy đúng 24
CPU logic, khoảng 126 GiB RAM usable và disk `/dev/sda` 644.245.094.400 byte.
Partition ext4 `/dev/sda2` đã được mở rộng theo disk, cung cấp 633.792.950.272
byte (khoảng 591 GiB) cho root filesystem. Sau rolling restart kubelet, trường
allocatable ephemeral-storage là 602.103.302.287 byte trên control plane và
570.413.654.301 byte trên worker; không node nào có DiskPressure,
MemoryPressure hoặc PIDPressure.

Namespace `production` có đủ 10 workload AIMS
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
          ↓ mỗi 500 ms trong candidate A2
rolling feature: 3 window lịch sử + window hiện tại
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
| Chờ đủ exact-counter window | 0.500 s |
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

Candidate A2 đăng ký `alpha=10^-3`, nên split calibration phải có tối thiểu
999 example cho từng candidate để conformal p-value nhỏ nhất có thể đạt alpha.
R5 đạt 20/20 key, key nhỏ nhất có 1.428 example. Trainer fail-closed nếu không
đủ độ phân giải; điều kiện toán học này không bảo đảm false-positive ngoài
phân phối bằng 0. Cấu hình mặc định `10^-4` nếu dùng trong run khác vẫn yêu cầu
tối thiểu 9.999 calibration example/key và không được nhập nhằng với A2.

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

| Hạng mục | Trạng thái 31-08-2026 |
|---|---|
| Audit AIMS và dependency | Hoàn thành; application/dependency healthy |
| Xác minh traffic | Đã apply và live-check: HTTP health/ingress, Redis AUTH+PING, MinIO health, PostgreSQL/Kafka/RabbitMQ TCP |
| Feature schema exact counter + transition | Đã implement local, 249 chiều |
| ExtraTrees normal-only + conformal score | A1 lịch sử giữ nguyên; A2 pilot đã train/load 20/20 model từ R5 với alpha 0,001, chưa promote |
| eBPF collector theo cgroup | Đã build/verifier và active trên 3/3 worker |
| Exact eBPF counter 500 ms | A2 canary đã terminal; control collector production 1 giây vẫn active trên 3/3 worker; sampled Tetragon event không phải feature chính |
| Dataset 500 ms đa workload | R5 terminal 178.991 row/20 key/4 regime, zero loss; dataset SHA-256 `2a016dc4...` |
| Đóng băng capture bất biến | R5, model/policy và canary archive đã checksum/freeze; aggregate v2 read-only SHA-256 `d649726d...` |
| Blind attack và latency CDF | Chưa chạy |
| Capture integrity/ingest-lag validator | Đã implement local |
| Model artifact integrity | Manifest v2 khóa SHA-256/size/metadata; runtime verify trước unpickle |
| Independent normal-soak evaluator | Đã implement; các run cũ terminal/frozen; A7 bị preflight reject, không có formal soak active |
| Terminal candidate decision | Đã implement; chỉ mở overhead evaluation, không auto-promote |
| Multi-node dataset provenance | Contract + node-finalizer manifest + source/dataset hash bắt buộc khớp trước assemble |
| Canary-first worker rollout | A2 audit-only pass 3/3 worker trong 15 phút: 63.076 decision, 0 alert quan sát, p99 decision 841,42 ms; candidate đã dừng |

### 7.0 Cổng tương thích runtime và pilot A2 ngày 30-08-2026

A7 không được tính là một lần normal soak. Lifecycle dừng trước marker formal;
receipt immutable nằm tại
`/home/dat/sentinel-pulse-evidence/preflight-rejections/pulse500-normal-soak-a7-20260830T043500Z-PREFLIGHT_REJECTED.txt`,
SHA-256 `96e68aaf...`. Không có detector decision stream A7 nào được dùng để
claim hoặc tune.

Sau khi AIMS chuyển payment/notification sang native runtime, smoke 60 giây
được chạy độc lập trên từng worker và finalize bằng capture validator:

| Worker | Feature row | Workload key | Ingest p99 | Window-start→emit p99 | CPU trung bình | Peak RAM |
|---|---:|---:|---:|---:|---:|---:|
| k8s-worker1.local (.237) | 1.314 | 10 | 19,15 ms | 0,523 s | 0,0648 core | 36,9 MB |
| k8s-worker3.local (.239) | 1.144 | 12 | 21,24 ms | 0,525 s | 0,0588 core | 36,8 MB |
| k8s-worker4.local (.238) | 1.778 | 17 | 28,64 ms | 0,534 s | 0,0842 core | 38,9 MB |

Union có 20 key; `feature_dim=249`; `malformed=0`, `unresolved=0` và toàn bộ
`collector_max_drops=0`. SHA-256 capture tương ứng là `77aa1f62...`,
`91f09478...`, `e865c998...`. Các số này chỉ đo telemetry đến feature emission;
chưa bao gồm inference, corroboration hay alert.

Lần start đầu trên hai worker và pilot R2 từng báo chung “no valid target”. Sau
khi loader tách lỗi rỗng khỏi lỗi map, journal R3 ghi chính xác worker3 gặp
`Cannot allocate memory` hai lần khi populate per-CPU BPF map. Loader mới chỉ
retry hữu hạn với `ENOMEM/EAGAIN` (50 ms rồi 100 ms ở run này), sau đó attach
thành công với 36 target; mọi lỗi khác và allowlist rỗng vẫn fail-closed. Cùng
binary SHA-256 `7e9821e7...` đã được cài trên ba worker, bản cũ được giữ ở
`pulse_counter_loader.pre-bounded-20260830` để rollback.

Pilot R3 có schedule preregistered: steady 09:48:28–09:53:28 UTC, toolmix
09:53:58–09:58:58, burst 09:59:28–10:04:28 và recovery
10:04:58–10:09:58. Run đã terminal `PULSE_500MS_DATASET_COMPLETE`: dataset có
89.503 row, 249 feature, đủ 20 workload/container; steady/toolmix/burst/recovery
lần lượt 21.499/22.445/24.771/20.788 row. Dataset SHA-256 là
`67bfcc42ac19451779cfc2c55ad9eec2e42d8791fad9b3f1d99a9b6aebeee1bc`;
top-level `SHA256SUMS` verify pass. p99 interval/ingest/window-start-to-emit là
0,508/0,0278/0,532 giây và mọi collector loss counter bằng 0. Đây là
compatibility pilot, không phải formal training dataset. Hai attempt trước được
giữ nguyên `FAILED.txt`: R1 lỗi current working
directory trước collector; R2 lỗi BPF allocation trước khi có feature row hợp
lệ. Không rerun chọn lọc hay đổi nhãn hai attempt này.

Calibration split của R3 cho thấy 16/20 key đủ alpha `0,001`; bốn key thiếu là
frontend (714), waypoint (716), Kafka topic-operator (713) và user-operator
(713). Vì vậy không hạ alpha và không gọi R3 là full candidate dataset.
Extended R4 `pulse500-data-pilot-20260830T162216Z` bị reject trước measured
interval: worker4 trả `ENOMEM` qua đủ năm retry khi insert target vào sparse
per-CPU hash map. `FAILED.txt` được giữ và hai collector đã mở trên worker1/3
được restore tự động.

Root fix đổi `pulse_cgroups` từ `max_entries=4096 + BPF_F_NO_PREALLOC` sang
preallocated `max_entries=1024`. Trên worker4, `bpftool` đo map mới có memlock
31.147.712 byte; current target high-water là 50. BPF object SHA-256
`ead3346cdafe3ba42179d141f6c255e651e3d215ad6a9453d537076aebca5317`
được cài trên cả ba worker, có backup object cũ để rollback. Smoke 60 giây
đồng thời sau sửa terminal valid: 1.330/1.137/1.788 row trên worker1/3/4,
mọi loss counter bằng 0, p99 emit 0,525/0,524/0,533 giây và không có ENOMEM.

Extended R5 `pulse500-data-pilot-20260830T163059Z` đã attach đủ ba worker.
Schedule khóa trước: steady 16:33:34–16:43:34, toolmix 16:44:04–16:54:04,
burst 16:54:34–17:04:34, recovery 17:05:04–17:15:04 UTC. Trước terminal
`COMPLETE`/checksum/validation, mục này chỉ ghi trạng thái active.

Full regression trên detached source overlay đạt **448 passed, 2 warnings**
trong 21,17 giây. Receipt tại
`/home/dat/sentinel-pulse-evidence/pilot-a2/regression/local-overlay-20260830T163400Z.txt`
có SHA-256 `3182ee16ff259b339d2025a3835dcea6daa9c63870e833bf45bf08ec5932dde6`;
worktree test tạm đã được dọn sau khi lưu receipt.

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

### 7.22 Live-normal canary 500 ms trên worker1

Canary `pulse500-live-normal-a1-20260820T095437Z` chạy collector 500 ms trong
902,43 giây trên worker1. Capture gồm 25.863 row/14 workload, `valid=true`, mọi
drop counter bằng 0; interval p99 508,28 ms, window-start-to-emit p99 545,06 ms,
collector trung bình 0,0484 core và memory peak 70.598.656 byte.

Run detector hợp lệ có 20.387 decision, gồm 48 warming, 20.306 normal, 33
suppressed và **0 alert**; 20.339 scored window phủ khoảng 11,8 phút/workload,
coverage thấp nhất 99,4%. Live inference p50/p95/p99/max là
17,66/30,74/**39,18**/77,57 ms; post-window processing p99 404,94 ms, max
703,67 ms. Nominal window 0,5 giây cộng processing p99 là 0,905 giây; tổng hai
component max quan sát là 1,218 giây. Đây không phải true attack latency và
canary ngắn không thay thế normal soak 24 giờ.

Lần rollout đầu của canary bị env trỏ nhầm stream một giây do source chưa sync;
1.040 decision đó được khóa `valid=false` trong
`REJECTED_WRONG_SOURCE_RUN.json`, tuyệt đối không nhập vào kết quả. Khi finite
collector dừng, systemd trả group của run directory về root làm follower cũ
`PermissionError` và phát sinh 14 restart sau measured interval. Code follower
đã được harden để chờ ở EOF khi path-stat mất quyền; installer cũng reset stale
restart counter trước run mới. Canary summary/normal report/bundle-index SHA-256
là `11b26e2b...`/`178b3ff7...`/`b2611351...`.

### 7.23 Formal normal soak A1: infrastructure-rejected

Run `pulse500-normal-soak-a1-20260820T101251Z` được preregister trước launch,
bind model `c4683505...`, policy `272e9119...`, source commit `4d2a992...`, cấm
blind evaluation và auto-promotion. Nó bị loại khỏi normal gate lúc 10:41:58
UTC vì Kubernetes đã evict `aims-postgres-cnpg-2` trên worker3 do thiếu
ephemeral-storage lúc 10:41:37 UTC. Bốn alert trên PostgreSQL primary/replica
còn sống xuất hiện 2,075–2,678 giây sau event này.

Raw evidence có 135.033 decision và 136.360 feature row trên ba worker, zero
collector integrity error. Validator độc lập xác nhận 12/12 checksum, 4/4 raw
alert và đúng một eviction event trong marker interval; `VALIDATION.json`
`valid=true`, SHA-256 `3fe8591a...`. Run được khóa
`rejected_infrastructure_failure`; candidate không pass/fail bởi run này và dữ
liệu tuyệt đối không dùng train/tune hay blind test.

### 7.24 Health provenance và bounded control telemetry

Launcher formal nay không chỉ đếm `Ready`: nó yêu cầu node pressure/taint bằng
0, production pod khỏe, CloudNativePG đủ replica và mọi Longhorn volume healthy
liên tục 300 giây trước marker. Monitor áp cùng predicate trong run và lưu
machine-readable failure snapshot. Worker3 có root disk thực tế 300 GiB,
Longhorn khoảng 204 GB và control stream một giây khoảng 7,0 GB; stream này
trước đây append không giới hạn. Daily rotation mới atomic-move, restart stream,
checksum và nén archive, đồng thời tự skip nếu experiment/detector active. Timer
đã enable trên ba worker. Ba rotation terminal success, nén 26,56 GB raw còn
7,01 GB; worker3 còn 53,91 GB trống. A2 chỉ mở sau khi preflight không còn
DiskPressure flapping. Full regression tại mốc này đạt **404 passed, 2 warning**.

PVC replica PostgreSQL `aims-postgres-cnpg-2` sau eviction bị rỗng và thiếu
`PGDATA`. Sau khi khóa YAML/UID evidence, chỉ pod/PVC replica này được thay;
primary và replica thứ ba giữ nguyên. CloudNativePG bootstrap PVC mới từ
primary và hoàn tất lúc 11:10:50 UTC: 3/3 `pg_isready`, hai replication session
`streaming/async`, Longhorn `healthy/attached`, DiskPressure false. Recovery
thành công không được tính vào normal soak.

### 7.25 Formal normal soak A2 đang chạy

Launcher A2 quan sát 6/6 node, node pressure/taint, production pod, Longhorn và
CloudNativePG cùng khỏe liên tục 306 giây trước marker. Run
`pulse500-normal-soak-a2-20260820T111533Z` bắt đầu lúc 11:20:46 UTC với đúng
model `c4683505...`, policy `272e9119...` và source commit `9911d8e...`; không
có bước train/tune giữa A1 và A2. Poll đầu lúc 11:22:19--11:22:22 UTC ghi nhận
3.301 decision, 0 alert, 0 restart, collector/detector active 3/3 và feature
source 500 ms đúng 3/3.

Monitor fail-closed chạy mỗi 60 giây và sẽ dừng run nếu service, restart,
feature source, alert hoặc cluster-health gate vi phạm. Mốc finalize sớm nhất là
11:20:46 UTC ngày 21-08-2026 (18:20:46 ICT); vì vậy số liệu đầu run chỉ chứng
minh launch đúng, chưa phải normal-pass hay bằng chứng không false positive.

Activity audit sau launch ghi nhận hai loadgen Ready/0 restart và 20/20 workload
đã có decision. HTTP 400/401/404 và 503 từ route chưa expose/workload sandbox là
normal error-mix đã freeze, trong khi ingress, health và product route chính vẫn
trả 200. Finalizer được harden thêm: nó bind file model manifest thật bằng
SHA-256 và yêu cầu tập workload quan sát bằng chính xác tập 20 workload trong
manifest; thiếu/thừa workload đều fail-closed thay vì chỉ duyệt những workload
tình cờ xuất hiện. Tám semantic replay record cũng được chuyển thành fixture
tracked, bind SHA-256 của ba source alert file; clean-checkout regression đạt
**406 passed, 2 warning**.

Finalizer formal nhận nhiều decision file và chấm chung ba worker theo stream,
giữ SHA-256 riêng từng file cùng bundle digest. Sau mốc eligible cộng biên 300
giây, nó đóng băng mọi detector trước collector, finalizes capture node, chuyển
raw không tạo tar tạm và chỉ phát hành `NORMAL_PASS` nếu manifest/workload,
duration, coverage, alert và identity gate cùng pass; không auto-promote. Full
clean-checkout regression đạt **408 passed, 2 warning**. Mốc chạy sớm nhất cho
A2 là 21-08-2026 11:25:46 UTC (18:25:46 ICT).

Timer transient `sentinel-pulse-a2-finalize.timer` đã active/waiting trên
control-plane, trigger đúng mốc 11:25:46 UTC và bind finalizer commit `745a80e`.
Nó fail-closed nếu run/health không hợp lệ và không auto-promote. Vì unit nằm
trong `/run/systemd/transient`, control-plane reboot trước trigger thì phải arm
lại; provenance nằm trong `SCHEDULED_FINALIZER.json`.

### 7.26 Blind matrix fail-closed và phép đo kernel-to-alert đúng nghĩa

Audit measurement xác nhận detector trước đây gắn alert với marker userspace
trước lệnh inject. Đây là injection-command-to-alert upper bound, không phải
timestamp kernel. Evaluator v2 không còn cho field này mở latency gate. Mỗi
trial paper phải có thêm đúng một Tetragon `process_exec` kernel event khớp
injection ID, static binary, argument, pod UID, node và workload; evaluator tự
tính `alerted_at - kernel_event_at`. Thiếu, trùng, sai identity hoặc thứ tự thời
gian đều làm `kernel_timestamp_gate=false`.

Runner mới chỉ được start khi exact normal evidence đã có `NORMAL_PASS`, rồi
khóa model/policy/contract/source/binary/commit trước trial đầu. Static blind
binary tái lập đúng SHA-256 `a4d68d79...`. Matrix có 450 row bất biến; miss hợp
lệ không rerun, còn infrastructure failure được ghi machine-readable và dừng
toàn campaign. Runner không có promotion path và không đưa attack outcome vào
train/tune.

Audit read-only trên cluster resolve 18/18 controller tới pod Ready và cgroup
được model theo dõi. Với hai sandbox gVisor, resolver chọn leaf sentry scope
theo độ sâu cgroup thay cho parent pod slice cùng nhãn; lựa chọn không dùng
attack label. Full clean regression tại commit `cbcdd66` đạt **417 passed, 2
warning**. Snapshot A2 lúc 12:12:52 UTC có 220.509 decision, 0 alert, 0 restart
và mới đạt khoảng 3,62% clock 24 giờ; blind injection vẫn chưa chạy.

Timer `sentinel-pulse-a2-blind.timer` đã được arm cho 11:26:30 UTC ngày
21-08-2026 bằng detached source commit `d50a847`. Nó chờ `NORMAL_PASS` tối đa
14.400 giây, dừng nếu normal finalizer ghi failure, và chỉ sau pass mới chạy
trọn lifecycle start → 450-row matrix → three-worker freeze → evaluator v2.
Schedule được lưu trong `SCHEDULED_BLIND.json`, không auto-promote. Vì timer
transient, control-plane reboot trước trigger cần arm lại. Snapshot 12:20:33
UTC: 253.458 decision, 0 alert, 0 restart, khoảng 4,15% clock 24 giờ.
Interlock probe timeout `rc=124` không tạo artifact và không dừng sáu service
A2. Source timer cuối cùng kiểm tra lại node pressure/taint, pod readiness,
Tetragon 6/6, Longhorn và CNPG trước từng trial, đồng thời xóa binary tạm sau
mỗi injection. Full clean regression vẫn đạt 417 pass, 2 warning.
Mỗi kernel record nay chứa cả raw Tetragon JSON; evaluator tự kiểm canonical
SHA-256 và tái đối chiếu timestamp/exec/binary/node/pod thay vì tin derivative.

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
  thêm evaluator injection-marker-to-alert ban đầu; phép đo này về sau được
  phân loại đúng là userspace upper bound, không phải kernel timestamp.
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
- 20-08-2026: rerun dataset 500 ms hợp lệ có 178.636 row, 249 feature, 20
  workload và đủ bốn traffic regime. Candidate A1 train 20/20 workload; live
  inference p99 39,18 ms và canary 902 giây có 0 alert. Đây chưa phải accuracy
  hoặc true attack-latency evidence.
- 20-08-2026: formal A1 bị infrastructure-reject sau khi worker3 DiskPressure
  evict PostgreSQL replica. Bốn raw alert khớp 2,075–2,678 giây sau eviction;
  validator xác nhận 12 checksum, 4 alert và một event. Dữ liệu run bị cấm
  train/tune; candidate chưa được normal gate đánh giá.
- 20-08-2026: formal launcher/monitor thêm pressure, production pod, CNPG và
  Longhorn gate cùng preflight ổn định 300 giây. Daily checksum+gzip rotation
  chặn control telemetry append vô hạn; full regression đạt 404 pass.
- 20-08-2026: rotate 26,56 GB control stream còn 7,01 GB trên ba worker.
  Replica CNPG số 2 có PVC rỗng sau eviction, được recreate có evidence từ
  primary; hậu kiểm 3/3 `pg_isready`, replication streaming và Longhorn healthy.
- 20-08-2026: formal A2 mở sau 306 giây continuous healthy preflight, khóa model
  `c4683505...`/policy `272e9119...`/commit `9911d8e...`. Poll đầu 3.301
  decision, 0 alert, 0 restart; chưa được finalize trước 21-08-2026 11:20:46
  UTC.
- 20-08-2026: activity audit A2 đạt 20/20 workload. Normal finalizer bind model
  manifest thật và fail nếu tập workload quan sát thiếu/thừa bất kỳ key nào.
- 20-08-2026: thêm multi-file formal finalizer ba worker, detector-first freeze,
  streamed raw export, checksum và no-auto-promotion gate; clean regression 408
  pass.
- 20-08-2026: arm transient finalizer timer cho A2 tại 21-08-2026 11:25:46 UTC;
  schedule bind commit/model/policy/run và giữ fail-closed.
- 20-08-2026: thêm blind lifecycle 450-row interlock bởi `NORMAL_PASS`, static
  binary checksum gate và evaluator v2 dùng Tetragon `process_exec` làm kernel
  timestamp. Production target/cgroup audit đạt 18/18; clean regression 417
  pass. A2 snapshot 220.509 decision/0 alert/0 restart, chưa đủ 24 giờ.
- 20-08-2026: arm blind timer, cập nhật source cuối lên commit `d50a847` sau
  normal finalizer; service chỉ
  mở khi có `NORMAL_PASS`, chờ tối đa bốn giờ và dừng trên normal failure.
  Snapshot A2 mới nhất 253.458 decision/0 alert/0 restart, đạt 4,15% thời gian.
- 20-08-2026: harden blind source lên commit `51f214e`: exact union của marker
  controller và ba detector, checksum raw stream, ràng buộc run/model/policy/
  workload/pod/cgroup/container cho alert, raw Tetragon identity và terminal
  candidate gate. Detached regression trên control plane đạt 420 pass. Timer
  blind đã trỏ đúng commit mới; active A2 repo/model/policy không thay đổi.
  Snapshot 15:31:38 UTC đạt 1.080.654 decision/0 alert/0 restart, tương đương
  4,181 giờ hay 17,42% formal soak 24 giờ; chưa được diễn giải là normal-pass.
- 20-08-2026: blind bundle tại commit `3cdff28` trở thành self-contained:
  policy, attack/implementation contract, C source, static binary và model đều
  được stage read-only, hash trước run và verify lại khi finalize. Commit
  `9540a00` làm final checksum portable và bind cả terminal result cùng worker
  snapshot. Scheduled worktree sạch đã cập nhật đúng commit; regression vẫn
  420 pass. A2 tiếp tục
  active với snapshot 1.132.488 decision/0 alert/0 restart; không hot-update
  candidate đang formal soak.
- 20-08-2026: audit overhead xác định systemd resource snapshot cũ lấy nhầm
  control plane thay vì worker. Commit `594d051` thêm `--systemd-host`, lấy
  `CPUUsageNSec`/`MemoryCurrent` đúng node treatment và ghi host vào evidence.
  Throughput/HTTP latency cũ không bị thay đổi nhưng systemd CPU/RAM cũ không
  được dùng làm claim. Full regression đạt 421 pass; A2 không bị can thiệp.
- 20-08-2026: preregister full-pipeline overhead contract SHA-256
  `80de96a2f966ee0690ea4f205e30f347d633fe8c04ac14a18002f8bbd17b90b6`
  trước blind outcome. Thiết kế đo phần tăng thêm của collector 500 ms +
  ExtraTrees trên cùng nền Tetragon/traffic, 6 cặp counterbalanced/campaign,
  ba worker, tối thiểu hai ngày; khóa equivalence margin 3% throughput và 5%
  p99 latency, CI 95%, bootstrap/randomization và Holm correction. Chỉ được
  chạy khi terminal candidate là `eligible_for_overhead_evaluation`; không có
  auto-promotion. Full regression đạt 423 pass.
- 21-08-2026: triển khai runner/evaluator full-pipeline overhead commit
  `5e0099f`. Runner chỉ mở bằng terminal candidate eligible, treatment bật cả
  collector 500 ms và ExtraTrees detector, bắt buộc 0 alert/restart; aggregator
  verify lại frozen candidate/model/policy/contract cùng từng decision stream.
  Worker resource, source và raw artifact đều checksum-bound. Worktree overhead
  sạch đã staging nhưng chưa chạy; full regression đạt 426 pass.
- 21-08-2026 05:27:09 UTC: A2 đạt 18,106/24 giờ (75,444%), tổng
  4.686.880 decision trên ba worker, 0 alert/restart/bad monitor row. 6/6 node
  Ready và production health count 0. Đây chưa phải terminal normal-pass.
- 21-08-2026: commit `5ffb837` bổ sung cluster-health gate và JSON snapshot
  trước/sau từng overhead phase: node pressure, production pods, Tetragon 6/6,
  Longhorn và CNPG đều phải healthy. Regression giữ 426 pass; overhead worktree
  sạch đã cập nhật nhưng interlock vẫn đóng.
- 21-08-2026: capacity pre-finalize pass. Raw A2 khoảng 12,8 GB; control plane
  còn 227 GB và ba worker còn 177/46/92 GB. Monitor sẽ thoát ở mốc 24 giờ trước
  khi finalizer freeze service; finalizer không có hard timeout. Không reboot
  control plane vì hai schedule hiện là transient systemd timer.
- 21-08-2026 06:04:29 UTC: A2 terminal infrastructure-reject tại worker1 do
  collector 500 ms inactive. Snapshot hợp lệ cuối có 4.846.267 decision trên
  ba worker, 0 alert và 0 restart, nhưng run chưa đủ 24 giờ nên **không** tạo
  no-FP/stable claim. Log unattended-upgrades chứng minh `needrestart` restart
  containerd lúc 06:03:26; hard dependency cũ truyền stop qua resolver tới
  collector hữu hạn. Immutable-output guard từ chối lần start lại và bảo vệ raw
  dataset khỏi ghi đè. Cluster failure snapshot vẫn 6/6 node Ready, production,
  CNPG và Longhorn healthy; finalizer/blind timer bị hủy, không inject attack.
- 21-08-2026: commit `d6bfa33` chuyển dependency runtime từ `Requires` sang
  `Wants`, giới hạn detector tối đa ba restart/60 giây, bắt launcher stage và
  verify dependency graph trước preflight/marker, đồng thời thêm failed-soak
  freezer self-contained. A2 bị cấm dùng cho normal gate/train/tune/blind;
  archive raw+journal+package log hoàn tất và verify lúc 08:05:09 UTC. Raw trên
  worker không bị xóa; không rerun chọn lọc A2.
- 21-08-2026: dependency canary đầu bị reject do lỗi quote `journalctl` ở bước
  hậu kiểm dù collector đã kết thúc success; giữ nguyên FAILED. Canary r2 tại
  commit `f4c31df` pass: restart containerd 08:15:27–08:15:29, collector vẫn
  active và row tăng 480→1.005; terminal capture 183,016 giây có 5.154 row/14
  workload, 0 drop, ingest p99 36,01 ms, emit p99 539,89 ms, cluster trước/sau
  healthy và checksum pass. Đây là resilience evidence, không phải accuracy.
- 21-08-2026: thêm resumable fail-closed supervisor normal→finalize→blind và
  archive checkpoint; clean regression đạt 430 pass, 2 warning. Formal A3 dùng
  nguyên model `c4683505...`/policy `272e9119...`, source `f4c31df`, mở sau 306
  giây preflight tại 08:25:24 UTC. Snapshot đầu 3/3 collector/detector active,
  6.877 decision, 0 alert/restart. Finalize sớm nhất sau 08:30:24 UTC ngày
  22-08; blind 450 trial vẫn đóng cho tới exact `NORMAL_PASS`, không auto-promote.
- 21-08-2026 08:31:04 UTC: chuyển A3 supervisor sang persistent enabled unit
  `sentinel-pulse-a3-lifecycle.service` mà không dừng sáu worker service.
  Credential environment mode 0600 root-only; source candidate vẫn frozen ở
  `f4c31df`. Monitor resume đủ ba worker, 0 alert/restart. Installer commit
  `839e6c2`; clean full regression tăng thành 431 pass, 2 warning.
- 21-08-2026 10:32:33 UTC: A3 bị **infrastructure-reject** vì
  `k8s-worker3.local DiskPressure=True`, không phải model outcome. Snapshot
  cuối hợp lệ là 217.018/132.437/192.112 decision trên worker1/3/4 (541.567
  tổng), 0 alert và 0 detector restart. Archive failed-soak hoàn tất 10:34:15
  UTC, checksum pass; raw A3 bị cấm normal gate/train/tune/blind và blind chưa
  hề inject.
- 22-08-2026: worker3 có 48,5 GB root free (84% used), nên Longhorn node bị
  đặt `allowScheduling=false` để chặn replica mới, không đổi eviction threshold.
  CNPG replica `aims-postgres-cnpg-2` mất PGDATA được rebuild có evidence: thay
  đúng pod/PVC lỗi, tạo volume Longhorn mới, khởi tạo directory rỗng UID:GID
  26:26 theo restricted PodSecurity rồi `pg_basebackup` mTLS từ primary. Hậu
  kiểm 3/3 CNPG healthy và hai replica `streaming/async`.
- 22-08-2026: launcher/monitor formal thêm capacity interlock: mọi worker phải
  có ≥64 GiB root available và ≤80% used, ngoài cluster-health gate hiện hữu.
  Preflight không tạo marker khi thiếu headroom; monitor tạo
  `FAILURE_CAPACITY.txt` và reject nếu capacity giảm trong run. Bash syntax và
  24 deployer test pass; full regression sạch cần chạy trước formal A4. A4 chưa
  được mở vì worker3 vẫn dưới ngưỡng.
- 25-08-2026: kiểm tra recovery mới xác nhận 6/6 node `Ready`,
  `DiskPressure=False`, CNPG `3/3` healthy với hai replication stream và 0
  Longhorn managed volume non-healthy. worker3 gặp eviction ephemeral-storage
  và replica CNPG lỗi filesystem; chỉ replica/PVC lỗi được rebuild qua mTLS
  `pg_basebackup`, primary/replica lành giữ nguyên. Sau archive checksum-verify
  rồi dọn đúng scope duplicate A2/A3, 12 orphan `DataCleanable` và journal,
  worker3 còn **70.655.328.256 byte / 77%**. Một `features.jsonl` đang mở báo
  `file size changed` khi gzip nên đã quarantine, không được dùng làm data;
  collector restart có kiểm soát và active. Capacity chỉ vừa đạt tại snapshot,
  nên **A4 vẫn khóa** cho tới khi health/capacity liên tục 300 giây và regression
  worktree sạch pass. Không có claim accuracy/no-FP/latency mới.
- 25-08-2026 15:45:01 UTC: sau khi snapshot rồi xóa một loadgen pod `Error`
  stale (replacement Running), A4 qua 307 giây preflight liên tục và tạo marker
  bất biến `pulse500-normal-soak-a4-20260825T154500Z`. Source `1b33a77...`,
  model `c4683505...`, policy `272e9119...`; lifecycle persistent
  `sentinel-pulse-a4-lifecycle.service` đang monitor 25 giờ. Vòng monitor đầu:
  cả ba collector/detector active, 0 restart/0 alert; counter decision lần lượt
  6.453/1.867/4.317 tại các timestamp poll khác nhau. Đây chỉ là startup health,
  không phải no-FP result. Finalize không sớm hơn 26-08 15:50 UTC (24 giờ + 300s)
  và blind set vẫn khóa tới normal-pass terminal.
- 26-08-2026 06:54:35 UTC: Run A4 bị **infrastructure-reject** tại worker1 do
  `unattended-upgrades` tự động restart `containerd.service`. Toàn bộ dữ liệu raw
  và journal đã được nén và lưu trữ fail-closed tại `pulse500-normal-soak-a4-20260825T154500Z/infrastructure-failure/`
  với đầy đủ SHA-256 checksums (`ARCHIVE_COMPLETE`). Run A4 bị cấm dùng cho normal gate/train/tune.
- 27-08-2026 07:30:00 UTC: Đã can thiệp triệt để nguy cơ restart hạ tầng: thực hiện
  stop và mask `unattended-upgrades.service`, `apt-daily.timer`, `apt-daily-upgrade.timer`
  trên cả 3 worker (`k8s-worker1.local`, `k8s-worker4.local`, `k8s-worker3.local`).
- 27-08-2026 08:08:26 UTC: Khởi chạy chính thức formal normal soak **A5** với marker
  `pulse500-normal-soak-a5-20260827T070900Z`. Khóa model `c4683505...`, policy `272e9119...`,
  source commit `1b33a77...`. Tiến trình persistent lifecycle `sentinel-pulse-a5-lifecycle.service`
  đang tự động giám sát 24 giờ.
- 27-08-2026 12:30:00 UTC: Snapshot A5 sau 4 giờ 23 phút hoạt động liên tục:
  tất cả 3 collector và candidate detector đều `active`, 0 restart (`nrestarts=0`),
  0 alert (`alerts=0`), tổng cộng **1.116.584 decisions** được xử lý (worker1: 511.306,
  worker4: 442.696, worker3: 162.582). Thời gian finalize sớm nhất là **2026-08-28 08:08:26 UTC**.
- 28-08-2026 03:11:09 UTC: Snapshot A5 sau 19 giờ 03 phút hoạt động liên tục (79,4% chặng đường):
  tất cả 3 worker collector và candidate detector giữ nguyên trạng thái `active`,
  0 restart (`nrestarts=0`), 0 alert (`alerts=0`), tổng cộng **4.963.086 decisions** được xử lý
  (worker1: 2.268.118, worker4: 1.971.716, worker3: 723.252).
- 28-08-2026 06:01:32 UTC: Run A5 bị **infrastructure-reject** tại mốc 21 giờ 53 phút (91,2% chặng đường 24h)
  do container của pod `notification-service-85955489ff-v5tmq` trên worker1 bị restart (`exitCode 255`).
  Snapshot cuối hợp lệ có **5.699.660 decisions** trên 3 worker với **0 alert**
  và **0 candidate-detector restart**. Đây không phải accuracy/no-FP claim.
  Raw worker archive đã nén và checksum pass; tuy nhiên checker cũ tiếp tục sửa
  `SOAK_PERIODIC_CHECKS.log` sau `ARCHIVE_COMPLETE`, làm top-level
  `RAW_SHA256SUMS` mismatch đúng file phụ đó. Timer đã bị disable ngày
  29-08-2026; A5 vẫn bị cấm dùng cho normal gate/train/tune.
- 28-08-2026 07:20 UTC: A6 chỉ vào preflight, chưa tạo `SOAK_START.json` hay
  khởi động collector candidate. worker3 còn khoảng 65,3 GB, thấp hơn gate 64
  GiB (68.719.476.736 byte); supervisor bị dừng rồi retry vấp thư mục dở dang.
  A6 không được tính là formal soak. Launcher kế tiếp chỉ tạo evidence directory
  sau khi preflight pass để interruption không chặn retry.
- 29-08-2026: audit xác nhận package update units trên cả ba worker thực tế đã
  trở lại `enabled`; dòng lịch sử “masked từ 27-08” không còn đúng tại thời
  điểm kiểm tra. Các unit đã được disable/mask lại, có restore timer 40 giờ.
  Source schema v7 yêu cầu trạng thái masked xuyên suốt preflight và monitor
  fail-closed nếu guard mất. Regression sạch đạt **436 pass, 2 warning**.
- 29-08-2026: tạo
  `INTEGRITY_INCIDENT_20260829T140500Z.json` cho A5. Original manifest có 28
  entry pass và một mismatch ở log checker phụ; ba worker `raw.tar.gz` đều được
  verify lại thành công. Dọn worker3 chỉ xóa duplicate A4/A5 có archive phục
  hồi; không xóa Longhorn managed data. Archive lịch sử tiếp tục được offload
  và hash-verify trước khi xóa bản worker.
- 30-08-2026: audit sau nâng cấp phần cứng xác nhận cả sáu VM đã nhận 24 vCPU,
  khoảng 126 GiB RAM usable và disk 600 GB. Root ext4 trước đó vẫn giữ kích
  thước cũ nên đã được mở rộng online lên 633.792.950.272 byte trên từng node.
  Kubelet được restart rolling, từng node một; allocatable ephemeral-storage
  sau refresh đạt khoảng 560,8 GB/control-plane và 531,2 GB/worker. Hậu kiểm có
  6/6 node Ready, 0 node pressure, 0 pod không-ready và 28/28 Longhorn volume
  healthy.
- Cũng trong ngày 30-08-2026, reboot hạ tầng làm lộ filesystem corruption trên
  Kafka-2 và Vault-1 cùng bbolt corruption cục bộ trên Vault-2. Mỗi sửa chữa
  đều có Longhorn snapshot trước thao tác. Filesystem được sửa bằng `e2fsck`
  trên đúng block device đã xác minh unmounted; Vault-2 corrupt state được giữ
  nguyên trong `lost+found/vault2-corrupt-20260830t0322z`, sau đó node được
  join/unseal lại. Kiểm tra cuối: Vault 3/3 Ready, autopilot healthy,
  FailureTolerance=1, năm ExternalSecret đều `SecretSynced=True`.
- Lỗi topology Longhorn được xử lý theo quy trình có snapshot/backup và không
  xóa dữ liệu nguồn. Worker3 được cordon/drain đúng PDB; cây clone 194 GB được
  giữ tại `replicas.clone-quarantine-20260830t0401z`. Disk UUID cũ
  `e0acfceb-...` được thay bằng UUID độc lập `af26014b-...`; các replica được
  auto-balance rồi khóa lại với `replica-auto-balance=disabled`. Guard cuối trả
  `duplicate_disk_uuid=0`, `colocated_running_replicas=0`, không volume nào
  non-healthy.
- Recovery làm lộ thêm corruption trên volume Kafka-0, OpenSearch-0,
  PostgreSQL replica-1 và Trivy DB. Chỉ block device đã unmount mới được sửa và
  mỗi volume đều có snapshot trước thao tác. Kafka-0 và Trivy trở lại Ready.
  PostgreSQL replica-1 mất `PG_VERSION`, nên không được vá file thủ công: bản
  forensic được backup NFS 100%, pod/PVC lỗi được thay và CNPG bootstrap lại từ
  primary. Cụm trở lại `Cluster in healthy state`, 3/3 Ready; truy vấn primary
  thấy hai replication stream.
- Hai OpenSearch node còn lại mang hai cluster UUID khác nhau, xác nhận
  split-brain metadata chứ không phải lỗi TCP 9300. Sau khi backup NFS 100% cả
  ba PVC và lưu manifest/checksum, riêng cụm OpenSearch telemetry được
  bootstrap lại theo cấu hình ba cluster-manager nhất quán. Hậu kiểm cho thấy
  cả ba node cùng UUID `VUagXlIUTV2vBHFNu0_arw`, health `green`, 9/9 shard
  active và 0 shard unassigned. Kafka CR trở lại `Ready` sau khi restart riêng
  Strimzi operator bị kẹt reconciliation; không restart broker.
- Regression trước A7 đạt **440 passed, 2 Torch deprecation warnings**. A7 mở
  lifecycle lúc 30-08-2026 04:34:54 UTC từ clean detached worktree `5568683`
  nhưng dừng ở production traffic preflight vì AIMS HTTP 503; chưa từng tạo
  `SOAK_START.json`. Service đã inactive/disabled, receipt rejection bất biến.
- Sau sửa AIMS topology, traffic gate, loader diagnostic và preallocated BPF
  counter map, R3 compatibility pilot terminal valid; R4 infrastructure-reject
  được giữ; R5 extended pilot đang active. Trainer hiện ghi rõ dirty source và
  hash toàn bộ tracked diff + untracked file vào model manifest. Cổng
  calibration mới tái tạo R3 là 16/20 workload đủ `alpha=0,001` và fail-closed
  cho bốn workload còn thiếu. Contract v2 khóa dataset + source fingerprint
  trước fit; post-processor bắt buộc checksum → coverage 20/20 → freeze → train
  → benchmark và không có lệnh promote. Overlay đạt **452 passed, 2 warnings**,
  receipt SHA-256
  `e3eab61c2f4050f7759fea221c5bd9ffd6a864df1911ee1d2128dd777b0103a8`.
  PID post-process 597434 đang chờ R5 terminal. Không có claim false-positive,
  recall hay kernel-to-alert mới và không có auto-promotion.
- 31-08-2026: R5 terminal valid với **178.991 window/249 feature/20 workload**,
  bốn regime steady/toolmix/burst/recovery lần lượt
  42.899/44.946/49.617/41.529, zero loss counter. Dataset SHA-256
  `2a016dc43b61c6c8e325c06e3d90e77bf8e567eb0acccf9f1c4c41d903acaf53`;
  window-start-to-emit p99 534,05 ms, ingest p99 29,26 ms. Calibration
  `alpha=0,001` đạt 20/20, nhỏ nhất 1.428 example (margin +429).
- Lượt post-process đầu fail-closed trước fit vì shared venv thiếu Narwhals và
  lệch software lock; evidence FAILED được giữ. Venv chuyên dụng đúng sáu
  version lock được tạo và lượt r2 hoàn tất 20/20 model, 0 collect-only, fit
  tổng 52,13 giây. Contract SHA-256 `bb3739bd...`, model manifest SHA-256
  `2e37ffd1...`; bundle verifier pass 27 entry, mọi file read-only.
- In-sample benchmark 10.000 inference cho mean/p50/p95/p99/max lần lượt
  16,70/16,46/20,16/**24,94**/37,12 ms, 58,26 scored window/s, peak RSS
  194.196 KiB. 9.999 normal và một suppressed, không có alert. Tổng hai tầng
  p99 đã đo khoảng 558,98 ms nhưng chưa phải kernel-to-alert end-to-end;
  candidate vẫn non-formal, dirty-source hash-bound, không auto-promote và chưa
  có claim no-FP/recall.
- Policy semantic A2 schema v2 SHA-256 `a7400e275d49c16999aa4688e3c3dcadd33d4ffb9c03d5f38479eaf10ba6cf2f`
  bind trực tiếp sáu normal/model artifact, bao phủ 20 workload, không dùng
  blind outcome và không thêm confirmation window. Benchmark policy-specific
  10.000 inference có p99 23,41 ms, max 34,77 ms, 9.999 normal + một
  suppressed và không thiếu workload.
- Canary normal 15 phút `pulse500-a2-live-canary-20260831T012000Z` đã terminal
  hợp lệ trên 3/3 worker, injection tracking tắt, audit-only, không enforcement
  và không auto-promote. Worker1/3/4 chạy lần lượt 902,62/901,86/903,34 giây,
  tạo 19.653/17.002/26.421 decision. Tổng **63.076 decision/20 workload** gồm
  62.069 normal, 89 suppressed, 918 warming, **0 alert quan sát và 0 restart**;
  toàn bộ loss/integrity counter bằng 0. Mỗi node có `CANARY_COMPLETE`, không có
  `CANARY_FAILED`; candidate detector đã dừng sau finalization, còn collector
  production 1 giây là pipeline riêng vẫn active.
- Aggregate checksum-verified trên 62.158 scored decision cho inference
  p50/p95/p99/max 16,75/24,09/**29,31**/48,43 ms; post-window p99 336,73 ms;
  window-start-to-decision p50/p95/p99/max
  649,87/789,41/**841,42**/994,47 ms. `AGGREGATE.v2.json` read-only có SHA-256
  `d649726dc478b4216cef69b33d611ec9fdac89f374672d0f43ad25db4a73aaa5`.
  Aggregator v2 xác minh `node_name` trên đủ 62.158 scored decision. Chỉ 918
  warming record của schema cũ thiếu provenance; runtime đã được vá để
  warming/collect-only record tương lai cũng ghi node/pod/container identity.
  Aggregate v1 được giữ bất biến làm lịch sử và không thay thế v2.
- Evidence chỉ cho phép nói “0 alert quan sát trong canary normal non-formal 15
  phút”, không cho phép claim FPR=0, không false positive, recall hay blind
  attack latency. Regression mới đạt **458 passed, 2 warnings**; receipt
  SHA-256 `a614fc4ce7002fa9ff616f5a0a4433d03aaf4fe18ee48d0d9b8d205bf7cb433f`.
  Hậu kiểm cụm: 6/6 node Ready ở Kubernetes v1.34.10 và 42/42 pod `production`
  Running.

### 7.31 Pilot kernel-to-alert A2 và hardening provenance (31-08-2026)

Sau live-normal canary, một pilot 15 trial được đăng ký trước trên ba role
`api-gateway`, `aims-postgres-cnpg` và `aims-kafka-dual-role`, năm scenario,
seed 13001 và rate 12 operation/s. Pilot mang nhãn
`nonformal_attack_latency_pilot`, không được dùng để train/tune, không tạo
`MATRIX_COMPLETE` và không có đường auto-promote. Mọi detection miss hợp lệ
được giữ; chỉ trial chưa có kernel provenance do lỗi hạ tầng mới được tiếp tục.

Các attempt R1–R5 đều được giữ riêng, checksum và không overwrite. R1 phát
hiện mismatch acknowledgement `done/complete`; R2 hoàn tất một Kafka
`namespace_probe` với kết quả miss rồi dừng do copy timeout CNPG; R3 chứng minh
`/tmp` của CNPG là read-only; R4 chứng minh `/dev/shm` chạy được nhưng stdout
exporter không cung cấp `process_exec`; R5 dùng `/run` và hoàn tất một CNPG
`credential_read_burst` có alert, sau đó dừng khi stdout exporter bỏ event exec
Kafka kế tiếp. Các attempt lỗi đều đã stop/disable candidate, archive raw
stream và tạo SHA-256 receipt. Miss R2 và alert R5 không bị chạy lại.

Để bỏ phụ thuộc vào stdout exporter, manifest
`sentinel/k8s/tetragon-sentinel-pulse-exec-provenance.yaml` thêm một
TracingPolicyNamespaced chỉ match hai exact path binary pilot trên
`sys_execve`. Policy được xác minh `enabled` trên 6/6 Tetragon sensor. Runner
mở `tetra getevents` gRPC trước khi ghi marker, yêu cầu đúng một event
`sys_execve` exact-path trên đúng node và fail-closed nếu policy không enabled,
event thiếu hoặc event trùng. Policy manifest được stage read-only và SHA-256
bind vào `BLIND_START.json`; marker userspace không được dùng thay kernel
timestamp. CNPG dùng `/run`, các controller còn lại dùng `/tmp`.

R6 `pulse500-attack-latency-pilot-r6-20260831T041332Z` đã terminal đủ **13/13**
trial còn lại, không có infrastructure failure. Mỗi injection có đúng một
kernel event gRPC; `injections.jsonl` và `kernel-events.jsonl` cùng có 13 dòng.
Runner ghi 9 alert và giữ nguyên bốn miss: Kafka
`identity_transition_probe`, API gateway `process_fanout`, API gateway
`namespace_probe` và Kafka `credential_read_burst`. Kế hoạch lineage mang theo
hai outcome bất biến không chạy lại: Kafka `namespace_probe` miss từ R2 và CNPG
`credential_read_burst` alert từ R5. Vì vậy toàn pilot có 15 trial, 10 alert và
5 miss; tỷ lệ 10/15 chỉ là thống kê mô tả của pilot, **không phải recall được
phép công bố**.

Finalizer đã dừng/disable candidate trên ba worker, archive raw stream và kiểm
tra toàn bộ `RAW_SHA256SUMS`/`FINAL_SHA256SUMS`. Lần finalize đầu fail-closed vì
evaluator cũ chỉ chấp nhận `tetragon_process_exec`, trong khi R6 dùng nguồn mới
`tetragon_execve_kprobe_grpc`. Evaluator được sửa để xác minh nghiêm ngặt cả
hai schema: policy name, exact binary argument, function `sys_execve`, node,
exec ID, PID, raw-event checksum và timestamp. Finalizer cũng có recovery path
chỉ đọc raw archive đã checksum, do đó không cần và không được chạy lại attack.
Kết quả cuối có đủ kernel/model/policy/run/identity gate và checksum pass.

Trên **9 alert của riêng R6**, kernel-to-alert min/p50/p95/p99/max là
0,214/0,718/4,739/**5,332**/5,481 giây. Sáu alert dưới 2 giây nhưng ba outlier
là Kafka `process_fanout` 5,481 giây, Kafka `local_socket_beacon` 3,044 giây và
API gateway `identity_transition_probe` 3,628 giây. Inference p99 chỉ 28,97 ms
và post-window processing p99 337,31 ms; vì vậy phần lớn tail latency không đến
từ ExtraTrees mà do model/corroboration chỉ cùng thỏa ở cửa sổ muộn. Pilot fail
cả coverage và cổng p99 <= 2 giây (`pilot_engineering_pass=false`). Phân tích
sau sự kiện cho thấy một số miss không qua raw-model gate, số khác có anomaly
và semantic signal ở các cửa sổ khác nhau. Chẩn đoán này không được dùng để
tune candidate A2 hay đổi outcome; kiến trúc kế tiếp phải hiệu chỉnh bằng normal
data độc lập rồi đánh giá trên blind set mới. Full regression sau hardening đạt
**472 passed, 2 warning**.

### 7.32 Candidate bounded event-time B1 (31-08-2026)

A2 được giữ nguyên làm development evidence sau khi fail pilot; không sửa model
hoặc policy A2 theo 15 attack outcome. Nhánh B1 thêm policy schema v3 và bộ nhớ
corroboration theo event-time: model anomaly đã qua score gate và semantic
evidence có thể nằm ở hai cửa sổ khác nhau nhưng cách nhau không quá horizon
đóng băng. State tách theo workload/node/pod/container/cgroup, hết hạn theo
event-time, reset khi temporal gap hoặc traffic regime đổi và consume sau alert.
Loader từ chối horizon <=0 hoặc >2 giây, policy thiếu normal calibration, hoặc
policy có đường auto-promote.

Calibration chỉ replay canary normal A2, không đọc attack outcome. Attempt đầu
fail-closed vì 918 warming record schema cũ thiếu full identity và được giữ tại
`temporal-calibration-b1-20260831T114503Z/FAILED.json`. Calibrator được sửa chỉ
bỏ qua warming unscored; mọi scored row vẫn bắt buộc đủ identity, model, policy,
run và timestamp. R2 đọc **63.076 decision**, gồm 62.158 scored và 918 warming;
baseline có 0 alert. Cả bốn horizon 0,5/1,0/1,5/2,0 giây đều chiếu ra 0 alert
trên normal canary. Report SHA-256 là
`86296997db4cd25f61ee4fb8084a9de53ae1456b5155d714f423cae4f7c2c431`.

B1 chọn horizon **1,0 giây** từ latency budget, không chọn theo attack recall.
Policy `sentinel-pulse-bounded-join-b1` có SHA-256
`bdbdd2577c8a9a31a5ee0bb220e2e540f413a8035f85a6b311351d2332bcf85b`,
bind model A2, base policy A2 và temporal calibration; bundle read-only và
checksum pass. Canary live normal B1 R2
`sentinel-pulse-bounded-canary-b1-r2-20260831T120032Z` đã terminal song song
trên ba worker sau 901,79–903,29 giây. Aggregate hợp lệ có **63.160 decision**
trên 20 workload: 62.164 normal, 85 suppressed, 911 warming và **0 alert quan
sát**, 0 detector restart. Trên 62.249 scored decision, inference
p50/p95/p99/max là 16,95/24,46/**29,65**/118,58 ms; post-window p99 338,42 ms;
window-start-to-decision p50/p95/p99/max là
0,653/0,791/**0,843**/1,024 giây. Aggregate SHA-256 là
`afdb4b92bed4baa2406cab60158550ef4d5cd3f092a0f74aa1eb272f218adb7c`;
`FINAL_SHA256SUMS` pass, `ACTIVE` đã xóa và candidate inactive+disabled trên
3/3 worker.

Attempt collect đầu fail trước copy vì precheck chạy bằng user `dat` không
traverse được run directory `0750 root`; raw node evidence vẫn nguyên vẹn.
Collector được sửa để precheck bằng `sudo`, sau đó archive và aggregate pass.
Kết quả chỉ cho phép nói “0 alert quan sát trong canary normal non-formal 15
phút”, không phải FPR=0. B1 không được đánh giá lại bằng attack set A2 để claim
blind accuracy; bước attack kế tiếp phải freeze blind contract mới.

### 7.33 B1 fail normal dài, B2 risk-tiered và blind set C2 (31-08-2026)

Tập successor C1 được tạo trước khi đánh giá candidate, gồm năm scenario mới
`anonymous_mprotect_churn`, `child_ptrace_handshake`, `invalid_setns_burst`,
`seccomp_api_probe` và `execveat_resolution_probe`; không trùng năm scenario
A2. Binary static chỉ có effect trong process tree, không external network,
persistent write, mount hay privilege change. Smoke test chạy khi candidate
detector tắt trên 3/3 worker và chỉ xác minh execute/cleanup. Bundle C1 bất biến
tại `contract-c1-20260831T165500Z`, SHA-256 của index là
`2b24541ee6ec6488878bdfeb73b83e9f8f43f8687cc9687ad81728ae5eccdaff`.
Không outcome ML nào của C1 đã được đọc.

Attempt normal dài đầu tiên fail ở launcher vì dùng model snapshot của canary
chỉ có manifest, thiếu file `.pkl`; cleanup xác nhận candidate/collector 500 ms
inactive trên 3/3 worker và attempt giữ `START_FAILED`. R2 dùng đúng bundle
training đầy đủ nhưng B1 phát sinh hai alert normal nên được dừng sớm, không
chờ đủ 24 giờ. Archive checksum có **39.051 decision**, 2 alert: Redis trên
worker4 và PostgreSQL trên worker3; worker1 có 0 alert. Summary SHA-256 là
`1477c5441143569254fc732872a40ca9886daf7456497a3564121b2a516f51fb`,
checksum index SHA-256 là
`df7684e1935ddcb459290cc5625e00eb7c9ae53064091b23f3afe5e2c67ecada`.
B1 vì vậy bị reject, tuyệt đối không được trình bày là stable hay FPR=0.

Hai false alert có cùng cơ chế phase-shift. Redis có window semantic trước với
`clone3=5`, vượt `process_fanout` envelope đúng 4; window sau cách 0,504 giây
có score 0,6179 vượt calibration max 0,5739. PostgreSQL có window trước với
socket+connect=34 và openat=127, vượt envelope tương ứng; window sau cách
0,505 giây có score 0,6077 vượt calibration max 0,5799. B1 đã cho các tín hiệu
thường gặp này mượn semantic evidence từ window trước. Runtime cũng được sửa để
alert tương lai nhúng score/conformal của model evidence cùng mass, exact field,
triggered group của semantic evidence thay vì chỉ ghi timestamp.

B2 áp dụng **risk-tiered temporal join**: mọi signal group vẫn alert nếu model
và semantic cùng window, nhưng chỉ `identity_transition` và `namespace_probe`
được join lệch window tối đa 1 giây. `socket/open/fanout` không được carry qua
window. Replay normal-only trên 39.051 decision checksum-bound (38.429 scored,
622 warming, 2 alert B1) chiếu ra **0 alert B2** ở cả horizon
0,5/1,0/1,5/2,0 giây. Calibration SHA-256
`584b2ea6c2584dc7d2e4d86eb7b84a1759e42eefc77c23b628b740fe648383ce`;
policy B2 SHA-256
`17fa395a3e538d603ed0afe27529dbbd77ae30e1a602b3f9e812134056de83ac`.

Blind contract C2 bind model `2e37ffd1…` và policy B2 `17fa395a…`; C2 kế thừa
scenario chưa mở của C1, ghi rõ predecessor chưa từng candidate-evaluate và
không dùng attack outcome. Freeze index C2 SHA-256 là
`d2f425b493daeee892f9b19e12589920a2c6c3ef8e99ad59bbc6d9dc9055ff95`.
Canary B2 900 giây `sentinel-pulse-risk-tiered-canary-b2-20260831T175000Z`
bắt đầu lúc 17:28:49 UTC trên 3/3 worker, audit-only, injection tracking tắt.
Run đã terminal hợp lệ sau tối thiểu 901,86 giây; cả ba worker có
`CANARY_COMPLETE`, toàn bộ detector/collector/finalizer đã inactive và mọi
checksum trong `FINAL_SHA256SUMS` đều pass. Aggregate có **63.315 decision**
trên 20 workload: 62.302 normal, 82 suppressed, 931 warming và **0 alert normal
quan sát**, 0 detector restart. Trong 62.384 scored decision, inference
p50/p95/p99/max là 16,74/23,98/**29,28**/110,74 ms; post-window processing
p99 là 332,63 ms; window-start-to-decision p50/p95/p99/max là
0,650/0,786/**0,837**/1,029 giây. Aggregate SHA-256 là
`861090772045a495c10e07340f7a620e1d74061321690c5db5ea68ff57b207d5`;
checksum index SHA-256 là
`e148edfdabf7957317a59c6798dfb7164ea4e78bf059f0f9507a6a5387518335`.

Đây chỉ là **0,25 giờ live-normal non-formal**: kết quả cho phép nói “không có
alert trong canary này”, nhưng không cho phép suy ra FPR=0, recall, blind
accuracy hoặc production readiness. C2 vẫn chưa được mở. Regression source B2
đạt **482 passed, 2 Torch deprecation warnings**. Hậu kiểm trước canary có 6/6
node Ready, 42/42 pod production Ready và Tetragon 6/6 Ready.

Ngay sau khi khóa canary, soak B2 dự kiến 24 giờ được khởi chạy với run ID
`sentinel-pulse-risk-tiered-soak-b2-20260831T175408Z`, bắt đầu
`2026-08-31T17:54:14.278261Z`. Run giữ nguyên model `2e37ffd1…`, policy
`17fa395a…`, normal-only, audit-only, `blind_outcome_used=false` và
`automatic_promotion=false`. Tuy nhiên zero-alert gate đã fail sau khoảng 13
phút nên run được dừng sớm và archive, không chờ đủ 24 giờ. Evidence terminal
có **52.660 decision**: 51.772 normal, 95 suppressed, 791 warming và **2 alert
normal**, 0 restart. Worker1 và worker4 mỗi node có một alert; worker3 có 0.
Summary SHA-256 là
`194c1541e21df3120690d84a103dacaac138aba886b131d9cb8baa2fec887cae`;
checksum index SHA-256 là
`ff438b3c25deb681fafe366fd50c01b826edb794bf6085c7282709afaeeaaf5f`.

Cả hai alert là PostgreSQL trên hai replica gần như cùng thời điểm và đều là
same-window, không phải lỗi cross-window của B1: model anomaly trùng burst
socket/connect/openat/clone bình thường. B2 do đó bị reject và không được gọi
stable. Replay development normal ban đầu với xác nhận hai window liên tiếp,
gap tối đa 1,25 giây và bypass `namespace_probe` chiếu 2 alert xuống 0 trên
51.869 scored decision; report SHA-256 `90e96068665679f8a5405ce750cdd04ff05e96756c02a176e5fa4992647423cb`.
Đây chỉ là hướng B3 từ normal evidence, chưa phải kết quả candidate. C2 vẫn
đóng và không được dùng để tune.

B3 hiện đã được implement thành policy/runtime riêng, không sửa model A2.
Nhóm phổ biến `local_socket_beacon`, `process_fanout`, `credential_open` phải
có model+semantic+score gate ở **hai window liên tiếp cùng signal group**,
gap tối đa 1,25 giây. `identity_transition` và `namespace_probe` vẫn bypass
ngay; bounded cross-window join của B2 chỉ áp dụng cho hai nhóm này. Khi
telemetry gap hoặc traffic regime đổi, cả history model, bounded evidence và
confirmation state đều reset. Với window 500 ms, nhánh phổ biến thêm tối đa
một window xác nhận, còn nhánh high-risk không thêm wait.

Replay B3 R2 dùng trực tiếp ba decision stream trong failed B2 và xác minh qua
`FAILED_FINAL_SHA256SUMS` SHA-256 `ff438b3c…`; model, policy và run identity đều
được fail-closed. Trên 51.869 scored decision, 2/2 alert B2 bị suppress và
projected alert B3 bằng 0. Replay SHA-256
`83d049bad9955cee00ce9e946914e9276f62c3dc334b601b8b285a968424fb8e`.
Policy `sentinel-pulse-risk-tiered-consecutive-b3` source-clean có SHA-256
`02e0f02aa846ae6a6548004b73e5e8274d5f53f098f6cccf4fc6301277583d10`.
Full regression sau implementation đạt **487 passed, 2 Torch warnings**.

Live-normal canary B3
`sentinel-pulse-consecutive-canary-b3-20260901T000957Z` đã terminal hợp lệ trên
ba worker sau tối thiểu 902,03 giây. Aggregate có **63.056 decision/20
workload-container**: 62.058 normal, 66 suppressed, 932 warming, **0 alert** và
**0 detector restart**. Trong 62.124 scored decision, inference
p50/p95/p99/max là 16,75/23,91/**29,00**/51,00 ms;
window-start-to-decision p50/p95/p99/max là
0,650/0,790/**0,842**/0,970 giây. Aggregate SHA-256 là
`a68b3ea3281681b1b931b122426f109bdf9788fcee4e59f4f716fd020d2422c2`;
`FINAL_SHA256SUMS` SHA-256 là
`551529c03e9d1b367b76ed86330222f70485167ad059451c051e94a9d4e0cec7` và toàn
bộ checksum đã pass.

Ranh giới claim không đổi: đây là live-normal canary non-formal 0,25 giờ,
không chứng minh FPR=0, recall, formal kernel-to-alert hay production
readiness. C2 chưa mở nhưng bind policy B2 nên không còn hợp lệ cho B3. Trước
khi cân nhắc promotion, B3 phải qua long normal soak và một blind contract mới
được freeze sau policy B3 mà không dùng kết quả attack để tune.

### Formal normal-only soak B3

Lifecycle sau canary đã được harden trước khi mở soak: bounded supervisor tự
terminalize control-plane evidence; formal runner hỗ trợ
`STOP_AFTER_NORMAL=true`; control collector được suspend/restore có receipt;
model và policy được bind bằng hash sau cài; isolated detector unit không còn
`Wants=` control collector trong formal mode. Maintenance monitor cũng được sửa
để phân biệt trạng thái hợp lệ `masked` với lỗi SSH, và failure archive hoạt
động cả khi fail trước monitor row. Regression sau cùng đạt **490 passed, 2
warnings**.

R2, R3 và R4 là development infrastructure/evidence rejection, không phải
model result: R2 load nhầm policy V4 do thiếu explicit binding; R3 hiểu sai exit
code của `systemctl is-enabled`; R4 phát hiện systemd `Wants=` tự bật control
collector. Cả ba bị cấm dùng cho training/tuning/normal gate/blind evaluation;
R3/R4 quan sát 0 alert trước khi archive.

R5 `sentinel-pulse-formal-normal-b3-r5-20260901T122000Z` hiện active, bind
source `3c3be6c…`, model `2e37ffd1…`, policy B3 `02e0f02a…`. Start marker là
`2026-09-01T12:16:28.224154Z`, eligible finalize sau đúng 24 giờ. Snapshot
`2026-09-01T12:57:07Z` có 105 monitor row, tương đương 35 vòng đầy đủ trên ba
worker và **168.940 decision hiện hữu, 0 alert, 0 restart**; control collector
inactive, experimental collector/detector active và feature source đúng trên
cả ba worker. Đây mới là trạng thái `ACTIVE`, chưa phải normal pass, FPR claim
hay production promotion.

### Blind contract C3 đóng băng nhưng chưa mở

C3 được preregister tại `blind-attack-contract-b3.json`, SHA-256
`85ead02bae2e7f79744523d14332faac1f3e8e51d623ddf6d23adcb53d81b328`.
Contract bind model `2e37ffd1…`, policy B3 `02e0f02a…` và đúng runtime commit
R5 `3c3be6c…`. Ma trận giữ nguyên bộ chưa mở của C2: 18 controller × 5
scenario × 5 seed/rate = **450 injection**; năm scenario A2 bị loại trừ và
không có attack outcome nào được dùng để chọn lại scenario hoặc tune policy.
Attack implementation vẫn bind static binary/source B1 đã khóa checksum.

Validator hiện fail-closed cả predecessor-contract digest/trạng thái unopened
và runtime commit. Wrapper `open_b3_blind_after_normal.sh` chỉ chuyển phase khi
R5 có `NORMAL_PASS`, không còn `ACTIVE`, không có `INFRA_FAILURE.json`, runtime
tracked source sạch, không có untracked file ngoài `.runtime-artifacts/` và HEAD
đúng `3c3be6c…`. Full regression trên ML venv của VM đạt **493 passed, 2 Torch
warnings**. Offline audit compile lại static source cho đúng binary SHA-256
`d77c7237…`; toàn bộ model/policy/predecessor/C3 binding đều khớp. Guarded
opener được thử khi R5 còn active và fail trước mọi mutation với exit code 1.
Tại snapshot trên, C3 **chưa được mở**, không có attack injection và
`blind_evaluation_started=false`; vì vậy chưa có recall hay kernel-to-alert
blind result để công bố.

### Hardening terminal finalization của R5

Audit lifecycle phát hiện nhánh finalizer lỗi trước đây chỉ để lại
`FINALIZE_FAILED`: lifecycle có thể thoát trước khi tạo `FAILED`, archive raw
evidence và restore control collector. Đây là lỗi orchestration tiềm ẩn, chưa
xảy ra trên R5 và không phải model alert. Lifecycle mới bắt exit code finalizer,
ghi failure marker nguyên tử, xóa `ACTIVE`, archive với
`candidate_status=not_evaluated_by_this_run` và kết thúc trước blind interlock.

Vì R5 đang chạy runtime commit đã khóa `3c3be6c…`, code của tiến trình không bị
hot-patch. Thay vào đó, external supervisor read-only được attach lúc
`2026-09-01T13:06:40.745040Z`, PID `2212271`, theo dõi lifecycle PID `2165273`.
Supervisor chỉ được mutation sau khi lifecycle đã chết, chờ thêm 120 giây mà
vẫn không có `NORMAL_PASS`/`ARCHIVE_COMPLETE`; khi đó mới fail-closed archive
và restore. Integration test xác minh không mutation khi lifecycle sống và
đúng failure archive khi finalizer chết. Full regression đạt **497 passed, 2
Torch warnings**.

Snapshot R5 `2026-09-01T13:06:59Z`: 132 monitor row = 44 vòng đầy đủ trên ba
worker, **213.250 decision, 0 alert, 0 restart**. R5 vẫn active và C3 vẫn chưa
mở; snapshot này không phải terminal normal/FPR/recall claim.

### Terminal R5 và sửa coverage pacing (02-09-2026)

R5 đã kết thúc sau hơn 24 giờ với 6.131.787 scored window, 0 alert quan sát và
Wilson 95% upper bound `6,264823638016002e-7`. Tuy nhiên formal gate trả
`normal_gate=false`: `production/aims-frontend:web` chỉ có 73.906 giây quan sát
trên span 86.649 giây (`coverage_ratio=0,8529354061`) trong khi protocol khóa
ngưỡng 0,95. Tất cả identity/integrity, duration, 20/20 workload và 19 coverage
key còn lại đều pass. Đây là **coverage/evidence rejection**, không phải model
false alert và cũng không phải normal pass. C3 vẫn unopened; không có blind
attack nào được inject và R5 bị cấm dùng để train/tune.

Root cause là ingress loadgen thực hiện 4--6 request liên tiếp rồi sleep một
giây, tạo khoảng trống định kỳ trong exact second-bucket dù tổng traffic vẫn
healthy. Fix giữ gần cùng throughput bằng pacing từng request 0,22 giây; ngưỡng
coverage không bị hạ. Bộ aggregate canary mới tính second-bucket cho từng model
key, yêu cầu đủ workload, span tối thiểu 300 giây và coverage ≥0,95 trước khi
cho phép formal R6. Startup cũng verify toàn bộ `.pkl` trước khi chạm service và
restore control collector ở mọi nhánh lỗi. Full regression đạt 499 passed.
Preflight đầu tiên sau pacing được dừng sớm ở 378,27 giây: đủ 20 workload,
0 alert/restart nhưng frontend vẫn chỉ đạt 281/353 bucket (79,60%), vì chỉ URL
`/` chạy code frontend còn `/api/*` route thẳng tới api-gateway. Run được đóng
`coverage_preflight_failed`; R6 không mở. Loadgen tiếp tục được sửa thành hai
request `/` mỗi vòng, vẫn giữ gần cùng tổng RPS.

Preflight R3 terminal pass sau 601,85 giây với 42.054 decision, 0 alert/restart
và đủ 20/20 workload. Coverage thấp nhất là frontend 560/580 bucket = 96,55%.
Inference p99 29,02 ms, post-window-processing p99 0,341 giây và
window-start-to-decision p99 0,846 giây (max 0,966 giây). Aggregate SHA-256
`f3f601151b07cca8d7f7de266c0814841750b9bdbd4f92a3fe6eeef8d52b2fcc`.
Đây chỉ là engineering preflight, không phải accuracy claim. Regression hiện
đạt 504 passed, 2 warnings. Formal normal-only R6
`sentinel-pulse-formal-normal-b3-r6-20260902T154252Z` đã active sau 309 giây
stability preflight với frozen runtime/model/policy B3. Marker start
`2026-09-02T15:48:42.587983Z`, eligible finalize đúng 24 giờ sau và có SHA-256
`af0ac94dd206691e530d6436e5cf3bd7d0a5ef1baefbe63702b32cfaf9dc7792`.
Snapshot `15:51:53Z` có 7.022 decision/0 alert/0 restart; ba experimental
collector/detector active, control collector inactive và feature binding khớp.
External supervisor đã attach; C3 vẫn đóng và `STOP_AFTER_NORMAL=true`.

Hậu kiểm SSH lúc `2026-09-02T16:03:42Z` ghi nhận tổng **61.394 decision, 0
alert, 0 restart** trên ba worker; collector/detector đều active, feature binding
đúng, 6/6 node Ready và không có pod production non-Ready. R6 vẫn chỉ là run
đang chạy, chưa đủ 24 giờ nên chưa có normal-gate result. C3 không có evidence
file và không có attack injection.

Failure freezer của source canonical đã được sửa để tránh lặp I/O: khi
finalizer đã tạo và verify `RAW_SHA256SUMS`, freezer tái sử dụng cây raw local
read-only và chỉ hash metadata mới vào `FAILURE_SHA256SUMS`. Nhánh monitor fail
trước checkpoint vẫn dùng archive `raw.tar.gz` tự chứa. Cơ chế này không tune,
evaluate hay promote model và không hot-patch frozen runtime của R6.
Thay đổi ở commit `941037b`; host, `origin/main` và VM canonical đã đồng bộ.
Full regression trên VM đạt **505 passed, 2 Torch deprecation warnings**.

Bounded-canary preflight tiếp tục được harden để không phụ thuộc magic number
42 pod: nó checksum-bind snapshot node/pod, yêu cầu đúng 6 node, zero unhealthy
resource và namespace không rỗng; expected workload coverage vẫn được quyết
định bởi model manifest ở aggregate gate. `POLICY_SOURCE` nay bắt buộc explicit
ở cả lifecycle và normal finalizer, ngăn fallback nhầm policy cũ. Full
regression đạt **508 passed, 2 Torch deprecation warnings**. Hậu kiểm R6 lúc
`2026-09-02T16:16:19Z` có **116.061 decision, 0 alert, 0 restart**; đây vẫn là
interim observation.

Lifecycle canonical còn giữ single-writer lock theo run ID và kiểm model/policy
hash ngay khi resume. Duplicate process hoặc identity mismatch dừng trước
monitor/finalizer; hai behavioral test thực thi thật đã khóa hai invariant này.

### R6 terminal: B3 bị loại bởi false positive PostgreSQL (03-09-2026)

R6 bắt đầu `2026-09-02T15:48:42.587983Z` và monitor fail-closed lúc
`19:12:43Z` với `reason=normal_alert_observed`. Archive hoàn tất lúc 19:15:23Z;
không còn `ACTIVE`, không có `NORMAL_PASS`. Audit tái lập từ ba raw tar, sau khi
verify 32/32 checksum, thu được **882.176 decision và đúng 1 alert**. Phân bố
theo worker là `.237` 271.583/1, `.238` 375.181/0, `.239` 235.412/0.

False alert ở pod `aims-postgres-cnpg-2`, workload
`production/aims-postgres-cnpg:postgres`: score 0,734959, conformal p-value
0,00023299, inference 19,88 ms và post-window processing 0,194 giây. Hai
window liên tiếp cùng kích hoạt `local_socket_beacon`; window thứ hai có 24
`socket`, 24 `connect`, 7 `clone`, 104 `openat`. Local-socket observed 48 vượt
normal max 28, trong khi score vượt calibration max 0,155014. Alert xuất hiện
khoảng 0,698 giây sau đầu window, nhưng đây là latency của false alert chứ
không phải attack-detection result.

Hạ tầng không cung cấp bằng chứng để reject alert này: tại failure snapshot,
6/6 node Ready, 42/42 pod production khỏe, 28/28 Longhorn volume healthy và
CNPG 3/3 instance ready. Finalizer của worker phát alert `.237` hợp lệ, service
healthy, zero drop, interval p99 0,507 giây và emit p99 0,525 giây. Worker
`.238` có một cụm 47 row interval-invalid do gap tối đa 3,078 giây nhưng không
phát alert; chi tiết này không được dùng để che false positive ở `.237`.

Archive gốc được giữ bất biến. Vì freezer schema v1 từng gắn nhầm mọi monitor
failure thành infrastructure rejection, sidecar audit riêng tại
`/home/dat/sentinel-pulse-evidence/posthoc-analysis/sentinel-pulse-formal-normal-b3-r6-20260902T154252Z`
bind lại source hashes và ghi `classification=rejected_normal_gate`. SHA-256
classification là `9521dce42cfc45153080d7e86e65617601d93c1668ddec8894b687ded4a8dc2e`.
Source canonical commit `6e9f188` đã sửa freezer tương lai và thêm audit tool;
full regression đạt **513 passed, 2 warnings**.

Kết luận khoa học: B3 không stable và không được mở blind C3. R6 chỉ được dùng
như normal development evidence nếu thiết kế B4; không được dùng train model,
tune rồi vẫn gọi C3 cũ là blind, hoặc claim FPR bằng 0. Hướng B4 cần tách
PostgreSQL connection burst hợp lệ khỏi beacon bằng provenance destination
hoặc policy confirmation chuyên biệt theo semantic group, sau đó đóng băng
identity mới và chạy normal soak độc lập.

### B4: group-specific temporal confirmation (04-09-2026)

B4 giữ nguyên 20 model `PulseExtraTrees` và chỉ thay decision policy. Ba raw
stream R6 đã được materialize thành 882.176 row với checksum index SHA-256
`4c0eb55db008548c2e7574cd5f7e3fea392fa02c3c97aaa15963894edb3940b0`.
Replay normal-only xét 874.270 scored row và 7.906 warming row: một alert B3
được suppress, B4 project 0 alert. Replay report SHA-256 là
`1a16c7a073478de5c7e266c3a64f6c181e8deb3b708d118f327d6c0f30cf51bb`.
Không attack outcome nào được dùng và replay này không tạo claim FPR/recall.

Runtime giữ streak độc lập cho từng semantic group và source identity. Nhóm
thường cần hai window liên tiếp; `local_socket_beacon` cần ba để chịu được
PostgreSQL connection burst; `identity_transition` và `namespace_probe` vẫn
alert ngay khi model, score và semantic evidence hợp lệ. Khoảng cách liên tiếp
tối đa 1,25 giây, state reset khi mất continuity và consume sau alert. Policy
B4 có SHA-256 `205b8d31252926f99f6716a37dfeaf3bc7d4324a51df5bf71da0f7a9cd11b187`.

Frozen runtime là commit `a561520ac9479e06a1ca08dbbf92070c28b906a0`,
tracked tree sạch; model manifest vẫn là `2e37ffd1…`. Blind contract B4 SHA-256
`9b1788cb4ff88a624d109f24b693d690cf61cfd67f91b345935104e1238e0454`
bind chính xác ba identity này và giữ nguyên ma trận chưa mở 450 injection. B4
blind evidence hiện có 0 file. Traffic preflight trước live canary đạt 90/90
east-west và 30/30 north-south, 9/9 rollout Healthy. Regression canonical mới
nhất đạt **524 passed, 2 warnings**.

Supervisor formal được sửa trước khi chạy dài: systemd environment root-only
giờ bắt buộc mang policy identity, mặc định `STOP_AFTER_NORMAL=true`, suspend
control collector và giữ duration/preflight interval qua reboot. Do đó normal
pass cũng chỉ kết thúc lifecycle; blind B4 chỉ có thể được mở qua guarded
opener sau khi verify marker, checksum và runtime commit.

Live-normal canary B4
`sentinel-pulse-b4-canary-r1-20260904T014737Z` đã terminal
`rejected_normal_gate`, không mở formal soak. Tổng 57.252 decision có đúng một
false alert trên `aims-kafka-dual-role:kafka`; 71/71 checksum trong failed
bundle verify thành công. Alert có score 0,766911, p-value 0,00023299,
inference 17,41 ms và post-window processing 0,197 giây.

Nguyên nhân không phải streak ba window của B4. Window trước kích hoạt nhiều
semantic group, trong đó có `identity_transition`, nhưng score chưa vượt margin;
window sau có score vượt margin nhưng không có semantic activity. Bounded
model-semantic join giữ evidence 1 giây đã ghép hai window cách nhau 0,503 giây
và phát alert; `temporal_confirmation_count=0`. Đây cũng chứng minh replay B4
ban đầu chưa mô phỏng toàn bộ decision policy vì chỉ xét confirmation branch.
B4 vì vậy bị đóng như failed candidate. Successor chỉ được giữ bounded join
cho `namespace_probe`, còn identity signal phải đồng thời với model/score trong
cùng window; mọi thay đổi cần identity, canary và normal soak mới.

### B5: bounded join chỉ dành cho namespace probe (04-09-2026)

Full-policy evaluator mới tái hiện đúng false alert B4 trên 56.491 scored
window. Policy successor chỉ giữ cross-window join cho `namespace_probe` cho
0 projected alert trên cùng canary và 0/874.270 trên R6, tổng 930.761 scored
normal window. Ba report checksum-bound được lưu trong
`sentinel_pulse/protocol/development-b5/`; chúng là development evidence,
không phải FPR hoặc recall.

B5 policy SHA-256 là
`ab6a4f6b93e2c5548ffaad9727fc0a23839d20ea2e27b7f6d7ea7e5eb155c5c7`.
Identity transition chỉ bypass khi model/score/semantic cùng window;
namespace probe được phép lệch tối đa một giây. Runtime commit đóng băng là
`5bb0c131ff88962e6c5b0ee56da72bf9892d04a0`. Blind contract B5 SHA-256
`ee91b565bebf50516793b1273e7b8a6716d95fdde6a12b545a90ed78e974e9fb`
đã khóa trước canary, kế thừa nguyên ma trận 450 injection chưa mở.

Traffic gate trước canary đạt 90/90 east-west, 30/30 north-south và 9/9
rollout Healthy. Run `sentinel-pulse-b5-canary-r1-20260904T080800Z` terminal
valid sau 900 giây với **63.531 decision, 0 alert, 0 restart và 20/20 workload**.
Inference p50/p95/p99 là 16,83/24,29/29,50 ms; p99
window-start-to-decision là 0,851 giây, max 0,998 giây. Coverage thấp nhất là
frontend 96,23%. Bundle verify 73/73 checksum; aggregate SHA-256 `82d31b85...`.
Đây chỉ là canary non-formal 0,25 giờ, không tạo FPR/recall claim. Full
regression tại thời điểm freeze B5 đạt **530 passed, 2 warnings**.

Formal normal run `sentinel-pulse-formal-normal-b5-r1-20260904T082600Z` đã
được giao cho persistent systemd lifecycle lúc 08:26:21 UTC. Duration đăng ký
90.000 giây (25 giờ), stability preflight 300 giây và
`STOP_AFTER_NORMAL=true`; control collector được suspend chỉ sau khi preflight
đạt. Preflight đã pass; `SOAK_START.json` ghi start 08:32:14 UTC và phase
`normal_active` bắt đầu 08:33:22 UTC. Ba worker đều có collector/detector
active, legacy collector inactive, restart=0; model/policy trên từng worker
khớp `2e37ffd1...`/`ab6a4f6b...`. Start bundle verify 3/3 checksum. Mốc eligible
finalize là 08:32:14 UTC ngày 05-09-2026. Blind interlock vẫn đóng, không có
automatic promotion và chưa được suy diễn formal pass khi run còn active.

### B5 formal rejection và B6 development proposal (05-09-2026)

B5 formal normal run bị lifecycle loại fail-closed lúc 09:26:06 UTC ngày
04-09, sau khoảng 53 phút active. Archive verify 31 entry, có 230.683 decision
row, 228.563 scored row, một alert và zero detector restart. Không có
`NORMAL_PASS`; blind B5 chưa từng mở.

Alert ở Kafka broker trên worker `.238`: window 0,504 giây, score 0,639083,
p-value 0,00023299, inference 25,99 ms. `setuid=12`, `setgid=12`, `capset=2`
làm identity-transition observed 26 vượt envelope 15. B5 cho nhóm này bypass
ngay ở count 1 nên phát alert cùng window; bounded join không tham gia. Pod
không restart và liveness/readiness đều là exec probe chu kỳ 10 giây; không có
identity transition lặp ở window kế tiếp.

Worker phát alert còn có một gap collector 4,8549 giây và các lỗi containerd
`ExecSync DeadlineExceeded`. Do continuity invalid, run không được dùng để
ước lượng formal FPR; tuy nhiên zero-alert gate vẫn loại B5 và alert không bị
xóa hoặc đổi nhãn. Audit checksum-bound được lưu trong
`protocol/development-b6/b5-formal-failure-audit.json`.

B6 mới ở development: chỉ `namespace_probe` được immediate bypass;
`identity_transition` cần hai window liên tiếp. Ba replay normal-only độc lập
project 0 alert trên 228.563 + 56.491 + 874.270 = **1.159.324 scored window**.
Không attack outcome nào được đọc. B6 phải có policy/runtime/contract identity
mới, canary mới và formal normal soak mới trước khi guarded blind opener được
phép chạy.

Policy B6 đã được freeze từ clean commit `2bb3a67`, có SHA-256 `53f3346f...`;
runtime đóng băng tại `ab3535ae715757e876567990b7e33e7a669b8014`. Blind
contract B6 SHA-256 `b2f5db8e...` bind chính xác model `2e37ffd1...`, policy và
runtime trên, đồng thời kế thừa nguyên 450 injection chưa mở của B5. Guarded
opener chỉ chấp nhận một B6 `NORMAL_PASS` độc lập. Việc freeze contract không
có nghĩa blind đã bắt đầu; evidence blind B6 vẫn phải rỗng trước canary.
Full regression B6 trên ML venv của VM đạt **535 passed, 2 Torch deprecation
warnings**.

### B6 live canary và formal normal soak (05-09-2026)

Traffic gate độc lập trước canary đạt 90/90 east-west HTTP 200, 30/30
north-south và 9/9 rollout Healthy. Run
`sentinel-pulse-b6-canary-r1-20260905T031108Z` terminal valid sau ít nhất
901,86 giây: **63.464 decision**, 62.788 scored, 154 suppressed, 0 alert, 0
restart, đủ 20/20 workload và coverage tối thiểu 95,449%. Inference
p50/p95/p99 là 16,998/24,971/30,405 ms; window-start-to-decision
p50/p95/p99 là 0,653/0,800/0,854 giây, max 1,079 giây. Aggregate SHA-256 là
`515a1041...`; final checksum index SHA-256 là `09461021...`. Đây là canary
non-formal 0,25 giờ, không tạo FPR/recall claim.

Formal run `sentinel-pulse-formal-normal-b6-r1-20260905T032856Z` đã pass
traffic gate riêng 180/180 east-west, 60/60 north-south và stability preflight
300 giây. `SOAK_START.json` (`b0544839...`) ghi start 03:35:17 UTC; ba worker
vào `normal_active` lúc 03:36:26 UTC với model `2e37ffd1...`, policy
`53f3346f...`, collector/detector active, control collector inactive và
restart=0. Lifecycle được systemd giữ persistent, `STOP_AFTER_NORMAL=true`,
blind evidence B6 vẫn rỗng và automatic promotion bị cấm. Marker 24 giờ là
03:35:17 UTC ngày 06-09; do collector chạy 90.000 giây, kết quả terminal không
thể có trước khoảng 04:36 UTC. Trạng thái active không được suy diễn thành
normal pass.

Lần kích hoạt systemd đầu tiên fail trước ExecStart vì thư mục `STATE_ROOT`
chưa tồn tại, trước mọi marker/capture. Sau khi tạo thư mục, cùng run ID khởi
động hợp lệ. Installer canonical đã được harden để tạo `STATE_ROOT` với owner
service trước redirect log; targeted regression đạt 38/38.
