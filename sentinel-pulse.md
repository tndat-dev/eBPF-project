# Sentinel Pulse: tài liệu kiến trúc và khái niệm đầy đủ

**Ngôn ngữ:** tiếng Việt  
**Phạm vi:** nhánh Sentinel Pulse của đồ án eBPF Runtime Security  
**Code được đối chiếu:** commit `2c7755d`  
**Snapshot cluster gần nhất đã xác minh:** 16-09-2026, 6/6 node Ready,
Kubernetes v1.34.10  
**Trạng thái khoa học:** research candidate; chưa đủ bằng chứng để gọi là
production-stable hoặc tuyên bố không có false positive  

> Tài liệu này giải thích thiết kế và thuật ngữ. Các số liệu lịch sử được ghi
> kèm phạm vi bằng chứng; chúng không tự động trở thành kết quả cuối của paper.
> Lần thử SSH ngày 18-09-2026 bị timeout, vì vậy tài liệu không giả định trạng
> thái live mới hơn snapshot đã xác minh.

## 1. Sentinel Pulse là gì?

Sentinel Pulse là một pipeline phát hiện bất thường runtime cho Kubernetes.
Nó dùng eBPF để đếm syscall theo container, tạo feature theo cửa sổ thời gian
ngắn, chấm điểm bằng ExtraTrees và chỉ phát alert khi anomaly được xác nhận bởi
các tín hiệu bảo mật có thể giải thích.

Mục tiêu chính:

- phát hiện bất thường ở runtime, không chỉ kiểm tra manifest trước deploy;
- giảm thời gian chờ telemetry từ cửa sổ 10 giây của V8 xuống 1 giây hoặc
  candidate 500 ms;
- giữ ML path đủ nhẹ để chạy liên tục trên worker;
- giảm false positive do tải, probe, backup, reconnect và rollout;
- tách dữ liệu normal dùng train khỏi blind attack dùng evaluation;
- cung cấp provenance và checksum đủ mạnh để tái lập kết quả paper;
- tạo nền tảng cho RCA mà không đưa thu thập payload vào hot path.

Sentinel Pulse không thay thế V8 đã đóng băng. V8 và Pulse là hai kiến trúc,
hai bộ model và hai chuỗi evidence khác nhau.

### 1.1 Testbed gần nhất đã xác minh

| IP | Hostname | Vai trò |
|---|---|---|
| 10.1.16.234 | k8s-master.local | control plane |
| 10.1.16.235 | k8s-master2.local | control plane |
| 10.1.16.236 | k8s-master3.local | control plane |
| 10.1.16.237 | k8s-worker1.local | worker |
| 10.1.16.239 | k8s-worker3.local | worker |
| 10.1.16.238 | k8s-worker4.local | worker |

Snapshot gần nhất ghi nhận mỗi node 24 vCPU, khoảng 128 GB RAM và disk 600 GB.
Đây là cấu hình của snapshot tài liệu, không phải kết quả SSH mới ngày
18-09-2026.

## 2. Luồng tổng thể

```text
Pod/container trong namespace production
        │
        ├─ cgroup resolver: Pod UID → container → cgroup ID → revision
        │
        ▼
raw tracepoint sys_enter trong kernel
        │
        ├─ exact syscall counters
        ├─ exact tracked-security counters
        ├─ 64 syscall hash bins
        └─ 64 adjacent-transition hash bins theo task
        │
        ▼ snapshot mỗi 1 s hoặc candidate 500 ms
delta của hai cumulative snapshots
        │
        ▼
feature vector 249 chiều theo workload/container
        │
        ├─ history thật của các window liền kề
        └─ rolling mean/std
        │
        ▼
PulseExtraTrees per-workload + conformal p-value
        │
        ├─ raw model anomaly
        ├─ score excess
        ├─ semantic envelope
        └─ temporal/bounded corroboration tùy policy
        │
        ├─ normal
        ├─ suppressed
        ├─ alert
        ├─ warming
        ├─ collect-only
        └─ rebaseline-required
        │
        ▼
immutable evidence + latency + optional RCA enrichment
```

## 3. Những khái niệm nền tảng

### 3.1 Syscall

System call là giao diện để process yêu cầu kernel thực hiện thao tác như đọc
file, ghi socket, tạo process, đổi UID hoặc mount filesystem. Ví dụ:

- hoạt động phổ biến: `read`, `write`, `close`, `mmap`;
- network: `socket`, `connect`, `accept4`, `sendto`, `recvfrom`;
- process: `clone`, `clone3`, `execve`, `execveat`;
- nhạy cảm: `ptrace`, `setuid`, `capset`, `mount`, `unshare`, `setns`.

Một syscall riêng lẻ thường không đủ kết luận tấn công. Ý nghĩa nằm ở tần suất,
tỷ lệ, thứ tự, process thực hiện, workload và bối cảnh thời gian.

### 3.2 eBPF

eBPF cho phép chạy chương trình được verifier kiểm tra trong kernel. Pulse gắn
vào `raw_tp/sys_enter`, vì vậy nhìn thấy mọi lần vào syscall trước khi dữ liệu
bị sampling ở user space.

eBPF của Pulse chỉ làm công việc bounded:

- tra cgroup hiện tại;
- tăng counter;
- hash syscall/transition vào số bucket cố định;
- giữ syscall trước đó của từng task trong LRU map;
- không chạy model trong kernel;
- không thu payload request.

### 3.3 BPF map và cumulative counter

BPF map là vùng dữ liệu kernel/user space dùng chung. Counter trong map tăng
dần. Loader đọc hai snapshot liên tiếp và tính:

```text
delta = current_counter - previous_counter
```

Nếu counter reset, giá trị hiện tại được xem như baseline mới thay vì tạo delta
âm. Snapshot đầu tiên không sinh feature vì chưa có snapshot trước để trừ.

### 3.4 Cgroup

Cgroup là đơn vị kernel dùng để quản lý tài nguyên và cô lập process. Pulse
dùng cgroup ID để gắn syscall với container cụ thể. Điều này chính xác hơn chỉ
dựa vào tên process, vì nhiều pod có thể cùng chạy `python`, `java` hoặc
`nginx`.

### 3.5 Tetragon

Tetragon cung cấp event chi tiết như process, binary, PID, parent, pod và
`connect`. Trong Pulse:

- exact count dùng eBPF map;
- Tetragon là kênh semantic/provenance thưa;
- rate limit của Tetragon không làm thay đổi exact counters;
- fast-path/rule event phải báo cáo riêng với ML path.

### 3.6 Exact telemetry và sampled telemetry

Exact telemetry đếm tất cả event phù hợp. Sampled telemetry chỉ post một phần
event để giảm overhead.

Không thể dùng sampled count để suy ngược đúng tỷ lệ syscall. Ví dụ `read`
5.000 lần/s và `connect` 3 lần/s cùng bị giới hạn hai event/s sẽ trông gần như
bằng nhau. Do đó Pulse dùng exact BPF counters cho ML, còn sampling chỉ áp dụng
cho log chi tiết tần suất cao.

## 4. Window, cadence, history và rolling statistics

### 4.1 Window là gì?

Window là khoảng giữa hai snapshot. Với cadence 500 ms:

```text
window_t = counters(t) - counters(t - 0,5 s)
```

Với cadence 1 giây, công thức tương tự nhưng độ dài khoảng 1 giây.

Window không phải “một syscall”. Nó là bản tóm tắt mọi syscall của một cgroup
trong khoảng thời gian đó.

### 4.2 Cadence

Cadence là nhịp snapshot mục tiêu. Hai profile đang tồn tại:

- control collector: khoảng 1 giây;
- candidate latency: khoảng 500 ms.

Khoảng đo thực tế không bao giờ chính xác tuyệt đối. Validator của profile
500 ms chấp nhận interval 0,35–0,80 giây; profile 1 giây chấp nhận
0,80–1,50 giây. Khoảng quá lớn tạo temporal gap và buộc warm-up lại.

### 4.3 Model history

Với `history=3`, một prediction dùng:

```text
[window t-3, window t-2, window t-1] + current window t
```

History giúp ExtraTrees nhìn biến đổi theo thời gian dù bản thân cây không phải
RNN/LSTM. Sau restart, gap hoặc đổi traffic regime, model phải thu lại đủ ba
window trước khi score.

### 4.4 Rolling history

Rolling history dùng để tính mean/std của tốc độ syscall gần đây. Đây là một
nhóm feature, khác với ba window được nối vào input model.

Trong profile 500 ms, collector có thể dùng 10 rolling windows, tương đương
khoảng 5 giây bối cảnh thống kê. Model history vẫn là tham số riêng.

### 4.5 Vì sao phải reset history?

History bị reset khi:

- timestamp không tăng: runtime fail-closed;
- khoảng cách vượt `max_contiguous_gap_seconds`;
- traffic regime thay đổi;
- workload revision chưa được approve;
- source identity thay đổi.

Không reset sẽ ghép hai trạng thái không liên tục thành một sequence giả.

## 5. Feature vector 249 chiều

Pulse theo dõi tường minh 29 syscall. Vector gồm:

| Nhóm | Số chiều | Ý nghĩa |
|---|---:|---|
| `log_count` của 29 syscall | 29 | Độ lớn, nén bằng `log1p` |
| `ratio` của 29 syscall | 29 | Tỷ trọng trong tổng syscall |
| Other/total/sensitive/seccomp | 5 | Long-tail, tổng tải, tỷ lệ nhạy cảm, deny |
| Syscall hash bins | 64 | Phân phối của toàn bộ syscall ID |
| Transition hash bins | 64 | Phân phối cặp syscall liền kề |
| Rolling mean của 29 syscall | 29 | Baseline tốc độ gần đây |
| Rolling std của 29 syscall | 29 | Mức biến động gần đây |
| **Tổng** | **249** | |

### 5.1 Vì sao vừa có count vừa có ratio?

- Ratio giúp phân biệt hình dạng workload và giảm nhạy với scale.
- Count/log-total giữ tín hiệu volume; nếu bỏ toàn bộ count, attack dạng burst
  có thể bị che mất.
- Kết hợp cả hai cho phép phân biệt “cùng tỷ lệ nhưng tăng tải” và “đổi hành vi”.

### 5.2 `other` là gì?

`other` là số syscall không thuộc 29 syscall theo dõi tường minh. Nó giữ tổng
khối lượng long-tail, nhưng không phải nguồn thông tin duy nhất vì toàn bộ
syscall vẫn đi vào 64 hash bins.

### 5.3 Sensitive ratio

`sensitive_ratio` là tỷ lệ của nhóm syscall nhạy cảm trên tổng syscall. Nó hữu
ích để nhận biết hành vi privilege/namespace/process bất thường mà không phụ
thuộc hoàn toàn vào traffic volume.

## 6. Syscall hash bins dùng để làm gì?

### 6.1 Mục đích

Kernel có hàng trăm syscall. Tạo một cột cho mọi syscall và mọi cặp syscall sẽ
làm map/vector lớn, phụ thuộc architecture và khó giữ bounded. Hash bins chiếu
không gian lớn vào 64 chiều cố định.

Code hiện tại dùng phép nhân hashing ổn định:

```text
syscall_bin = hash(syscall_id) mod 64
transition_bin = hash(previous_id, current_id) mod 64
```

Sau đó từng histogram được chuẩn hóa theo tổng count của nhóm.

### 6.2 Hash bin giữ được gì?

- hình dạng phân phối long-tail;
- sự xuất hiện của syscall không có cột tường minh;
- thay đổi tương đối giữa các nhóm syscall;
- một phần cấu trúc thứ tự qua transition bins;
- kích thước map và vector cố định.

### 6.3 Hash bin mất gì?

- nhiều syscall/cặp có thể collision vào cùng bucket;
- không thể giải ngược chính xác bucket thành syscall;
- transition bin chỉ cho biết histogram cặp, không giữ toàn bộ chuỗi;
- không giữ process lineage, destination hoặc nội dung network.

Vì vậy syscall nhạy cảm vẫn có exact counter riêng, còn RCA dùng event channel
khác.

## 7. Transition bins và “thứ tự syscall”

Pulse lưu syscall trước đó theo PID/TGID. Khi cùng task gọi syscall tiếp theo
trong giới hạn thời gian, cặp `(previous, current)` được hash vào transition
bin.

Pulse vì vậy thấy thứ tự cục bộ bậc một, ví dụ xu hướng:

```text
openat → read
socket → connect
clone → execve
```

Pulse không giữ raw sequence dài như LSTM. Ưu điểm là chi phí thấp và dữ liệu
tabular; nhược điểm là mất thứ tự dài hạn và có hash collision.

## 8. Workload identity và model per-workload

Khóa model có dạng:

```text
namespace/controller:container
```

Ví dụ:

```text
production/catalog-service:app
production/aims-minio-pool-0:sidecar
production/aims-kafka-entity-operator:topic-operator
```

Tên ReplicaSet hash và StatefulSet ordinal được loại để pod restart vẫn resolve
về controller ổn định. Container được giữ riêng để sidecar không làm nhiễu
process chính.

Không có model phù hợp dẫn tới `collect-only`, không fallback âm thầm sang model
của workload khác.

## 9. Workload revision và rebaseline

Cùng tên controller nhưng image/template mới có thể thay đổi hành vi syscall.
Pulse ghi `workload_revision` từ:

- `rollouts-pod-template-hash`;
- `pod-template-hash`;
- `controller-revision-hash`;
- `strimzi.io/revision`;
- hash của `cnpg.io/podSpec` cho CNPG.

Nếu revision live không nằm trong model manifest, runtime trả:

```text
status = rebaseline-required
```

Nó không gọi revision mới là attack và cũng không gọi là normal. Đây là guard
quan trọng sau khi formal R8 quan sát false alert ngay sau AIMS rollout.

## 10. PulseExtraTrees là mô hình gì?

`PulseExtraTrees` bọc `ExtraTreesClassifier` của scikit-learn:

- 192 cây;
- `max_depth=16`;
- `min_samples_leaf=4`;
- `max_features="sqrt"`;
- class weight balanced;
- random seed cố định `73021`;
- `n_jobs=-1` khi train và `n_jobs=1` khi inference online.

### 10.1 ExtraTrees khác Random Forest

Cả hai là ensemble cây. Random Forest chọn bootstrap sample và tối ưu split
trong feature subset. ExtraTrees ngẫu nhiên hóa threshold split mạnh hơn.

Trong bài toán tabular syscall hiện tại, ExtraTrees có lợi thế:

- inference nhanh;
- học quan hệ phi tuyến và tương tác feature;
- ít preprocessing;
- phù hợp dữ liệu nhỏ hơn deep learning;
- dễ benchmark và chạy CPU;
- không phải chờ sequence dài như LSTM.

ExtraTrees không mặc nhiên tốt hơn RF. Paper vẫn phải chạy RF, Decision Tree,
Isolation Forest và các baseline khác trên cùng split để chứng minh lựa chọn.

## 11. Self-supervised learning và synthetic corruption

Training chỉ nhận normal windows. Từ current row bình thường, code tạo negative
giả bằng hai phép biến đổi deterministic theo seed:

- khoảng 15% phần tử được thay bằng giá trị từ donor row khác;
- khoảng 8% phần tử được nhân hệ số log-uniform trong `[0,25; 4,0]`.

Classifier học phân biệt:

```text
class 0 = history + current normal thật
class 1 = history + current bị corrupt
```

Điểm class 1 được dùng làm anomaly score.

Đây là self-supervised anomaly ranking, không phải classifier được train bằng
nhãn attack. Synthetic corruption cũng không đại diện đầy đủ mọi tấn công; nó
chỉ tạo learning signal từ normal data.

## 12. Temporal split và tránh leakage

Mỗi contiguous sequence được chia theo thời gian, mặc định 70% fit và 30%
calibration. Sequence bị cắt tại gap hoặc regime boundary.

Không được random-shuffle mọi window trước split, vì các window gần nhau có
tương quan lớn và sẽ gây leakage.

Các mức đánh giá mạnh hơn cần thêm:

- capture-day holdout;
- pod-version/revision holdout;
- unseen workload;
- cross-node/cross-cluster;
- peak-hour holdout không tham gia fit/calibration.

## 13. Conformal calibration

Model tạo raw score `s`. Calibration split gồm các normal score đã sắp xếp.
Conformal p-value được tính:

```text
p = (số calibration_score ≥ s + 1) / (n_calibration + 1)
```

Raw anomaly xảy ra khi:

```text
p ≤ alpha
```

### 13.1 p-value không phải xác suất attack

`p=0,001` không có nghĩa “99,9% là attack”. Nó cho biết score hiện tại cực
đoan thế nào so với normal calibration distribution dưới các giả định trao đổi
được của conformal prediction.

### 13.2 Độ phân giải calibration

p-value nhỏ nhất là:

```text
1 / (n_calibration + 1)
```

Do đó:

- `alpha=10^-3` cần ít nhất 999 calibration examples;
- `alpha=10^-4` cần ít nhất 9.999 calibration examples.

Trainer fail-closed nếu không đủ sample; không được hạ alpha hoặc đổi split sau
khi xem attack outcome.

## 14. Từ anomaly score đến alert

Một raw model anomaly chưa đủ tạo alert. Tùy policy, runtime kiểm tra nhiều
cổng.

### 14.1 Score corroboration

Score phải vượt `calibration_max` một margin tối thiểu. Mục đích là loại các
điểm chỉ vừa chạm đuôi calibration.

### 14.2 Semantic corroboration

Exact count của các nhóm bảo mật được so với normal envelope riêng cho từng
workload. Các nhóm lịch sử gồm:

- `local_socket_beacon`: `socket + connect`;
- `process_fanout`: `clone + clone3`;
- `identity_transition`: `setuid + setgid + capset`;
- `credential_open`: `openat`;
- `namespace_probe`: `ptrace`, `pivot_root`, `mount`, `unshare`, `setns`,
  `execveat`.

Envelope là mức tối đa quan sát trong normal development evidence cộng minimum
excess đã khóa. Nó không phải luật MITRE cố định cho mọi workload.

### 14.3 Same-window corroboration

ML anomaly, score excess và semantic signal phải cùng xuất hiện trong window
nếu policy dùng same-window mode. Cách này giữ latency thấp nhưng có thể bỏ lỡ
tấn công trải tín hiệu qua hai window.

### 14.4 Bounded event-time join

Policy V3 có thể nối ML evidence và semantic evidence trong một khoảng tối đa,
ví dụ 1 giây. Evidence quá tuổi không được dùng; evidence đã alert được consume
để tránh lặp.

### 14.5 Temporal confirmation

Một số nhóm noisy phải lặp trong 2–3 window liên tiếp cùng nhóm mới alert.
Nhóm `namespace_probe` có thể bypass để giảm latency cho hành vi hiếm và nhạy
cảm. Confirmation giảm false positive nhưng tăng latency và có thể giảm recall
cho attack rất ngắn.

### 14.6 Logic khái quát

```text
raw_anomaly
AND score_corroborated
AND semantic_corroborated
AND temporal_policy_satisfied
→ alert
```

## 15. Các trạng thái runtime

| Trạng thái | Ý nghĩa |
|---|---|
| `warming` | Chưa đủ history sau start/reset |
| `collect-only` | Chưa có model cho workload key |
| `rebaseline-required` | Revision live chưa được model approve |
| `normal` | Đã score và không đạt điều kiện anomaly/alert |
| `suppressed` | Có model anomaly nhưng thiếu corroboration |
| `alert` | Qua toàn bộ decision policy |

`suppressed` không đồng nghĩa normal tuyệt đối. Nó là candidate anomaly bị
policy chặn. Số suppressed cần được báo cáo để audit threshold và recall.

## 16. High load và nguy cơ false positive

Nếu training chỉ có low/medium load, model có thể học:

```text
low/medium ≈ normal
high load ≈ abnormal
```

Ratio và hash-bin giảm nhạy với scale nhưng không loại bỏ rủi ro vì vector vẫn
có `log_count`, `log_total`, rolling mean/std, process/network activity.

### 16.1 Năm normal traffic regime

| Regime | Base/Readmix/Dependency | East-west sleep | Ingress interval | Mục đích |
|---|---:|---:|---:|---|
| steady | 1/0/1 | 1 s | 0,22 s | tải ổn định |
| toolmix | 2/4/2 | 1 s | 0,22 s | đa dạng endpoint/read path |
| peak | 4/2/3 | 0,25 s | 0,08 s | mô phỏng giờ cao điểm 20:00 |
| burst | 6/2/3 | 0 s | 0,04 s | stress hợp lệ, mạnh hơn peak |
| recovery | 1/0/1 | 2 s | 0,44 s | hạ tải và hồi phục |

`peak` là nhãn bối cảnh mô phỏng, không khẳng định campaign thực sự bắt đầu lúc
20:00 theo đồng hồ.

### 16.2 Coverage fail-closed

Dataset manifest ghi:

- `required_regimes`;
- `rows_by_regime`;
- `rows_by_workload_regime`.

Trainer từ chối candidate nếu bất kỳ workload/container nào thiếu một regime,
đặc biệt là peak.

### 16.3 Train peak không đủ để chứng minh FPR peak

Nếu peak rows được dùng fit/calibration, chúng không thể đồng thời là independent
peak holdout. Cần campaign peak khác, preregistered và không tham gia tuning,
hoặc live peak soak sau khi model đã đóng băng.

## 17. False positive, false negative và model stability

### 17.1 False positive

Normal activity bị phát alert. Nguồn thường gặp:

- peak traffic chưa có trong baseline;
- readiness/liveness probe storm;
- backup/compaction;
- Kafka/Redis reconnect;
- rollout/image revision mới;
- sidecar lifecycle;
- sparse workload thiếu calibration;
- telemetry gap ghép sequence sai;
- semantic threshold dùng chung cho workload khác nhau.

### 17.2 False negative

Attack không phát alert. Nguyên nhân có thể là:

- attack không làm thay đổi feature đủ lớn;
- hash collision;
- attack quá ngắn so với window;
- corroboration quá chặt;
- temporal confirmation yêu cầu nhiều window;
- attack dùng syscall bình thường nhưng tham số độc hại;
- aggregation theo cgroup che process cụ thể.

### 17.3 Không thể bảo đảm 100%

Không có anomaly detector thực tế nào chứng minh “100% chạy tốt” chỉ bằng test
nội bộ. Claim hợp lệ phải gắn dataset, split, confidence interval, workload,
attack set và thời gian soak cụ thể.

## 18. Latency được đo như thế nào?

### 18.1 Các timestamp

- `kernel_event_at`: Tetragon/eBPF quan sát event gốc của injection;
- `window_start`, `window_end`: biên feature window;
- `feature_emitted_at`: collector ghi feature;
- `decision_at`: model hoàn thành quyết định;
- `alerted_at`: alert được ghi;
- `attack_injected_at`: orchestrator bắt đầu scenario.

### 18.2 Các metric khác nhau

```text
telemetry latency       = window_end - window_start
ingest lag              = feature_emitted_at - window_end
inference latency       = model_predict_end - model_predict_start
decision latency        = decision_at - window_start
true kernel-to-alert    = alerted_at - kernel_event_at
injection-to-alert      = alerted_at - attack_injected_at
```

Không được gọi `window_start → decision` là true kernel-to-alert nếu thiếu
kernel event timestamp.

### 18.3 Ngân sách mục tiêu

Với profile 500 ms, mục tiêu thiết kế:

| Thành phần | Ngân sách p99 tham chiếu |
|---|---:|
| Chờ window | 0,500 s |
| Snapshot/resolve/feature | 0,300 s |
| ExtraTrees + calibration | 0,050 s |
| Queue/output/corroboration | 0,350 s |
| **Kernel-to-alert mục tiêu** | **≤ 2,000 s** |

Đây là budget, không phải kết quả tự động.

### 18.4 Bằng chứng lịch sử hiện có

- Prospective normal canary R6-r2: p99 `window-start → decision` 0,858 giây,
  517.459 decision và 0 alert; đây là normal engineering evidence.
- A2 normal canary: p99 khoảng 0,841 giây.
- Pilot attack-latency A2: 10 alert/15 trial, 5 miss; với chín alert R6,
  p50 0,718 giây nhưng p99 5,332 giây.

Do đó code đã chứng minh normal decision path có thể dưới 1 giây ở p99 trong
một số canary. Nó chưa chứng minh blind attack kernel-to-alert p99 ≤2 giây và
chưa đủ recall.

## 19. Fast path và ML path

Fast path là rule/event hiếm từ Tetragon hoặc policy bảo mật. Nó có thể cảnh
báo sớm gần như tức thời. ML path đánh giá pattern thống kê và generalization.

Paper phải báo cáo tách:

- fast-path early warning latency/precision;
- ML confirmation latency/precision/recall;
- combined policy;
- ablation bỏ fast path.

Không được lấy timestamp fast path để quảng cáo latency ML.

## 20. Dataset lifecycle

### 20.1 Capture contract

Contract được tạo trước campaign, khóa:

- campaign ID;
- node dự kiến;
- Unix timestamp bắt đầu/kết thúc từng regime;
- transition gap;
- `normal_only=true`.

Chỉ row nằm hoàn toàn trong measured interval mới được assembler nhận.

### 20.2 Node manifest

Mỗi worker finalizer kiểm tra:

- capture tồn tại và read-only;
- node identity đúng;
- capture phủ toàn campaign;
- mọi regime có row;
- hard integrity counters bằng 0;
- SHA-256 khớp final report.

### 20.3 Dataset manifest

Assembler yêu cầu đúng tập worker và source manifest. Output ghi:

- dataset hash;
- contract hash;
- source capture/hash;
- rows theo node/regime/workload;
- feature schema hash;
- campaign provenance.

### 20.4 Training Contract V3

Trước fit phải đóng băng:

- dataset SHA-256;
- blind contract SHA-256;
- history, alpha, window size;
- source commit/diff hash;
- approved workload revisions;
- completed observer fingerprint;
- `automatic_promotion=false`.

Observer chưa `COMPLETE`, checksum sai hoặc revision map lệch đều bị từ chối.

## 21. Model artifact integrity

Model manifest khóa:

- SHA-256 và byte size từng pickle;
- feature columns/schema hash;
- dataset/contract/training-contract hash;
- history, alpha, window, temporal gap;
- software versions;
- approved workload revisions;
- workload/regime coverage;
- source Git provenance.

Runtime xác minh detached `manifest.sha256` trước khi unpickle và kiểm metadata
sau load. Điều này không làm pickle an toàn với nguồn không tin cậy; nó chỉ
bảo đảm artifact đúng bundle đã approve.

## 22. Normal soak, canary và blind attack

### 22.1 Canary

Canary là run ngắn để phát hiện lỗi triển khai, coverage, restart và false alert
rõ ràng. Canary pass không chứng minh FPR dài hạn.

### 22.2 Formal normal soak

Normal soak độc lập thường yêu cầu:

- model/policy đã freeze;
- 24 giờ hoặc dài hơn;
- mọi workload đủ unique second-bucket coverage;
- zero alert nếu contract đăng ký zero-alert gate;
- zero detector restart;
- telemetry availability đạt ngưỡng;
- evidence hash-valid.

Một normal alert làm candidate fail. Không được xóa alert rồi chạy tiếp cho đến
khi đẹp.

### 22.3 Blind attack set

Attack set được khóa checksum trước training và không dùng tune. Pulse lịch sử
đăng ký 18 workload × 5 scenario × 5 seed/rate = 450 injection. Đây khác ma
trận 200 trial của V8.

Năm scenario nghiên cứu gồm:

- local socket beacon;
- namespace probe;
- process fanout;
- identity transition probe;
- credential read/open burst.

Các scenario là primitive an toàn, có thể ánh xạ MITRE ATT&CK ở phần phân tích,
nhưng không nên gọi mỗi trial là một kỹ thuật MITRE độc lập.

### 22.4 Infrastructure rejection và model rejection

| Kết quả | Ý nghĩa |
|---|---|
| Infrastructure rejection | Pod/node/telemetry/checksum/coverage hỏng; không kết luận model |
| Model rejection | Evidence hợp lệ nhưng normal alert hoặc miss vượt gate |
| Pass | Mọi gate preregistered đạt; không đồng nghĩa hoàn hảo ngoài phạm vi |

## 23. Các metric paper

Với TP, FP, TN, FN:

```text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
FPR       = FP / (FP + TN)
F1        = 2 × precision × recall / (precision + recall)
```

Với continuous normal stream, cần báo thêm:

- false alerts/hour hoặc false alerts/workload-day;
- Wilson/bootstrap confidence interval;
- latency CDF và p50/p95/p99/max;
- detection theo scenario/workload/rate/seed;
- suppressed rate và warming coverage;
- telemetry availability và max gap;
- CPU/RAM/throughput/p50/p95/p99 overhead.

Không nên chỉ báo accuracy vì normal windows áp đảo attack windows.

## 24. Baseline và ablation cần thiết

Baseline hợp lý:

- Tetragon/Falco rule-only;
- Decision Tree;
- Random Forest;
- ExtraTrees không temporal history;
- Isolation Forest;
- LSTM-only V8;
- semantic-only;
- EVT/POT nếu đủ dữ liệu.

Ablation:

- bỏ syscall hash bins;
- bỏ transition bins;
- bỏ count, chỉ giữ ratio;
- bỏ rolling mean/std;
- bỏ per-workload model;
- bỏ score corroboration;
- bỏ semantic envelope;
- bỏ temporal confirmation;
- bỏ revision guard;
- 1 s so với 500 ms;
- có và không fast path.

## 25. AIMS production simulation

AIMS cung cấp traffic thực tế hơn nginx/redis đơn lẻ:

- frontend và microservices;
- PostgreSQL CNPG;
- Kafka + entity operators;
- RabbitMQ;
- Redis + Sentinel;
- MinIO;
- Istio waypoint/ingress;
- các load generator north-south, east-west, readmix và dependency.

Mục tiêu của AIMS không chỉ tạo nhiều syscall mà tạo nhiều role khác nhau:
HTTP stateless, JVM/operator, database, broker, object storage và service mesh.

Loadgen phải được loại khỏi model workload fingerprint để actor sinh tải không
trở thành đối tượng được train như ứng dụng production.

## 26. RCA: từ alert đến cây nguyên nhân

### 26.1 Pulse hiện biết gì?

Hot path biết:

- workload/container/cgroup;
- thời điểm window;
- anomaly score và p-value;
- exact syscall counts;
- semantic group kích hoạt.

Nó chưa giữ raw process tree hoặc destination trong 249 feature.

### 26.2 Connect enrichment

Policy RCA khai báo ba argument của `connect(2)`:

- socket file descriptor;
- destination `sockaddr`;
- address length.

Tetragon event còn có:

- `exec_id`, `parent_exec_id`;
- PID/UID;
- binary;
- pod/container/node;
- timestamp.

`rca_connect.py` chuẩn hóa thành edge và resolve IP qua Pod, Service hoặc
EndpointSlice.

### 26.3 Cây/graph RCA đề xuất

```text
Alert
└─ workload/container
   └─ process (exec_id, binary, pid)
      ├─ parent process
      ├─ connect → destination IP:port
      │            └─ Pod/Service/Endpoint
      ├─ exec → child process
      └─ sensitive syscall group
```

Trong hệ phân tán, graph phù hợp hơn cây thuần vì một process có thể kết nối
nhiều service và một service có nhiều endpoint.

### 26.4 “Nội dung connect” có lấy được không?

`connect()` chỉ thiết lập socket; nó không chứa HTTP body hoặc TLS plaintext.

Nguồn L7 phù hợp:

- Istio/Envoy access log;
- OpenTelemetry trace;
- protocol-aware proxy metadata;
- method, route template, status, duration, peer identity đã redact.

Không nên thu raw request body, token, cookie, password hoặc TLS plaintext mặc
định. Nếu traffic mã hóa, syscall-level eBPF không tự nhìn thấy nội dung.

### 26.5 Vì sao RCA phải tách hot path?

- tránh tăng kernel-to-alert;
- tránh lưu lượng event quá lớn;
- giảm privacy risk;
- chỉ enrich quanh alert trong bounded time range;
- detector vẫn hoạt động nếu L7 source unavailable.

Code parser và policy args đã được implement/test; integration RCA terminal
trên production chưa có đủ evidence để claim hoàn thành.

## 27. Overhead

Overhead phải so sánh counterbalanced A/B:

- collector off/on;
- pipeline collector-only so với collector+detector;
- nhiều lần lặp và đổi thứ tự treatment;
- cùng traffic, workload revision và cluster health.

Metric:

- CPU-second và core trung bình;
- RSS/peak memory;
- snapshot read/emit lag;
- request throughput;
- HTTP latency p50/p95/p99;
- error/timeout;
- Tetragon queue loss;
- BPF map pressure.

Không dùng một lần `kubectl top` để kết luận overhead paper.

## 28. Privacy và security boundaries

Pulse mặc định không cần:

- nội dung file;
- request/response body;
- secret value;
- raw TLS plaintext;
- toàn bộ argv của workload bình thường.

Evidence cần:

- bounded retention;
- read-only/checksum sau finalization;
- RBAC tối thiểu;
- tách attack actor khỏi workload dataset;
- redact identity nhạy cảm khi publish paper;
- không tự động isolate pod từ research candidate.

ML runtime security không thay thế Kubernetes RBAC, admission policy, seccomp,
network policy, image signing hoặc secret management. Các lớp này bổ sung cho
nhau.

## 29. Luồng code quan trọng

| File | Vai trò |
|---|---|
| `sentinel_pulse/ebpf/pulse_counter.bpf.c` | Exact counters và hash bins trong kernel |
| `sentinel_pulse/ebpf/pulse_counter_loader.c` | Snapshot BPF map |
| `sentinel_pulse/cgroup_resolver.py` | Resolve pod/container/cgroup/revision |
| `sentinel_pulse/capture.py` | Đọc snapshot và xuất feature record |
| `sentinel_pulse/features.py` | Xây vector 249 chiều |
| `sentinel_pulse/prepare_contract.py` | Khóa lịch traffic regime |
| `sentinel_pulse/assemble_dataset.py` | Assemble dataset đa node |
| `sentinel_pulse/validate_capture.py` | Kiểm integrity/cadence/lag |
| `sentinel_pulse/model.py` | PulseExtraTrees + conformal score |
| `sentinel_pulse/train.py` | Train per-workload và tạo manifest |
| `sentinel_pulse/decision_policy.py` | Semantic/score/temporal contract |
| `sentinel_pulse/detect.py` | Runtime scoring và alert decision |
| `sentinel_pulse/evaluate_normal.py` | Normal-soak/FPR evidence |
| `sentinel_pulse/evaluate_latency.py` | Kernel-to-alert evaluation |
| `sentinel_pulse/tetragon_evidence.py` | Kernel event provenance cho injection |
| `sentinel_pulse/workload_fingerprint.py` | Revision-stability fingerprint |
| `sentinel_pulse/freeze_training_contract.py` | Training contract V3 |
| `sentinel_pulse/finalize_candidate.py` | Terminal release gates |
| `sentinel_pulse/rca_connect.py` | Process/connect/destination RCA edge |

## 30. Runtime service trên worker

Các unit chính:

- `sentinel-pulse-resolver.service`;
- `sentinel-pulse-collector.service` — control collector;
- `sentinel-pulse-collector-500ms-experiment.service` — candidate experiment;
- `sentinel-pulse-detector-candidate.service` — audit-only detector;
- rotate timer và freeze/finalizer unit.

Nguyên tắc:

- resolver và control collector có thể chạy liên tục;
- experiment/detector chỉ bật theo contract;
- canary-first trước khi rollout ba worker;
- research candidate không tự enable response;
- cleanup phải trả traffic về steady.

## 31. Chạy từ đầu ở mức khái niệm

```text
1. Kiểm cluster/AIMS/traffic/storage health
2. Build eBPF theo BTF của từng worker
3. Deploy resolver + collect-only control collector
4. Quan sát workload revision đủ dài
5. Đóng băng capture contract normal-only
6. Thu steady/toolmix/peak/burst/recovery trên mọi worker
7. Finalize read-only và validate integrity
8. Assemble dataset đa node
9. Đóng băng Training Contract V3
10. Train PulseExtraTrees per workload/container
11. Build semantic/temporal policy chỉ từ normal development evidence
12. Benchmark inference và A/B overhead
13. Audit-only canary
14. Independent 24h normal soak
15. Chỉ khi normal gate pass mới mở blind attack matrix
16. Finalize precision/recall/latency CDF/CI
17. Không auto-promote; review evidence trước rollout
```

Lệnh chi tiết nằm trong `sentinel_pulse/README.md`; không nên chạy từng script
rời rạc mà bỏ contract/finalizer.

## 32. Trạng thái hiện tại và giới hạn claim

### 32.1 Đã triển khai trong code

- exact eBPF counters theo cgroup;
- 249-dimensional feature schema;
- profile 1 giây và candidate 500 ms;
- ExtraTrees self-supervised per workload/container;
- conformal calibration;
- semantic, score và temporal corroboration;
- gap/regime/revision reset;
- immutable dataset/model/policy provenance;
- canary, normal soak, blind matrix và overhead harness;
- peak-hour normal regime và workload-regime coverage;
- connect RCA parser/policy schema.

### 32.2 Bằng chứng tích cực

- nhiều canary normal có 0 alert;
- normal decision p99 từng đạt khoảng 0,84–0,86 giây;
- inference p99 lịch sử khoảng 29–40 ms;
- telemetry/provenance/fail-closed guards đã bắt được nhiều lỗi thật;
- regression gần nhất trước tài liệu đạt 579 test pass, 2 Torch deprecation
  warning.

### 32.3 Bằng chứng thất bại phải giữ nguyên

- nhiều formal normal candidate B3–B6 bị loại do normal alert;
- B7 formal run bị infrastructure rejection;
- R8 formal availability chạy khoảng 21,2 giờ rồi fail với ba normal alert sau
  AIMS rollout;
- attack pilot A2 có 5 miss/15 trial và latency tail trên 2 giây.

### 32.4 Chưa được phép tuyên bố

- zero false positive trong production;
- blind recall/precision đạt chuẩn cuối;
- kernel-to-alert p99 ≤2 giây trên toàn attack matrix;
- world-class paper đã hoàn tất;
- RCA end-to-end đã production-ready;
- Sentinel Pulse đã tự động response/isolate workload.

## 33. Điều kiện để đạt paper mạnh

1. Đóng băng candidate, không chỉnh theo test set.
2. Hoàn tất revision-stable normal dataset có đủ năm traffic regime.
3. Dùng capture peak độc lập làm holdout.
4. Normal soak 24 giờ–7 ngày không alert, coverage đầy đủ.
5. Blind attack matrix mới, nhiều seed/rate, không dùng tune.
6. Temporal/pod-version/unseen-workload/cross-cluster split.
7. Baseline RF/DT/IF/LSTM/rule-only và thống kê paired.
8. Ablation đầy đủ feature và corroboration.
9. Repeated A/B overhead với confidence interval.
10. Latency CDF từ kernel event thật, không thay bằng window timestamp.
11. Công bố cả miss, false alert, infrastructure rejection và negative result.
12. Nếu claim RCA, đánh giá attribution accuracy và thời gian dựng graph.

## 34. Thuật ngữ nhanh

| Thuật ngữ | Diễn giải |
|---|---|
| Window | Delta giữa hai snapshot BPF |
| Cadence | Chu kỳ snapshot mục tiêu |
| Feature | Đại lượng số đưa vào model |
| Hash bin | Bucket nén nhiều syscall/cặp vào số chiều cố định |
| Transition | Cặp syscall liền kề của cùng task |
| Rolling mean/std | Thống kê tốc độ trên các window gần đây |
| History | Các vector quá khứ ghép với current row |
| Raw score | Đầu ra `predict_proba` class corruption, dùng làm điểm ranking; chưa phải xác suất attack đã calibration |
| Conformal p-value | Độ cực đoan so với normal calibration scores |
| Alpha | Ngưỡng conformal anomaly |
| Semantic envelope | Ngưỡng normal theo workload và nhóm syscall |
| Corroboration | Tín hiệu xác nhận bổ sung cho model anomaly |
| Suppressed | Anomaly chưa đủ điều kiện alert |
| Warming | Chưa đủ temporal history |
| Collect-only | Thu feature nhưng không có model |
| Rebaseline-required | Workload revision chưa được model approve |
| Normal soak | Chạy normal độc lập sau khi model/policy freeze |
| Blind set | Attack set không dùng train/tune |
| Provenance | Chuỗi nguồn gốc dataset/code/model/policy |
| RCA | Root Cause Analysis, truy nguyên process và dependency |
| FPR | Tỷ lệ normal bị báo sai |
| Recall | Tỷ lệ attack được phát hiện |
| p99 | 99% quan sát nhỏ hơn hoặc bằng giá trị này |

## 35. Kết luận

Sentinel Pulse không đơn thuần là “ExtraTrees đọc syscall”. Giá trị của kiến
trúc nằm ở chuỗi hoàn chỉnh:

```text
exact telemetry
+ bounded temporal representation
+ workload/revision conditioning
+ self-supervised ExtraTrees
+ conformal calibration
+ explainable corroboration
+ immutable evaluation protocol
+ optional post-alert RCA
```

Thiết kế có khả năng đạt decision latency thấp hơn V8 và phù hợp dữ liệu tabular
ít hơn deep learning. Điểm khó còn lại không phải làm model chạy được, mà là
chứng minh đồng thời ba yếu tố trên dữ liệu độc lập: false-positive thấp, recall
đủ cao và kernel-to-alert tail nằm trong ngân sách 1–2 giây.
