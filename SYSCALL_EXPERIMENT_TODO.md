# TODO thực nghiệm chọn syscall và đánh giá candidate

Cập nhật hiện hành qua SSH: **13/10/2026 01:53 UTC (08:53 UTC+7)**. Sentinel
Pulse normal soak `normal-a1-20261013` vẫn chạy trên worker1/3/4: khoảng
25.6 ks/86.4 ks exposure mỗi node (~29.7%), không error/pause/restart; chi tiết
ở [CANDIDATE_SHADOW_STATUS.md](CANDIDATE_SHADOW_STATUS.md). Shadow lag mẫu tối đa
~74 phút; chưa phải realtime.

Hai offline syscall-feature campaigns đã kết thúc: C1 attempt-000002 và C2
attempt-000002 đều terminal `completed`, 608/608 fits, errors rỗng, 19 workload
× 32 variants. C2 service là `active (exited)` kiểu oneshot, không còn fit process.
C2 attempt-000001 lỗi `NameError: os`; artifact gốc được giữ. C2 manifest hiện
có path dư `models/` (`models/models/<file>.pkl`) trong khi file thực tế ở
`attempt-000002/models/<file>.pkl`. SHA/size đã xác minh cho đủ 608 model file
(2,362,081,485 byte) theo `RESULTS.json` và metadata hash; không ghi đè manifest
đã seal. Generator đã sửa trong working tree, 36 test liên quan pass. C1/C2 đều
exploratory normal-only; precision, recall và kernel-to-alert để null, không tự
promotion.

Hai exact-ID histogram pilot worker1/worker3 đã có terminal exit 0 và analyzer
hợp lệ; chỉ là captures steady ngắn, chưa đại diện các regime khác. Checklist
này không thay cho artifact kết quả và không tuyên bố syscall tối ưu.

## Đã làm trong lượt hiện tại

- [x] Thêm runner bounded `sentinel_pulse/syscall_histogram_pilot.py`: ghi START
  trước attach, hash object/loader/allow-list, node/kernel/ABI, baseline/probe/post,
  host và cgroup metrics, resolver metadata snapshot, terminal và SHA256SUMS.
- [x] Thêm receipt traffic preregistered có schema, node, ID, lịch regime và
  timestamp; receipt được copy/hash-bind vào run. Không có receipt thì capture
  mang nhãn `unlabelled`, không được xếp hạng feature.
- [x] Thêm analyzer `sentinel_pulse/syscall_histogram_analysis.py`: kiểm tra
  seal, integrity/drop/map capacity, target coverage, identity/revision, độ mới
  metadata, receipt và việc interval nằm trọn trong đúng một regime.
- [x] Thêm cohort aggregator `sentinel_pulse/syscall_histogram_cohort.py`: gộp
  captures hợp lệ theo workload × revision × regime, loại run trùng/chồng lấn,
  và không tự xếp hạng feature.
- [x] Thêm 10 regression tests cho receipt, capture hợp lệ/unlabelled, ranh giới
  regime, artifact bị sửa, target coverage, runner sealing và cohort overlap.
- [x] Audit cluster trực tiếp: 6/6 node Ready; production 66 Running/Ready,
  31 pod terminal Evicted, 4 Job pod Succeeded. Deployment/StatefulSet/DaemonSet
  đều đủ replica; CNPG 3/3 và Kafka `Ready=True`. Đã lưu root cause DiskPressure
  vào [CLUSTER_READINESS.md](CLUSTER_READINESS.md), dọn 31 pod Failed production
  và 53 pod Failed Velero sau khi ghi nhận sự cố; không đụng PVC/data/log.
- [x] Hậu kiểm: không có Running pod chưa Ready; node pressure đều False;
  10/10 microservice health endpoint trả 200, MinIO health 200, Redis AUTH/PING
  OK, PostgreSQL/Kafka/RabbitMQ ports mở. Loadgen 401/400 là traffic error-mix,
  không phải pod readiness; chi tiết trong readiness report.
- [x] Regression pilot: **10 passed**, py_compile và `git diff --check` pass.
- [x] Cập nhật trạng thái C2 qua SSH: attempt-000002 terminal `completed`,
  `608/608`, errors rỗng; attempt-000001 lỗi được bảo toàn.
- [x] Pre-register receipt cho run `syscall-id-histogram-worker3-steady-
  20261012-001`, SHA-256 `f2a443df2b65ab7612f0d28c97c5e9b06f0a00583644cbd151f9202142e56c14`;
  receipt bind ba loadgen Deployment đang Ready cùng UID/config.
- [x] Đồng bộ commit `3cd8d1d` sang clone riêng trên worker3 và build loader/object
  theo kernel hiện tại. Hash loader `e744b99bc01c9633a4a8b44738f337c6b6545b8d5feabd0de4e7d55d203ba23d`,
  object `b8c13be88076036b5eff367a7c563bce17c7e932f1623224b75a32010ed922ee`.
- [x] Chạy systemd bounded capture worker3: baseline 300 s → probe 120 s /
  snapshot 1 s → post 300 s. Run completed với exit 0, 119 chu kỳ, 7 workload
  container có syscall, 519.421 syscall entries; analyzer không ghi lỗi integrity,
  drop, map pressure, identity gap hay lệch traffic receipt. Seal được kiểm tra
  và bản sao trên NFS `.233` đã xác minh checksum.
- [x] Capture lặp độc lập trên worker1 với receipt riêng, preregister trước khi
  chạy: `syscall-id-histogram-worker1-steady-20261012-001`, SHA-256
  `efe8d52a5a48d311afe9fcbe6d8e624de009ff8f919466ec57c9b74f0827df1c`.
  Run completed exit 0, 117 chu kỳ, 82 cgroup targets, 28 workload/container có
  count, 2.830.672 syscall entries; không drop/identity gap/integrity problem.
  Analyzer và cohort hợp lệ cho cả worker1 + worker3; 2/2 capture được nhận,
  không overlap hay bị loại. Raw, ANALYSIS, COHORT và checksum được lưu/kiểm
  tra trên NFS `.233`. Đây vẫn chỉ là hai capture steady ngắn; cohort cấm tự rank.

## Checklist để có bằng chứng chọn syscall

### A. Hoàn tất và đóng băng normal-only ablation

- [x] C2 hoàn tất `608/608`; terminal `completed`, `errors=[]`, manifest khai
  báo 19 workload và 608 variant records. Job là offline, không gắn serving.
- [x] Xác minh đủ 608 model file với SHA-256/size; phát hiện cả 608 manifest path
  đều lặp `models/models/`.
- [ ] Tạo manifest dẫn xuất đã sửa path, bind SHA manifest gốc/START/RESULTS và
  kiểm tra consumer; không sửa/ghi đè manifest gốc.
- [ ] Đối chiếu C2 với C1 theo input/source/training split hashes; không gộp
  timing tích lũy hoặc kết quả từ host khác vào wall time của VM.
- [ ] Khóa một candidate/model manifest và policy; không dùng blind set để tune.

### B. Thu full-ID syscall normal độc lập

- [ ] Phục hồi/ổn định workload và traffic generator; xác định target pod UID,
  container, revision, cgroup và node từ resolver/API tại thời điểm capture.
- [ ] Đăng ký trước traffic receipt với regime và khoảng thời gian chính xác.
  Bốn chế độ dự kiến phải được định nghĩa bởi lịch traffic có receipt (ví dụ
  steady, peak, burst, recovery); tên ví dụ không tự động được coi là chế độ đã
  chạy.
- [ ] Dùng runner trước trên một node, một run bounded; kiểm tra baseline và
  post metrics, drop counter, map occupancy, metadata coverage, scan skew, CPU,
  memory, throughput và p95/p99 nếu có nguồn đo đã đăng ký.
- [ ] Nếu không có receipt hoặc interval không nằm trọn trong một regime, giữ
  raw output là engineering/unlabelled; không tính vào syscall ranking.
- [ ] Thu đủ workload/revision/replica và regime; báo thiếu coverage, syscall
  hiếm/không thấy, ABI và syscall entry bị giới hạn quan sát. Không suy diễn
  thành syscall thành công.
- [ ] Seal raw capture, analyzer output, traffic receipt và environment metadata;
  kiểm tra bản sao lưu, SHA-256 và khả năng tái lập.

### C. Phân tích tần suất và ablation

- [ ] Thống kê exact syscall-ID count, share và rate/container-second theo
  workload × revision × regime; báo phân phối giữa workload, không chỉ gộp tổng.
- [ ] Định nghĩa trước cách xử lý syscall hiếm, `other`, hash bin và syscall
  ngoài ABI; không chọn top-K theo blind/test/attack.
- [ ] Dùng normal development set để đề xuất biến thể; retrain/calibrate mỗi
  biến thể trên cùng temporal split. So sánh paired với full model và semantic
  policy giữ nguyên.
- [ ] Báo feature importance theo nhiều phương pháp và giới hạn tương quan;
  permutation/importance không được gọi là quan hệ nhân quả.
- [ ] Tạo normal test mới độc lập chưa xem để đo FP/TN; alert trong soak giữ lại
  và adjudicate, không loại ra khỏi mẫu sau khi xem kết quả.

### D. Blind security evaluation — chỉ sau khi đóng băng

- [ ] Đăng ký trước binary SHA-256, scenario, seed, rate, target/revision, trial
  interval, expected event anchors, safety contract và unit phân tích.
- [ ] Chạy cùng blind trial mới cho full model và từng biến thể đã chọn; không
  tái dùng attack set để train/tune hoặc gọi lần chạy đã xem là blind.
- [ ] Ghi TP/FP/TN/FN và uncertain/missing telemetry; báo cả end-to-end và điều
  kiện telemetry hợp lệ, precision/recall/FPR với CI/bootstrap theo trial hoặc
  block. Mọi miss giữ trong recall mẫu số.
- [ ] Đo kernel-to-alert bằng timestamp injection đã bind tới alert; phân biệt
  inference time và replay latency. Báo miss/censored, p50/p95/p99 và overhead.
- [ ] Chỉ kết luận syscall/variant hữu ích nếu cải thiện blind security metric
  so với full, đồng thời giữ chi phí/latency trong ngưỡng preregistered.

### E. Khả năng khái quát ABI/nền tảng

- [ ] Giữ phạm vi kết luận hiện tại là Linux native x86-64 cho đến khi có VM,
  kernel/BTF, architecture và capture độc lập cho distro/ABI khác.
- [ ] Với mỗi nền tảng mới, kiểm tra ánh xạ ABI theo nguồn kernel tương ứng;
  không chuyển trực tiếp syscall number giữa Linux, Windows hay architecture.
- [ ] Chạy lại frequency/ablation và blind validation cho từng miền cần claim;
  không gộp dữ liệu cross-OS khi ngữ nghĩa không tương đương.

## Gate hiện tại

Hai bounded feasibility capture trên worker1/worker3 đã có terminal/seal;
analyzer và cohort đều hợp lệ. Kết quả/giới hạn được ghi trong
`syscall_analysis.md` cùng `sentinel_pulse/SYSCALL_SELECTION_PILOT.md`. Chưa có
đối chứng overhead A/B, kết luận feature ranking đã xác nhận hay blind
evaluation; pilot histogram mới có steady regime, chưa phủ mọi replica/regime.
C1/C2 normal-only refits đã xong; C2 model hashes hợp lệ nhưng manifest path lỗi
cần tạo bản dẫn xuất và đối chiếu input/source trước khi nạp model.
Không có syscall fit job đang chạy; normal soak Sentinel Pulse vẫn chạy riêng.
Không khai báo project xong chỉ vì TODO được tạo; checklist chỉ chuyển sang
hoàn tất khi có artifact và receipt có thể kiểm tra độc lập.
