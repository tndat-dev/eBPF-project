# TODO thực nghiệm chọn syscall và đánh giá candidate

Cập nhật hiện hành qua SSH: **14/10/2026 03:14 UTC+7**. Capture soak
`normal-a1-20261013` hoàn tất **100% trên ba worker**, đủ 86.400 giây/node,
errors=0, capacity pauses=0. Shadow vẫn xử lý backlog, chưa chốt đánh giá.
Job `pulse-syscall-capture-c3.service` enabled/active trên `.234`, đã chấp nhận
4/10 phase (12/30 capture worker), đang thu selection-recovery; sau đó là năm
regime holdout riêng. ETA capture khoảng 05:30–06:00 ngày 14/10. Chi tiết:
[SYSCALL_CAPTURE_C3.md](SYSCALL_CAPTURE_C3.md).

Hai offline syscall-feature campaigns đã kết thúc: C1 attempt-000002 và C2
attempt-000002 đều terminal `completed`, 608/608 fits, errors rỗng, 19 workload
× 32 variants. C2 service là `active (exited)` kiểu oneshot, không còn fit process.
C2 attempt-000001 lỗi `NameError: os`; artifact gốc được giữ. C2 manifest gốc có
path dư `models/` (`models/models/<file>.pkl`). Đã tạo
`VARIANT_MODEL_MANIFEST.derived.json` riêng trên NFS bằng verifier mới: kiểm tra
START/RESULTS/TERMINAL binding và SHA-256/size cả 608 model, rồi sửa đúng prefix
trong sidecar; SHA-256 sidecar là
`4c379dcabd8ea2c8ca0c19f9e13e186dfa9fe63f0df1ea1a2d4d591e946c4408`; manifest
gốc không bị sửa. Sidecar có detached SHA-256 và provenance. C1/C2 dùng cùng
input hashes và cùng hash của model/features/train/encoding; chỉ hash module
điều phối experiment khác nhau, nên đây **không phải
hai lần xác nhận độc lập**. Cả hai vẫn exploratory normal-only; precision,
recall và kernel-to-alert để null, không tự promotion.

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
- [x] Tạo manifest dẫn xuất đã sửa path, bind SHA manifest gốc/START/RESULTS/
  TERMINAL và xác minh hash/size đủ 608 model; giữ nguyên manifest gốc.
- [x] Đối chiếu C2 với C1 theo input/source/training split hashes: input và các
  module ML giống nhau; hai run không độc lập về dữ liệu.
- [x] Nạp tuần tự 608/608 pickle trên VM bằng đúng venv C2 (Python 3.12.3,
  scikit-learn 1.9.1, NumPy 2.5.3); mỗi model có estimator `predict_proba` và
  calibration scores. Đây chỉ là deserialization/schema check, không phải
  inference benchmark hay kiểm thử phát hiện.
- [x] Replay 608/608 model trên context C2 đã lưu: score sai lệch lớn nhất 0,
  conformal p-value và decision khớp. Receipt riêng trên NFS; không gọi là test độc lập.
- [ ] Chấm các model trên normal holdout mới, độc lập và chưa xem; kiểm tra
  overlap source/hash/revision, nhãn unknown không được tính TN.
- [ ] Khóa một candidate/model manifest và policy; không dùng blind set để tune.

### B. Thu full-ID syscall normal độc lập

- [x] Triển khai coordinator systemd bền vững C3; build hai collector trên ba
  worker; cấu hình năm regime selection và năm regime holdout tách biệt.
- [x] Đăng ký điều kiện chờ soak, source/archive binding, capture/feature schema,
  unit phân tích 30 giây và kế hoạch bootstrap/Holm trước capture mới.
- [ ] Phục hồi/ổn định workload và traffic generator; xác định target pod UID,
  container, revision, cgroup và node từ resolver/API tại thời điểm capture.
- [ ] Đăng ký trước traffic receipt với regime và khoảng thời gian chính xác.
  Năm chế độ steady, toolmix, peak, burst, recovery được định nghĩa trong code;
  receipt execution được phát hành sau rollout, trước probe. Job hiện đang chờ,
  chưa coi cấu hình tải là dữ liệu đã thu.
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
C1/C2 normal-only refits đã xong; manifest dẫn xuất, load và replay 608/608
đã xác minh. Không có fit job đang chạy. C3 đã chấp nhận bốn phase selection,
đang thu recovery; còn vòng holdout riêng. Preflight 12 capture kiểm tra
313.318 rows, 269.036 context đủ điều kiện đầu vào; chưa phải kết quả scoring.
Blind attack từng biến thể và thống kê kết luận giữ/bỏ vẫn chưa có kết quả mới.
Không khai báo project xong chỉ vì TODO được tạo; checklist chỉ chuyển sang
hoàn tất khi có artifact và receipt có thể kiểm tra độc lập.
