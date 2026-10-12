# TODO thực nghiệm chọn syscall và đánh giá candidate

Cập nhật hiện hành: **12/10/2026**. Đây là checklist điều phối công việc, không
phải số liệu kết quả. Trạng thái live C2 đọc qua SSH lúc 12:24:09 UTC: service
`pulse-syscall-variant-models-c2.service` đang `activating`, `57/608` fit,
đang ở `drop_sendmmsg`, `errors=[]`. Không sửa hoặc dừng service này.

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
- [x] Thêm regression tests cho receipt, capture hợp lệ, dữ liệu unlabelled,
  interval cắt qua ranh giới regime và artifact bị sửa.
- [x] SSH kiểm tra cluster: 6/6 node `Ready`, Kubernetes `v1.34.10`; namespace
  `production` có 66 Running, 20 Evicted, 5 Error, 6 ContainerStatusUnknown,
  4 Completed; trên worker3, một phần loadgen AIMS Evicted/Unknown và một số
  microservice Error/Completed. Vì vậy lượt hiện tại **không attach probe** và
  không phát sinh tải/canary mới.
- [x] Cập nhật trạng thái C2 qua SSH lúc **12:24:09 UTC**: `57/608`, không lỗi.

## Checklist để có bằng chứng chọn syscall

### A. Hoàn tất và đóng băng normal-only ablation

- [ ] Chờ C2 hoàn tất đủ `608/608`, không dừng job chỉ vì phiên SSH kết thúc.
- [ ] Xác minh terminal `completed`, `errors=[]`, đủ 608 model artifact, manifest
  chứa checksum khớp mọi model/dataset/source/policy.
- [ ] Đối chiếu C2 với C1; giữ nguyên checkpoint cũ, không gộp timing tích lũy
  hoặc kết quả từ host khác vào wall time của VM.
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

Code harness và unit tests đã có; chưa có lần chạy collector histogram nào được
thực hiện bởi harness mới, chưa có traffic receipt thực, chưa có full-ID capture
được chấp nhận làm selection evidence, chưa có blind evaluation cho từng biến
thể. C2 đang chạy là offline normal-only refit, không thay cho các bước trên.
Không khai báo project xong chỉ vì TODO được tạo; checklist chỉ chuyển sang
hoàn tất khi có artifact và receipt có thể kiểm tra độc lập.
