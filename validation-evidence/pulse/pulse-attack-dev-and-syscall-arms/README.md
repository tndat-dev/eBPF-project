# Bằng chứng lượt matched 500 ms pulse-attack-dev và lượt tiếp nối

Các JSON ở đây được sao chép trực tiếp qua SSH/SFTP từ NFS của cụm.
pulse-attack-dev là đánh giá development trên scenario đã biết, dùng frozen candidate preview;
control mang nhãn expected-normal và còn cần review.

- `pulse-attack-dev-campaign-TERMINAL.json`: terminal gốc, 315 cặp attack/control.
- `pulse-attack-dev-campaign-START.json`, `pulse-attack-dev-CONFIG.json`: đăng ký và binding gốc.
- `pulse-attack-dev-replay-TERMINAL.json`, `pulse-attack-dev-replay-START.json`, `pulse-attack-dev-replay-CHANGES.json`:
  replay sau sửa evaluator cho warming không có policy hash; terminal gốc được giữ nguyên.
- `syscall-arms-CONFIG.json`: study sửa điều kiện chờ segment đóng, cùng khoảng selection pulse-attack-dev.
- `syscall-arms-STATUS-at-inspection.json`: snapshot tiến độ study, có timestamp trong file.
- `syscall-arms-INDEX.json`, `syscall-arms-INPUTS.json`: index workload/arm và danh sách input đã seal.
- `pulse-attack-dev-rabbitmq-CONFIG.json`, `pulse-attack-dev-rabbitmq-STATUS-at-inspection.json`: đăng ký và tiến độ follow-up RabbitMQ.
- `pulse-attack-dev-rabbitmq-START.json`, `pulse-attack-dev-rabbitmq-RESULTS.json`, `pulse-attack-dev-rabbitmq-TERMINAL.json`: đủ 15 cặp RabbitMQ, giữ hai attack unknown.

Nguồn gốc pulse-attack-dev: `/mnt/sentinel-pulse-archive/matched-parallel-r3-20261015`.
Replay: `/mnt/sentinel-pulse-archive/matched-parallel-r3-replay-20261015`.
syscall-arms: `/mnt/sentinel-pulse-archive/matched-parallel-r4-20261015`.

`kernel_to_preview_seconds` chỉ đo các trial phát hiện được. Các metric
`confirmed_precision`, `confirmed_FPR` và `kernel_to_alert` còn null.
Timestamp kernel đến từ execve của fixture; control chưa chạy benign fixture
cùng cơ chế launch. Phép đo này còn có confound cần xử lý ở thiết kế tiếp theo.
