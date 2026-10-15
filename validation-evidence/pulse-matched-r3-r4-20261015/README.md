# Bằng chứng lượt matched 500 ms R3 và lượt tiếp nối

Các JSON ở đây được sao chép trực tiếp qua SSH/SFTP từ NFS của cụm.
R3 là đánh giá development trên scenario đã biết, dùng frozen candidate preview;
control mang nhãn expected-normal và còn cần review.

- `r3-campaign-TERMINAL.json`: terminal gốc, 315 cặp attack/control.
- `r3-campaign-START.json`, `r3-CONFIG.json`: đăng ký và binding gốc.
- `r3-replay-TERMINAL.json`, `r3-replay-START.json`, `r3-replay-CHANGES.json`:
  replay sau sửa evaluator cho warming không có policy hash; terminal gốc được giữ nguyên.
- `r4-CONFIG.json`: study sửa điều kiện chờ segment đóng, cùng khoảng selection R3.
- `r4-STATUS-at-inspection.json`: snapshot tiến độ study, có timestamp trong file.
- `r4-INDEX.json`, `r4-INPUTS.json`: index workload/arm và danh sách input đã seal.
- `r5-CONFIG.json`, `r5-STATUS-at-inspection.json`: đăng ký và tiến độ follow-up RabbitMQ.
- `r5-START.json`, `r5-RESULTS.json`, `r5-TERMINAL.json`: đủ 15 cặp RabbitMQ, giữ hai attack unknown.

Nguồn gốc R3: `/mnt/sentinel-pulse-archive/matched-parallel-r3-20261015`.
Replay: `/mnt/sentinel-pulse-archive/matched-parallel-r3-replay-20261015`.
R4: `/mnt/sentinel-pulse-archive/matched-parallel-r4-20261015`.

`kernel_to_preview_seconds` chỉ đo các trial phát hiện được. Các metric
`confirmed_precision`, `confirmed_FPR` và `kernel_to_alert` còn null.
Timestamp kernel đến từ execve của fixture; control chưa chạy benign fixture
cùng cơ chế launch. Phép đo này còn có confound cần xử lý ở thiết kế tiếp theo.
