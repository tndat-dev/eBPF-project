# R10-C1 live normal canary

Ba tệp dữ liệu ở đây được sao chép từ VM `10.1.16.234` sau khi canary kết thúc:

- `START.json`: cấu hình và thời điểm bắt đầu.
- `AGGREGATE.json`: số liệu tổng hợp cho ba worker.
- `FINAL_SHA256SUMS`: checksum index nguyên bản của toàn evidence trên VM.

Canary kéo dài khoảng 15 phút, normal-only. Aggregate xác nhận 113.543 decision,
0 alert, 0 detector restart và đủ coverage cho 21/21 workload/container. P99
window-start-to-decision là 1,035 giây. Đây không phải blind attack latency,
không phải FPR population estimate và không chứng minh false-positive rate bằng
0. Bundle evidence đầy đủ, gồm raw worker logs, vẫn ở VM tại
`/home/dat/sentinel-pulse-evidence/canary-r10-c1-20260930`.

`FINAL_SHA256SUMS` tham chiếu nhiều file raw không được sao chép vào repository;
hãy chạy `sha256sum -c` trong archive đầy đủ trên VM để xác minh cả bundle.
