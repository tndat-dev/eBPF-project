# Sentinel Pulse và thí nghiệm syscall: triển khai song song

Hai nhánh có tiến độ và artifact riêng; không yêu cầu hoàn tất chọn syscall
mới tiếp tục đánh giá candidate Pulse đã đóng băng.

SSH **09:33 ngày 14/10/2026 (UTC+7)** xác nhận C3 đang collecting recovery
attempt 17. Cả ba review r2 đang `summarizing`, enabled, NRestarts=0, issues={}.
Đã tổng hợp 2.722.602 dòng decision, trong đó 929.400 dòng scored; 2.834 preview
dương còn chờ adjudicate. Đây là số đếm prefix đang đọc, chưa phải kết quả toàn
soak hoặc số false positive. Byte progress: `.237` 7,61%; `.238` 5,95%; `.239`
18,56%. Ngoại suy tuyến tính từ tốc độ hiện tại cho review khoảng **09:50–10:00**;
không phải cam kết hoàn thành nhãn/confusion matrix. Evidence:
`validation-evidence/syscall-c3-20261014/parallel-status-20261014-0935.json`.

| Nhánh | Công việc hiện hành | Service / output |
|---|---|---|
| Chọn syscall C3 | Recovery đa chế độ tải, sau đó năm regime normal holdout | `.234`: `pulse-syscall-capture-c3.service`; NFS `syscall-capture-c3-r2` |
| Sentinel Pulse | Tổng hợp toàn bộ decision của soak 24 giờ trên từng worker | `.237/.238/.239`: `pulse-shadow-soak-summary@normal-a1-20261013.service`; `/var/lib/pulse-shadow-review/normal-a1-20261013-r2` |

## Nhánh Pulse đang xử lý gì

Capture đã đóng với 33.149.479 feature rows tổng trên ba worker. Job review
đọc lần lượt các file decision khoảng 11,75 GB, 12,79 GB và 3,51 GB; không sao
chép lại raw. Nó tổng hợp theo workload:

- Số dòng scored, warming, thiếu model, degraded/rejected và lỗi binding.
- Raw model anomaly và preview dương cần adjudicate; giữ ví dụ identity/time.
- Histogram thời gian inference và feature-window-end đến lúc chấm score.
- SHA-256 toàn bộ file decision và chênh số dòng so với terminal capture.

So sánh số dòng chỉ kiểm tra tổng lượng dữ liệu; chưa chứng minh mọi feature
đã ghép đúng decision. Preview chưa có nhãn được giữ là pending adjudication;
precision/recall/FPR và confusion matrix còn null. Kernel-to-alert cần đánh
giá live attack riêng. Candidate/model/policy đã đóng băng vẫn được giữ nguyên.

Job review chạy systemd cố định, checkpoint mỗi khoảng 5 giây, tự chạy khi VM
boot. Resume xác minh source/input binding và SHA-256 prefix trước khi đọc tiếp;
không cộng lại những dòng đã checkpoint. Giới hạn mỗi worker: CPU 50% một core,
RAM 256 MiB, Nice=19, IOWeight=1. Chỉ đọc dữ liệu đã đóng; output tổng hợp nhỏ.

Source review: `/home/dat/pulse-shadow-summary-20261014/source-r2`, commit
`c416941` (summary logic từ `12c796d`). Bốn test cho resume, source thay đổi,
binding và bucket latency đã pass. Cấu hình r2 lấy run ID **riêng từng node** từ
environment đã đăng ký của soak. Output r1 được giữ để chẩn đoán: cấu hình đầu
đã dùng run ID chung nên ghi `run_binding_mismatch`, không phải lỗi của model.

## Công việc song song tiếp theo

Nhánh Pulse xử lý coverage/nhãn của soak, chuẩn bị adapter đánh giá attack cho
idle-aware candidate và đo confusion matrix trên interval thống nhất.
Nhánh syscall hoàn tất holdout, rồi chấm cùng trial cho các biến thể và tổng
hợp paired statistics/CI để đánh giá đóng góp syscall.

Blind attack tác động vào chính workload đang thu normal phải có khoảng thời
gian hoặc target riêng. Không inject vào capture đã đăng ký normal chỉ để làm
hai job cùng active. Trong lúc capture normal chạy, review/offline analysis và
chuẩn bị attack của nhánh Pulse vẫn triển khai độc lập. Việc điều phối lịch
inject bảo vệ nhãn dữ liệu, không tạo thứ tự ưu tiên giữa hai nhánh.

## Kiểm tra trên từng worker

```bash
sudo systemctl status pulse-shadow-soak-summary@normal-a1-20261013.service --no-pager
sudo python3 -m json.tool /var/lib/pulse-shadow-review/normal-a1-20261013-r2/STATUS.json
```

`activating/start` là trạng thái systemd bình thường của job `Type=oneshot`
đang tính toán. Xem tiến độ bằng byte offset/size và số row trong STATUS, không
chỉ dựa vào trạng thái active. `TERMINAL.json` chỉ được tạo sau khi đọc hết.
