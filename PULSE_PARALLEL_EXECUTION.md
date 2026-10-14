# Sentinel Pulse và thí nghiệm syscall: triển khai song song

Hai nhánh có tiến độ và artifact riêng; không yêu cầu hoàn tất chọn syscall
mới tiếp tục đánh giá candidate Pulse đã đóng băng.

SSH **14/10/2026, 14:36 UTC+7**: C3 đã hoàn tất **10/10 phase**, đủ 15 capture
selection và 15 capture holdout. Review soak Pulse đã đọc hết cả ba worker,
không có lỗi binding trong kết quả. Hai công việc tiếp theo đang chạy song song:

| Nhánh | Công việc hiện hành | Service / output |
|---|---|---|
| Chọn syscall C4 | Chấm 608 biến thể đã đóng băng trên holdout C3 mới | `.234`: `pulse-syscall-normal-evaluation-c4.service`; NFS `syscall-variant-normal-c4` |
| Sentinel Pulse | Canary batch 30 phút, live normal traffic trên ba worker | `.237/.238/.239`: `pulse-idle-batch-canary-b2.service`; `/var/lib/pulse-idle-batch-canary-b2-20261014` |

Canary bắt đầu khoảng **14:35**, dự kiến kết thúc khoảng **15:06 ngày 14/10**.
Kiểm tra cả hai nhánh khoảng **15:10 UTC+7**. Đây là ETA canary, không phải ETA
hoàn tất blind attack hoặc paper. C4 resume bằng checkpoint sau SSH/reboot;
canary 30 phút tách biệt SSH nhưng là job bounded, chưa có cơ chế cộng dồn sau
reboot. Cả hai giữ model/policy, không zero-alert gate và không auto-promotion.

## Kết quả soak Pulse đã tổng hợp

Capture đã đóng với 33.149.479 feature rows tổng trên ba worker. Job review
đã đọc hết các file decision khoảng 11,75 GB, 12,79 GB và 3,51 GB; không sao
chép lại raw. Tổng **33.148.914 decision**, gồm **11.388.831 scored**,
**21.759.882 model-unavailable**, **201 warming**. Các key model-unavailable
là `pod-slice`, không phải 21 container ứng dụng bị thiếu model. Có **30.412
preview dương chờ adjudicate**; không tự gọi chúng là FP. Tổng số decision
ít hơn feature capture **565 dòng**; chưa chứng minh alignment/coverage hoàn chỉnh.

Review cung cấp theo workload:

- Số dòng scored, warming, thiếu model, degraded/rejected và lỗi binding.
- Raw model anomaly và preview dương cần adjudicate; giữ ví dụ identity/time.
- Histogram thời gian inference và feature-window-end đến lúc chấm score.
- SHA-256 toàn bộ file decision và chênh số dòng so với terminal capture.

So sánh số dòng chỉ kiểm tra tổng lượng dữ liệu; chưa chứng minh mọi feature
đã ghép đúng decision. Preview chưa có nhãn được giữ là pending adjudication;
precision/recall/FPR và confusion matrix còn null. Kernel-to-alert cần đánh
giá live attack riêng. Candidate/model/policy đã đóng băng vẫn được giữ nguyên.

Job review dùng systemd cố định, checkpoint mỗi khoảng 5 giây, tự chạy khi VM
boot. Resume xác minh source/input binding và SHA-256 prefix trước khi đọc tiếp;
không cộng lại những dòng đã checkpoint. Giới hạn mỗi worker: CPU 50% một core,
RAM 256 MiB, Nice=19, IOWeight=1. Chỉ đọc dữ liệu đã đóng; output tổng hợp nhỏ.

Source review: `/home/dat/pulse-shadow-summary-20261014/source-r2`, commit
`c416941` (summary logic từ `12c796d`). Bốn test cho resume, source thay đổi,
binding và bucket latency đã pass. Cấu hình r2 lấy run ID **riêng từng node** từ
environment đã đăng ký của soak. Output r1 được giữ để chẩn đoán: cấu hình đầu
đã dùng run ID chung nên ghi `run_binding_mismatch`, không phải lỗi của model.

## Batch timing và giới hạn phép đo

Benchmark đã xác minh **21/21 frozen model**, score sai lệch lớn nhất **0**,
p-value/decision scalar và batch khớp tuyệt đối. Canary live 5 phút trên `.237`
chấm **16.380 context**, feature-window-end → score p50/p95/p99
**0,227/0,424/0,474 giây**, max **0,667 giây**; issues={}. Còn 4 snapshot và
607 byte ở frame cuối chưa đóng; giữ raw và không đưa vào scoring.
Đây chưa phải kernel-to-alert, chưa đánh giá recall/precision bằng attack.
Source, giới hạn và artifact: [PULSE_BATCH_TIMING.md](PULSE_BATCH_TIMING.md).

## Công việc sau hai job hiện hành

Nhánh Pulse xử lý coverage/nhãn của soak, chuẩn bị adapter đánh giá attack cho
idle-aware candidate và đo confusion matrix trên interval thống nhất.
Nhánh syscall hoàn tất C4; sau đó bind blind binary/cases/target mới, chấm cùng
trial cho các biến thể và tổng hợp paired statistics/CI. Không chọn syscall hay
tune threshold bằng holdout, không dùng latency offline thay cho live latency.

Blind attack tác động vào chính workload đang thu normal phải có khoảng thời
gian hoặc target riêng. Không inject vào capture đã đăng ký normal chỉ để làm
hai job cùng active. Trong lúc capture normal chạy, review/offline analysis và
chuẩn bị attack của nhánh Pulse vẫn triển khai độc lập. Việc điều phối lịch
inject bảo vệ nhãn dữ liệu, không tạo thứ tự ưu tiên giữa hai nhánh.

## Kiểm tra job đang chạy

```bash
sudo systemctl status pulse-idle-batch-canary-b2.service --no-pager
sudo python3 -m json.tool /var/lib/pulse-idle-batch-canary-b2-20261014/STATUS.json
```

Trên `.234`, xem `pulse-syscall-normal-evaluation-c4.service` và
`/mnt/sentinel-pulse-archive/syscall-variant-normal-c4/STATUS.json`.
`completed_models/608` là tiến độ scoring, không phải phần trăm chất lượng model.
Evidence hoàn tất capture/review:
[SUMMARY.json](validation-evidence/pulse-parallel-completion-20261014/SUMMARY.json).
