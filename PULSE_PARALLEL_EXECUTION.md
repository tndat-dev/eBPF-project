# Sentinel Pulse và thí nghiệm syscall: triển khai song song

Hai nhánh có tiến độ và artifact riêng; không yêu cầu hoàn tất chọn syscall
mới tiếp tục đánh giá candidate Pulse đã đóng băng.

SSH **14/10/2026**: C3, C5, C6, soak A1/review, B2 và B3 đã kết thúc.
C6 full raw-positive fraction 3,5825% sau sửa rolling profile, chưa phải FPR.
Hai nhánh tiếp theo tách biệt, giữ model/policy Pulse:

| Nhánh | Công việc hiện hành | Service / output |
|---|---|---|
| Thêm syscall A2 | 105/105 exploratory models, 0 unknown trên C3 đã lộ; không có blind/quality verdict | `.234`: `pulse-syscall-addition-a2.service`; NFS `syscall-addition-a2-20261014` |
| Sentinel Pulse B3 | Canary batch 30 phút hoàn tất trên ba worker; raw-score preview, không phát alert/enforcement | `.237/.238/.239`: `pulse-idle-batch-canary-b3.service`; `/var/lib/pulse-idle-batch-canary-b3-20261014` |

Snapshot terminal B3 được thu lúc **15:55 UTC ngày 14/10**; cả ba unit thoát
thành công, không restart. p99 `feature-window-end → score` lần lượt .237/.238/.239 là
**0,516 / 0,555 / 0,220 giây**. `.238` ghi 3 `collector_cadence_gap`; issue được
giữ, không làm mất terminal. Kernel-to-alert, precision và recall đều null vì
đây là normal timing canary, không có blind attack và policy chỉ preview.
Raw-positive preview vẫn chờ adjudication, không gọi tự động là false positive.

A1 terminal có 0/105 model; nguyên nhân là exact boundary tolerance 100 µs so
với jitter 0,6–1,4 ms. Code đã sửa, test jitter và material gap. A2 đã kết thúc
thành công trên `.234` lúc **16:44:43 UTC ngày 14/10**: terminal ghi
`completed_exploratory_addition_study`, **105/105 model**, `unknowns={}`,
`fresh_blind_complete=false`; precision/recall/FPR/kernel-to-alert đều null.
Đây là pipeline exploratory hoàn tất trên C3 đã lộ, không phải blind attack
hay bằng chứng chọn syscall. Không còn cần chờ A2 chạy nền. Candidate Pulse
giữ nguyên; không zero-alert gate và không auto-promotion.

Tình trạng cụm lúc kiểm tra: 6/6 node `Ready` ở v1.34.10; namespace
`production` có 70 pod objects, trong đó 66 `Running` và 4 `Completed` (job
pod đã hoàn tất, không phải service đang hỏng). Trên cả ba worker,
`sentinel-pulse-resolver.service` active và `pulse_counter_loader` đang thu
feature **mỗi 1.000 ms**. Canary B3 đã dừng bình thường; hiện không có B3
500-ms canary chạy. Đây là capture nền, không được mô tả nhầm thành ML
decision/alert real-time đang chạy trên 500 ms.

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

C4 đã hoàn tất lúc 14:46 và xác minh đủ 608 prediction. Full C2 có
145.820/334.655 raw flags (43,57%); **không được coi là bộ model đã ổn định**.
Không relabel chúng thành FP khi chưa adjudicate, cũng không che kết quả bằng
đổi ngưỡng. C5 chỉ đọc dataset reference và selection để tìm bằng chứng;
không dùng holdout để chọn biến thể. [Chi tiết](SYSCALL_FEATURE_EXPERIMENT_STATUS.md).

Nhánh Pulse xử lý coverage/nhãn của soak, chuẩn bị adapter đánh giá attack cho
idle-aware candidate và đo confusion matrix trên interval thống nhất. SSH hiện
xác nhận `sentinel-pulse-exec-provenance` đã enabled trên 6/6 Tetragon pod;
điều đó cung cấp timestamp exec, nhưng chưa đồng nghĩa đã chạy attack gắn với
preview của candidate hiện hành.
Nhánh syscall chốt audit C5; tiếp tục bind blind binary/cases/target mới, chấm cùng
trial cho các biến thể và tổng hợp paired statistics/CI. Không chọn syscall hay
tune threshold bằng holdout, không dùng latency offline thay cho live latency.

Blind attack tác động vào chính workload đang thu normal phải có khoảng thời
gian hoặc target riêng. Không inject vào capture đã đăng ký normal chỉ để làm
hai job cùng active. Trong lúc capture normal chạy, review/offline analysis và
chuẩn bị attack của nhánh Pulse vẫn triển khai độc lập. Việc điều phối lịch
inject bảo vệ nhãn dữ liệu, không tạo thứ tự ưu tiên giữa hai nhánh.

## Kiểm tra terminal và process live

```bash
systemctl show pulse-syscall-addition-a2.service -p Result -p ExecMainStatus -p ActiveState
python3 -m json.tool /mnt/sentinel-pulse-archive/syscall-addition-a2-20261014/TERMINAL.json
systemctl show pulse-idle-batch-canary-b3.service -p Result -p ActiveState -p SubState
```

Canary B3 hiện đã `inactive/dead` sau `Result=success`; baseline exact loader
trên workers chạy 1.000 ms, không có candidate 500 ms scorer live.
Trên `.234`, xem `pulse-syscall-distribution-audit-c5.service` và
`/mnt/sentinel-pulse-archive/syscall-development-distribution-c5/STATUS.json`.
`completed_inputs/expected_inputs` là tiến độ đọc dữ liệu, không phải chất lượng model.
Evidence hoàn tất capture/review:
[SUMMARY.json](validation-evidence/pulse-parallel-completion-20261014/SUMMARY.json).
