# Pulse: tối ưu batch inference và canary live

Trạng thái SSH **14/10/2026**. Model idle-aware 21 workload và policy đã đóng
băng không đổi. Chỉ thay cách gom context của các replica cùng workload để
gọi model một lần, thay vì gọi từng row. Cả hai đường giữ history riêng theo
pod/container/cgroup/revision; không gộp lịch sử giữa replica hoặc qua gap.

## Đã kiểm chứng

Benchmark worker1 dùng đúng runtime frozen: Python 3.12.3, NumPy 2.5.2,
scikit-learn 1.9.0. Mỗi model có 64 context từ prefix capture đã đóng, hai lần
đo, batch size 2/4/8/16/32/64. **21/21 model** có score sai lệch **0**, p-value
và quyết định khớp scalar. Batch 2 giảm tổng thời gian scoring **1,87–2,19 lần**
giữa các workload. Đây là benchmark kỹ thuật, chưa phải A/B thống kê hoặc
quality test độc lập. Batch lớn có lợi offline nhưng không được đợi tích đủ
64 window mới score live.

Canary B1 trên `.237` chạy **300,206 giây**, dùng frame counter 500 ms và
chấm ngay các context có trong frame, không đợi thêm window để tăng batch.

| Chỉ số đo được | Kết quả |
|---|---:|
| Frame hoàn chỉnh đã xử lý | 589 |
| Context scored | 16.380 |
| Feature-window-end → score p50 / p95 / p99 | 0,227 / 0,424 / 0,474 s |
| Feature-window-end → score lớn nhất | 0,667 s |
| Chi phí xử lý toàn frame p50 / p95 / p99 | 435 / 500 / 533 ms |
| Model call p50 / p95 / p99, lặp theo scored row | 19,52 / 26,44 / 31,94 ms |
| Batch thực tế | 1, 2 hoặc 3 context cùng workload |
| Warming / model-unavailable | 84 / 31.752 |
| Preview dương chờ adjudicate | 149 |
| Issues | {} |

Model-unavailable là các scope `pod-slice`, không biến chúng thành normal/TN.
4 snapshot và 607 byte frame cuối chưa đóng được giữ trong raw, không chấm.
Toàn bộ SHA-256 raw/features/decisions/issues/loader.log đã kiểm tra trên VM.
Source B1: `5f7b55c`; không restart hoặc sửa capture/decision của soak 24 giờ.

**Giới hạn:** đây là traffic normal live trên một worker trong 5 phút. Mốc
thời gian bắt đầu ở cuối feature window, không phải kernel syscall đầu tiên;
đầu ra `alert=false`, chỉ `candidate_alert_preview`. Vì vậy kernel-to-alert,
precision, recall và confusion matrix vẫn chưa được xác định cho candidate
này. Không cộng cơ học 500 ms vào p99 rồi công bố thành latency attack đã đo.
Soak scalar cũ có backlog lớn: 6.660.911/11.388.831 scored row có event age
trên một giờ. Canary mới là thay đổi kỹ thuật có triển vọng, không xóa kết quả cũ.

## Đang chạy

B2: **30 phút trên cả ba worker** `.237/.238/.239`, unit
`pulse-idle-batch-canary-b2.service`, source `5ee9c39`. Bắt đầu khoảng 14:35,
dự kiến kết thúc 15:06; kiểm tra khoảng **15:10 UTC+7 ngày 14/10**.
Mỗi node CPU quota 200%, RAM tối đa 2 GiB, Nice=15, IOWeight=1; raw/features/
decisions có budget 1 GiB. Mọi lỗi và preview được giữ, không zero-FP gate.
Đây là canary bounded, không phải soak 24 giờ mới hoặc job tự cộng dồn qua reboot.
Đóng SSH/laptop không dừng service; reboot/interruption được giữ là evidence.

Output từng worker: `/var/lib/pulse-idle-batch-canary-b2-20261014`.
Nhánh C4 syscall vẫn chạy độc lập trên control plane, không dùng runtime venv
1.9.0 này để mở pickle C2 vốn yêu cầu scikit-learn 1.9.1.

## Source và bằng chứng

- [idle_batch.py](sentinel_pulse/idle_batch.py): giữ output order, batch theo workload.
- [idle_batch_live_canary.py](sentinel_pulse/idle_batch_live_canary.py): complete-frame
  collector → feature → frozen model/policy → decision, giới hạn thời gian/dung lượng.
- [Benchmark đã seal](validation-evidence/pulse-parallel-completion-20261014/batch-benchmark.json).
- [B1 START](validation-evidence/pulse-batch-canary-b1-evidence-20261014/237-START.json),
  [TERMINAL](validation-evidence/pulse-batch-canary-b1-evidence-20261014/237-TERMINAL.json),
  [kiểm chứng seal](validation-evidence/pulse-batch-canary-b1-evidence-20261014/237-verification.json).

Bước kế tiếp là đánh giá tải/lag B2 theo từng node, rồi chạy fresh blind attack
với receipt kernel/injection và decision binding phù hợp idle-aware candidate.
Giữ mọi miss/unknown, đo recall và latency thực; không đổi ngưỡng theo blind set.

## Kiểm chứng code và quan sát đang chạy

Regression liên quan: **41 passed, 8 skipped** trên Python hệ thống host.
Các test ML bị skip vì host chưa có NumPy; bốn batch-runtime tests đã pass
trên cả ba worker, bốn context-extraction tests đã pass bằng venv C2 trên VM.
Lượt chạy toàn bộ pytest trên host bị chặn khi collect do thiếu NumPy
(46 collection errors); không báo toàn bộ suite đã pass trong lượt này.

Checkpoint B2 khoảng 14:43: cả ba unit running, NRestarts=0. Worker `.238`
ghi 3 cadence gap; giữ chúng, không dừng run hoặc sửa model. Row scored gần
nhất có feature-end age khoảng 0,114 / 0,241 / 0,172 s theo `.237/.238/.239`;
đây là các mẫu riêng lẻ, **không phải p95/p99**. CPU cgroup chưa ghi throttling
ở checkpoint này; chưa phải benchmark overhead A/B.
Evidence: [live prefix](validation-evidence/pulse-parallel-completion-20261014/b2-live-prefix-20261014-1443.json).
