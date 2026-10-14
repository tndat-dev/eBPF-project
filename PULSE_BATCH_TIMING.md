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

## B2/B3 đã hoàn tất; Pulse và A2 tiếp tục chạy song song

B2 đã hoàn tất **30 phút trên cả ba worker**, 230.895 scored rows,
7.158 preview pending. Feature-end-to-score p99 lần lượt .237/.238/.239:
**0,502/0,556/0,213 s**, max **0,880/0,863/0,290 s**. .238 có 9 cadence gaps;
giữ warming/reset và issue counts. .239 có bốn trailing snapshots/804 bytes
chưa đóng nên không score. Các seal đã kiểm tra trên từng worker.
[Terminal/verification B2](validation-evidence/pulse-batch-canary-b2-evidence-final-20261014/).

B3 unit `pulse-idle-batch-canary-b3.service`, source `8214906`, hoàn tất
**30 phút** trên cả ba worker, `ExecMainStatus=0`, `NRestarts=0`. Cadence là
**500 ms**; model manifest/policy khớp B2. Mỗi node CPU quota 200%, RAM tối đa
2 GiB, Nice=15, IOWeight=1; raw/features/decisions có budget 1 GiB. Unit này
không phát enforcement; mọi issue và positive preview được giữ.

| Worker | Frames | Scored rows | p99 window-end → score | Preview positives pending | Issue |
|---|---:|---:|---:|---:|---|
| .237 | 3.525 | 98.588 | 0,516 s | 3.362 | none |
| .238 | 3.452 | 104.403 | 0,555 s | 4.375 | 3 cadence gaps |
| .239 | 3.584 | 27.866 | 0,220 s | 2.401 | none |
| **Tổng** | **10.561** | **230.857** | — | **10.138** | — |

Pipeline frame processing p99 lần lượt là 0,579/0,642/0,246 s. Bảng B3 là
timing/coverage canary, **không phải** kernel-to-alert, recall hay FPR; các
10.138 preview cần adjudication. Evidence có per-file seals và START/TERMINAL
hash trong [B3 terminal summary](validation-evidence/pulse-parallel-completion-20261014/b3-canary-terminal-summary.json).
Raw terminal gốc vẫn root-owned tại `/var/lib/pulse-idle-batch-canary-b3-20261014`
trên worker; summary hash không thay thế export raw terminal.

Output B3 từng worker: `/var/lib/pulse-idle-batch-canary-b3-20261014`.
Nhánh syscall chạy độc lập trên control plane: C6 đã hoàn tất; nhánh mới
thử thêm ID ngoài tập 29, không đổi Pulse. Không dùng runtime venv 1.9.0 này để mở pickle
C2 vốn yêu cầu scikit-learn 1.9.1. Lỗi đó không áp vào Pulse idle-aware B1/B2.

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

Regression liên quan: **47 passed, 12 skipped** trên Python hệ thống host.
Các test ML bị skip vì host chưa có NumPy; bốn batch-runtime tests đã pass
trên cả ba worker, bốn context-extraction tests và một distribution-audit test
đã pass bằng venv C2 trên VM.
Lượt chạy toàn bộ pytest trên host bị chặn khi collect do thiếu NumPy
(46 collection errors); không báo toàn bộ suite đã pass trong lượt này.

Checkpoint B2 khoảng 14:43: cả ba unit running, NRestarts=0. Worker `.238`
ghi 3 cadence gap; giữ chúng, không dừng run hoặc sửa model. Row scored gần
nhất có feature-end age khoảng 0,114 / 0,241 / 0,172 s theo `.237/.238/.239`;
đây là các mẫu riêng lẻ, **không phải p95/p99**. CPU cgroup chưa ghi throttling
ở checkpoint này; chưa phải benchmark overhead A/B.
Evidence: [live prefix](validation-evidence/pulse-parallel-completion-20261014/b2-live-prefix-20261014-1443.json).
