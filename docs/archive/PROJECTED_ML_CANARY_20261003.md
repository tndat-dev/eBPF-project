# Sentinel Pulse — ML canary với projected counters, 03/10/2026

## 1. Trạng thái đã xác minh

**Terminal kiểm tra lại qua SSH lúc 11:50:47 ICT ngày 03/10/2026:**
`CANARY_COMPLETE=true`, `ACTIVE=false`, aggregate `valid=true`, coverage
**21/21 workload/container**; orchestrator exit 0. START checksum **10/10** và
FINAL checksum **76/76** đều khớp khi kiểm tra lại. Receipt:
[TERMINAL_RECEIPT_20261003.json](../../validation-evidence/projected-ml-c1-20261003/TERMINAL_RECEIPT_20261003.json).

| Kết quả terminal | Giá trị |
|---|---:|
| Tổng decision | 114.984 |
| Normal / suppressed / warming | 113.199 / 1.429 / 356 |
| Scored | 114.628 |
| Alert / restart | 0 / 0 |
| Inference p99 / max | 30,092 / 56,641 ms |
| Đầu window → timestamp sau inference p99 / max | 1,053 / 1,376 s |
| Sau cuối window → timestamp sau inference p99 | 0,546 s |

Timestamp trên nằm **trước policy và output**, không phải kernel-to-alert.
Canary normal-only 15 phút/node không chứng minh FPR=0 hoặc recall; blind
set vẫn chưa mở. Collector/detector candidate đã dừng sau finalization,
control collector/resolver active. Bước tiếp theo là soak operational mới
với projected collector và bundle frozen, không tự động promote.

Các checkpoint ACTIVE và lịch 10:35 dưới đây là **lịch sử**, không còn là
trạng thái hiện tại.

Checkpoint SSH **10:15 ICT ngày 03/10/2026**: ML candidate và collector
projected active trên **3/3 worker**, 0 restart. Đây là **live-normal canary
non-formal**, không phải production promotion hoặc operational normal PASS.

| Thuộc tính | Giá trị |
|---|---|
| Run ID | `pulse-projected-ml-c1-20261003T031200Z` |
| Parent START thực tế | **10:13:29 ICT**, không dùng timestamp run ID thay start |
| Duration | **900 giây/node**; các node khởi động lần lượt |
| Orchestrator | User systemd unit `.234`: `sentinel-pulse-projected-ml-canary-20261003.service` |
| Evidence VM | `/home/dat/sentinel-pulse-evidence/projected-ml/pulse-projected-ml-c1-20261003T031200Z/` |
| Source orchestrator readonly | `/home/dat/eBPF-project-projected-ml-canary-20261003` |
| Mode | Normal-only, audit-only, không injection, không auto-promote |
| Model/policy | R10-C1 frozen; không train lại hoặc sửa theo canary |

Ba checkpoint bất đồng bộ ghi **4.556 / 3.147 / 1.469 decision** trên
worker1/3/4, tổng **9.172**, 0 alert, 0 detector restart. Đây là snapshot giữa
run, chưa có normal-PASS, recall hoặc false-positive-rate claim.
Feature tails valid, cumulative hard counters/cadence violation 0.
Receipt ở [validation-evidence/projected-ml-c1-20261003](../../validation-evidence/projected-ml-c1-20261003/PARENT_START_RECEIPT.json).

**Monitor update 10:21 ICT:** supervisor vẫn active, không FAILED/COMPLETE.
Ba snapshot 10:20:53–10:20:57 ghi **17.663 / 16.378 / 15.277 decision**, tổng
**49.318**, 0 alert trên từng node; finalizers đang chờ collector kết thúc.
[Supervisor receipt](../../validation-evidence/projected-ml-c1-20261003/SUPERVISOR_CHECKPOINT_20261003.json)
không thay các receipt start lịch sử. Chưa có terminal PASS.

## 2. Thay đổi triển khai, không thay mô hình

Collector projected đã qua ba safety canary: 117.412 row, observed union 21
workload/container key, duration/source/raw hash và node coverage đều đạt.
Chi tiết ở [PROJECTED_COUNTER_CANARY.md](PROJECTED_COUNTER_CANARY.md).

Đường ML canary mới dùng:

```text
sys_enter → primary projected BPF counters
          → per-CPU copy + derive histogram/total
          → 500 ms deltas + rolling feature 249 chiều
          → history 3 + current, per-workload/container ExtraTrees
          → conformal p-value + frozen semantic/temporal policy
          → audit decisions / alerts JSONL
```

`COLLECTOR_VARIANT=projected` là opt-in; mặc định installer vẫn `legacy`.
`select_projected_collector.py` quét lại raw safety capture, kiểm tra source/
artifact hashes và duration; expectation lấy start metadata giao với manifest
frozen. Selector còn yêu cầu live node coverage không đổi và workload revision
nằm trong tập approve của manifest trước khi cài collector experiment.

Binary/object projected được copy readonly theo run ID vào:

```text
/opt/sentinel-pulse/experiments/pulse-projected-ml-c1-20261003T031200Z/
```

Không ghi đè loader/object của control collector tại `/opt/sentinel-pulse/bin`.
Checksum trước/sau được đối chiếu trên cả ba worker:

```text
control loader: 7e9821e735acb4209c8959e652de8394d341798f3f0c39dc962d293c402616bf
control object: b4e3d2f85c3bc6b32a681d777105478f2f42a203116bf3ff306050a4b9291ccf
```

Control collector và resolver vẫn active. Installer có đồng bộ Python runtime
package như workflow candidate hiện hữu; không có nghĩa toàn bộ `/opt` giữ
nguyên byte. Collector chuẩn đang chạy không bị restart trong checkpoint này.
Hai collector đồng thời cũng không phải cấu hình A/B overhead cuối cùng.

## 3. Bundle, tests và provenance

Model manifest SHA-256:
`6ddf7cf9b03cb783b82c23272f7046bafa7ab1412b0545b60a2821d1f441cc21`.

Policy SHA-256:
`602165bd48d81f549d3bfb65e5bdb319a11252678cbf484d739afcf2e5bc8143`.

21 model đã verify đủ artifacts trước rollout. Không mở blind attack set.
Parent START và worker START bind variant, paths, loader/object/unit hashes;
plan per-worker được hash trong START_SHA256SUMS. Source snapshot riêng
readonly; đây là frozen bytes cho non-formal canary, không mô tả dirty repo
main là một clean Git release.

Regression main source: **375 passed, 20 subtests passed** trên host
(24,92 s) và VM (35,49 s). Tests mới kiểm tra selection từ safety capture,
revision/coverage drift, tampered manifest, private binary paths và legacy
default. Bash syntax và `git diff --check` đạt. Source của run đã mở không bị
chỉnh tiếp trong khi đang đánh giá.

Code chính thay đổi:

- `sentinel_pulse/select_projected_collector.py`.
- `sentinel_pulse/install_500ms_experiment.sh`.
- `sentinel_pulse/start_bounded_live_canary.sh`.
- `sentinel_pulse/systemd/sentinel-pulse-collector-500ms-experiment.service`.
- `tests/test_sentinel_pulse_projected_canary_review.py`.

## 4. Kết thúc tự động và giới hạn latency

Worker START lần lượt khoảng **10:13:39 / 10:14:13 / 10:14:49 ICT**.
Deadline thu dự kiến **10:28:39 / 10:29:13 / 10:29:49**, rồi finalizer quét
capture, dừng candidate, tạo checksums và orchestrator collect/aggregate.
Nhắc kiểm tra **10:35 ICT ngày 03/10** để đủ thời gian archive; đó là ETA,
không cam kết canary pass. Nếu có alert/failure/coverage rejection, supervisor
archive và giữ rejection, không tự tăng threshold hoặc mở blind.

Không cần giữ terminal SSH hoặc agent chat theo dõi: systemd trên VM/worker
chạy lifecycle độc lập. Sau finalizer, phải đọc kết quả terminal, verified
checksums, coverage 21 key, restart count, normal/suppressed/alert distribution
và timing. Không dùng riêng checkpoint 0 alert để suy ra FPR=0.

`alerted_at` legacy được ghi **sau model inference, trước policy/output**.
Timing aggregate `window_start → decision` không phải kernel-to-alert đầy đủ.
Lượt này không inject attack; chưa đo recall hoặc attack-to-alert/kernel-to-alert
p99. Muốn claim 1–2 s phải có paired event/injection/output timing trong
evaluation độc lập, sau khi normal/operational gates đạt.

## 5. Bước tiếp theo

1. Đọc và giữ nguyên terminal/disposition ML canary này, kể cả fail.
2. Nếu đạt, đăng ký operational soak **mới** với source/model/policy/variant
   được bind; không resume R10-C3 bị loại.
3. Sau normal gate, đánh giá blind độc lập và A/B overhead. Không tune bằng
   blind outcomes hoặc hợp thức hóa collector canary thành ML performance.
