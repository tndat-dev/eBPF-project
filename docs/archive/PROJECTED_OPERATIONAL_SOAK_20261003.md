# Sentinel Pulse — operational soak với projected counters, 03/10/2026

**Checkpoint04/10:** diagnostic ML pressure C2 reject00:02:31 ICT,179.034
decision/1 alert Redis Sentinel trên worker4. Capture gap13,209 s đi trước
alert và availability0,990699. Giữ alert/verdict, không infrastructure-excuse.
Observer cả3 đã terminal01:46–01:47 và23/23 checksum/node khớp. Worker recovery
deploy và smoke evaluator đã bổ sung, formal recovery lifecycle chưa hoàn tất.
Lịch chờ02:10 dưới đây là lịch sử.
[Incident report](PULSE_PRESSURE_C2_INCIDENT_20261004.md).

**Checkpoint tiếp theo khoảng23:40 ICT03/10:** diagnostic pressure C1 đã
reject, không còn là job chờ đến02:00. Terminal90.343 decision/0 alert,
worker4 gap16,485 s, availability0,976314, hard counters0; supervisor trước
đó gặp SSH unreachable. Observer C1 failed126, nên chưa có clock/PSI evidence
để kết luận nguyên nhân pause. Launcher đã sửa; observer C2 ready3/3 từ23:36
và ML C2 START23:37:48, duration7200 s. Nhắc kiểm tra **02:10 ICT04/10**.
Recovery core riêng `936d3df` đã test435 +20 subtest host/VM nhưng chưa nối
vào formal lifecycle và không bật trên ML C2. Không đổi verdict/model/policy
run này. [Recovery report](../../PULSE_TELEMETRY_RECOVERY.md).

**Terminal kiểm tra qua SSH lúc khoảng 23:10–23:18 ICT ngày 03/10:** run
đã **infrastructure-reject lúc 20:13:34**, archive hoàn tất **20:28:04**.
START thật **12:05:14 ICT**, thu khoảng **8 giờ 8 phút** trước rejection;
không còn ACTIVE và không có OPERATIONAL_PASS. START checksum 5/5 và archive
`RAW_SHA256SUMS` **52/52** được kiểm tra lại thành công.

Failure receipt ghi worker3 `.239` có max snapshot gap **14,030071 s**, vượt
contract 10 s; availability tại fail 0,999169 vẫn đạt 0,999. Các counter
consistency retry exhausted, projection fail, total mismatch, target gap và
insert/task failures đều **0**. Vì vậy đây là **cadence/telemetry rejection**,
không phải collector consistency regression hoặc model alert gate fail.

Snapshot monitor cuối bất đồng bộ: **3.806.735 decision, 0 alert, 0 restart**;
không phải terminal ML evaluation và không được dùng để train/tune, claim
FPR/recall hoặc hợp thức hóa soak PASS. Full worker3 capture validation ghi
1.270.207 row, max snapshot-read 11,816 s, max ingest lag 21,493 s.
[Failure evidence](../../validation-evidence/projected-operational-c1-20261003/FAILURE_FEATURE_TAIL.stdout)
và [disposition](../../validation-evidence/projected-operational-c1-20261003/infrastructure-failure/DISPOSITION.json).
Host giữ metadata; raw tar archives đầy đủ vẫn ở VM, không xóa.

Kernel worker3 lúc **20:12:57** ghi iSCSI ping timeout, **20:12:59** device
reset; health monitor ghi Longhorn degraded-but-attached cùng giai đoạn.
Đây là tương quan, **chưa đủ chứng minh nguyên nhân stall**. Service memory
peak 537.137.152 byte sát MemoryHigh 512 MiB; không có memory.events/PSI theo
service của lượt cũ để xác nhận direct reclaim. Không đổi memory limit, không
đổi model/policy hoặc nới gap budget dựa trên suy đoán.

Cụm kiểm tra lại: 6/6 node Ready không pressure, 67/67 production pod Ready,
29/29 Longhorn healthy. Control collectors đã phục hồi. Bổ sung observer
read-only cho service cgroup CPU/memory/I/O PSI, memory.events, memory.stat và
clock deltas; lượt tiếp theo là diagnostic canary riêng, không resume run fail.

Phần preflight và kế hoạch finalize phía dưới là lịch sử của lượt đã bị loại.

**Diagnostic C1 lịch sử, đã reject:** parent START 23:16:45 ICT03/10, run
`pulse-projected-pressure-c1-20261003T162000Z` đăng ký7.200 s/node, cùng
model/policy frozen. Observer dự kiến7.800 s nhưng **failed exit126 trước
khi thu sample**; nhận định “observer đang chạy” ở checkpoint cũ không đúng.
Source riêng
`/home/dat/eBPF-project-pressure-diagnostic-20261003`, commit
`5cac5cd81f8501d15e292a0aca4c6b1cd29925f6`, đã fetch về host branch
`runtime/pressure-diagnostic-20261003`. Regression 399 test +20 subtest đạt
(host 18,78 s; release VM 38,21 s). Không đổi MemoryHigh/Max, CPUQuota hay
gap budget; đây là diagnostic non-formal, không phải soak thay thế đã PASS.
Unit parent: `sentinel-pulse-projected-pressure-canary-20261003.service`;
unit root observer từng worker: `sentinel-pulse-pressure-diagnostic-20261003.service`.
Evidence parent ở `/home/dat/sentinel-pulse-evidence/projected-pressure/`
cùng run ID. C1 đã archive FAILED_COMPLETE lúc23:30; **hủy lịch chờ02:00**
của C1. Lượt C2 mới START23:37:48, active3/3 worker và START checksum10/10
kiểm tra lại23:41. Observer C2 có sample/sar thật, dự kiến xong01:46 ICT04/10;
nhắc kiểm tra terminal C2 khoảng02:10. Không tự mở blind hoặc promote.

## 1. Trạng thái và mục đích

Lifecycle khởi động lúc **11:58:45 ICT ngày 03/10/2026**, run
`pulse-projected-operational-c1-20261003T050000Z`. Run ID không thay thế thời
điểm START. Checkpoint 12:00 đang ở preflight; **chưa có operational PASS**.

Lượt này đánh giá độ ổn định vận hành dài hạn của cùng bundle R10-C1 sau khi
projected collector đã qua safety canary 3/3 worker và ML canary normal-only.
Không train lại, không tăng threshold theo test, không mở blind attack và
không auto-promote. Run R10-C3 cũ vẫn giữ disposition infrastructure-reject.

## 2. Kết quả đủ điều kiện mở lượt mới

ML canary trước đó có aggregate valid: **114.984 decision**, 21/21 workload/
container, **0 alert, 0 restart**; START 10/10 và FINAL 76/76 checksum đã kiểm
tra lại. Inference p99 30,092 ms. Window-start → timestamp sau model p99
1,053 s, max 1,376 s, **chưa bao gồm policy/output, chưa phải kernel-to-alert**.
Xem [canary report](PROJECTED_ML_CANARY_20261003.md).

AIMS traffic preflight của lượt mới exit 0: 10/10 Rollout Healthy, mỗi service
HTTP 200 **20/20**; ba ingress path `/`, `/api/health/`,
`/api/products/?page=1` đều thành công **20/20**, 0 failure. Đây là smoke
traffic/readiness check, không phải benchmark throughput hoặc chứng minh
website production hoàn chỉnh. Các loadgen hiện có tiếp tục chạy.

## 3. Source và model đóng băng

| Thành phần | Định danh |
|---|---|
| Git source release | `4c2948f817bb0d856b8b4cb34b5267563af15cdd` |
| Repo source riêng trên VM .234 | `/home/dat/eBPF-project-projected-operational-20261003` |
| Source stage trên worker | `/home/dat/pulse-projected-operational-20261003` |
| Git branch đã fetch về host, không checkout | `runtime/projected-operational-20261003` |
| Evidence VM | `/home/dat/sentinel-pulse-evidence/operational-projected/pulse-projected-operational-c1-20261003T050000Z` |
| Lifecycle user unit | `sentinel-pulse-projected-operational-20261003.service` |
| External supervisor user unit | `sentinel-pulse-projected-operational-supervisor-20261003.service` |

Regression: **395 test + 20 subtest đạt** trên host (18,94 s) và release VM
(37,07 s); Bash syntax và `git diff --check` đạt. Không commit/reset các file
báo cáo bị xóa hoặc thay đổi ngoài scope trong main worktree của người dùng.
Main host/VM có đồng bộ các code thay đổi; Git release riêng là source chạy soak.

```text
model manifest SHA256:
6ddf7cf9b03cb783b82c23272f7046bafa7ab1412b0545b60a2821d1f441cc21
policy SHA256:
602165bd48d81f549d3bfb65e5bdb319a11252678cbf484d739afcf2e5bc8143
projected collector plan SHA256:
59550971f129899384599d692519e842bfc1e1189a54411498a085a99408e002
```

Model gồm 21 per-workload/container ExtraTrees, window 500 ms, history 3,
feature schema 249, conformal alpha 0,001; semantic/temporal policy frozen.
Projected counters bỏ các cập nhật bản đếm dư thừa trong collector, không đổi
feature/model. “Exact” nghĩa không sample syscall tại điểm đếm, **không** có
nghĩa snapshot atomic across CPU, toàn bộ transition và mọi timestamp.

## 4. Guard triển khai mới

1. Verify đủ model artifacts và plan khớp model/policy SHA trước mutation.
2. Mỗi worker revalidate raw safety capture, duration/coverage/source/binary
   SHA và live workload revisions.
3. Preregister collector contract trong `SOAK_START.json`: variant projected,
   plan SHA, verified artifacts từng worker, unit SHA và remote source root.
4. Installer dùng binary/object readonly riêng theo run, không ghi đè
   `/opt/sentinel-pulse/bin` của control collector. Control collector tạm dừng
   có ghi suspended-host list để tránh hai collector cùng đo trong soak.
5. Worker marker khớp checksum parent; env/path/loader/object/unit được kiểm
   tra ngay sau install và mỗi monitor poll. Resume đổi variant/plan bị từ chối.
6. Finalizer dùng source root đã đăng ký; kiểm tra provenance trước khi dừng
   candidate và export. Failure giữ evidence, dừng experiment, phục hồi control.

## 5. Tiêu chuẩn vận hành không bị thay đổi

Profile: [operational-soak-v1.json](../../sentinel_pulse/protocol/operational-soak-v1.json).
Collector đăng ký tối đa **90.000 giây (25 giờ)**; mỗi key cần **24 giờ scored
exposure hợp lệ**. Telemetry availability ≥0,999, max single gap ≤10 s; integrity,
identity/revision, non-finite vector, restart và worker pressure vẫn fail closed.
Dependency degraded-but-attached có recovery/exclusion budget đã đăng ký;
không giấu alert trong degraded interval. Xem
[operational runbook](../../OPERATIONAL_SOAK_RUNBOOK.md).

Alert budget: fleet ≤0,01 alert/workload-hour, từng key ≤0,05. **Không buộc
quan sát 0 alert mới đạt**, nhưng các alert vẫn được giữ và cần adjudication;
không tự gọi mọi alert là false positive hay tự công bố FPR=0.

Capacity mới: min available byte **0**, max root used **85%**, maintenance
guard masked. Worker3 còn khoảng 119 GB lúc preflight, used 81%. Ngoại suy
canary feature+decision khoảng 17 GB/node/25 h; tăng storage khác có thể làm
run dừng theo capacity guard. Không nới ngưỡng marker cũ, không xóa Longhorn
hoặc evidence để che lỗi.

## 6. Theo dõi và bước sau

Các unit systemd chạy độc lập với phiên SSH/chat. Xem trạng thái trên .234:

```bash
systemctl --user status sentinel-pulse-projected-operational-20261003.service
systemctl --user status sentinel-pulse-projected-operational-supervisor-20261003.service
journalctl --user -u sentinel-pulse-projected-operational-20261003.service -n 30 --no-pager
```

Thời điểm finalize phải lấy `eligible_finalize_after` của marker thật cộng
margin 300 s; chưa dùng giờ khởi động lifecycle để tính 24 giờ exposure.
Sau đủ thời gian, lifecycle tự freeze/export/evaluate; cần kiểm tra
`OPERATIONAL_REPORT.json`, telemetry report và checksum, không chỉ file ACTIVE.
`OPERATIONAL_PASS` không tự mở legacy blind interlock. Bước tiếp theo vẫn là
blind attack độc lập với paired kernel/injection → alert-output timestamp,
recall/precision/latency CDF và A/B overhead; chưa có kết quả cho các claim này.
