# Sentinel Pulse: Redis Sentinel alert và telemetry gap — 04/10/2026

Tất cả thời gian dùng ICT (UTC+7). Số liệu lấy từ archive SSH và observer
thật. Chưa adjudicate ground truth bằng process-level evidence.

## 1. Terminal canary C2

Run `pulse-projected-pressure-c2-20261003T163700Z`, source ML `5cac5cd`.
START **23:37:48,534 ngày03/10**, FAILED_SUMMARY **00:02:31,269 ngày04/10**.
Recovery **không bật**, không inject attack.

| Node | Decision archive | Alert | Terminal |
|---|---:|---:|---|
| worker1 `.237` | 60.386 | 0 | complete |
| worker3 `.239` | 59.499 | 0 | complete |
| worker4 `.238` | 59.149 | 1 | failed_gate |
| Tổng | 179.034 | 1 | rejected_normal_gate |

`failure_class=normal_alert_observed`, `valid_zero_alert_gate=false`.
Không promote candidate. Decision bao gồm nhiều status, **không phải mẫu số
để tính FPR/precision**. Không claim false-positive0%.

Collector worker4: gap **13,208959103 s**, availability terminal
**0,990699405 <0,999**, validation fail. Worker1/worker3 capture valid,
availability1. Hard integrity counters cả ba node0. **Giữ alert và verdict**,
không đổi thành infrastructure-only failure hoặc dùng run này train/tune.

## 2. Timeline raw evidence trên Redis Sentinel

| Window end ICT04/10 | Cadence | Detector cũ | Chi tiết |
|---|---:|---|---|
| 00:01:16,302981 | 0,511865 s | normal | Emit00:01:29,696869, backlog13,394 s |
| 00:01:29,511940 | 13,208959 s | warming / temporal_gap | Raw window dài được giữ |
| 00:01:30,089623 | 0,577683 s | warming / history_fill | Chưa đủ history |
| 00:01:30,602479 | 0,512855 s | warming / history_fill | Chưa đủ history |
| 00:01:31,111563 | 0,509084 s | suppressed | Raw anomaly, identity confirmation1 |
| 00:01:31,624199 | 0,512636 s | alert | Identity confirmation2 |

`alerted_at`=**00:01:32,589548**. Đây là timestamp detector ghi, **không phải
phép đo kernel-to-alert/delivery của attack**. Score0,583646195,
conformal p0,000187336081, calibration max0,547876733,
score excess0,035769461 >minimum0,01. Inference riêng row **19,108 ms**.
Security mass40; identity observed25, normal envelope19, excess6 >minimum4.

Detector cũ đã lấp lại ML history nhanh nhưng rolling context/backlog vẫn
cần kiểm tra. Timeline chứng minh **alert đi sau gap**, không chứng minh gap
là nguyên nhân duy nhất. Không sửa ngưỡng trên validation run này.

## 3. Observer độc lập đã hoàn tất

Run `pulse-pressure-observer-c2-20261003T163600Z`, không còn chờ01:46.

| Node | Sample thật | Late sample | Max monotonic interval | Clock offset change | Kết thúc ICT |
|---|---:|---:|---:|---:|---|
| worker1 `.237` | 7.772 | 0 | 1,179337 s | 0 | 01:46:14 |
| worker3 `.239` | 7.774 | 0 | 1,028641 s | 0 | 01:46:16 |
| worker4 `.238` | 7.709 | 8 | 24,076896 s | 0 | 01:47:29 |

Trong incident ML, worker4 sample bị ngắt **13,643161357 s** từ
00:01:15,757380 đến00:01:29,400542. Realtime–monotonic chênh khoảng
0,000000655 s, không vượt ngưỡng offset-change.
Collector-experiment memory.events high/max/OOM0; memory.current khoảng149 MB,
dưới MemoryHigh512 MiB. CPU nr_throttled2→105,
throttled_usec2.786.308→17.052.093 µs. Node CPU PSI some avg10
12,87→49,96, I/O some avg10 0→6,89.

Đây là pressure/scheduling **tương quan**, chưa đủ để quy kết CPUQuota,
hypervisor pause hoặc storage là RCA. Không đổi quota/RAM/Longhorn dựa riêng
trên tương quan này.

## 4. Redis probes và giới hạn attribution

Pod `aims-redis-sentinel-sentinel-1`, UID
`fe856cbd-3a87-4201-9635-0af4c0153ac9`, image
`quay.io/opstree/redis-sentinel:v8.2.1` trên`.238`: API cho thấy Ready/Running,
restart0. Liveness/readiness đều exec `sh -ec` gọi `redis-cli ... ping`,
period10 s, timeout1 s. UID1000, drop ALL capabilities, không allowPrivilegeEscalation.

Probe exec là giả thuyết hợp lý cho burst normal sau stall, **chưa chứng minh**.
Exact counts không cho PID/parent/argv hoặc syscall return value; setuid count
không có nghĩa successful privilege escalation. Không log password/env,
không whitelist toàn bộ identity-transition của Redis. Cần Tetragon/process
lineage hoặc CRI/kubelet evidence đúng timestamp để adjudicate alert.

## 5. Những phần code đã triển khai tiếp

Giữ21 model frozen,249 feature, calibration và semantic policy:

- `recovery_deployment.py`: bind JSON bytes/canonical hash với collector START
  và detector; render unit dùng đúng private profile path.
- Detector recovery luôn `--from-start`, không bỏ journal outage.
- Installer từ chối profile không khớp cadence/availability/gap và collector/
  detector khác protocol. Default legacy không đổi.
- Starter/finalizer legacy từ chối recovery: không tạo NORMAL_PASS bằng
  evaluator cũ.
- `run_recovery_runtime_smoke.sh`, `evaluate_recovery_smoke.py`: diagnostic
  hữu hạn một worker, giữ mọi alert, kiểm tra journal/rolling/identity,
  không có quyền formal PASS, accuracy claim, blind hay promote.
- Regression dùng timestamp incident thật nhưng **count synthetic** để kiểm
  tra hai confirmation window vẫn warming và không inference. Đây không phải
  re-evaluation của candidate C2.

Smoke đầu `pulse-recovery-runtime-smoke-c1-20261004` dừng trước deploy do root
Git ownership check, chưa bật collector/model. Sửa bằng scoped
`git -c safe.directory=<source leaf>` từng invocation, không global trust;
lưu preregistration failure cho lượt mới, dùng source/run ID mới để retry.

Formal recovery lifecycle/exposure evaluator **chưa hoàn tất**. Smoke dù đạt
cũng không chứng minh24h normal soak, recall hay kernel-to-alert1–2 s.

Release retry`ef056f5742047781e46a761a8477e1f72e43c6a7` đã test host/VM:
**459 test +20 subtest đạt**. Runtime smoke C2 trên worker4 đã terminal
10:56:48 ICT,26.648 decision,19 workload scored,0 alert,17+3 checksum khớp.
Không có incident recovery. Audit phát hiện backlog startup: toàn run đầu
window→sau model p9912,551 s; sau120 s đầu còn1,907 s, max2,457 s, vẫn156
row>2 s. Không kernel-to-alert. Model/policy giữ nguyên; thêm processing-age
gate opt-in trong run/source mới, không đổi verdict C2 cũ. Receipt:
[`recovery deployment`](../../validation-evidence/recovery-deploy-dev-20261004/RECEIPT.json).
[Status formal và terminal smoke](../../PULSE_RECOVERY_LIFECYCLE_STATUS_20261004.md).

## 6. Evidence và checksum

VM control plane:
`/home/dat/sentinel-pulse-evidence/projected-pressure/pulse-projected-pressure-c2-20261003T163700Z`.
Host: [`validation-evidence/projected-pressure-c2-20261003`](../../validation-evidence/projected-pressure-c2-20261003).
Alert bytes SHA-256:
`c2c12c53e35f7d3bf4d03a5cbe54439b3dbde8f457644bcd260d194137050caf`.

START10/10, FAILED_FINAL77/77 kiểm tra trên VM đạt. Observer23/23 checksum/node
đạt trên từng worker, kernel/runtime journal exit0. Host giữ metadata/alert;
full feature/decision và observer raw còn trên VM. Bulk observer transfer về
host đã dừng để không chiếm VPN; không claim host đã verify toàn bộ raw.
