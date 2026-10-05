# Sentinel Pulse — trạng thái formal recovery lifecycle

## Trạng thái hiện hành

Cập nhật ngày **05/10/2026**, theo SSH và receipt có checksum. Chỉ sửa mục
hiện hành; giữ riêng evidence và verdict cũ, không nối thêm checkpoint lịch sử.

**Đang chạy ngầm:** formal recovery soak `pulse-recovery-formal-c1-20261005`,
đăng ký **09:06:19 ICT**, **89.880 s/node** (24 giờ58 phút), `diagnostic_only=false`.
Coordinator/systemd trên master234; ba worker237/238/239 đã active, tail ready,
detector restart0, health không degraded tại receipt START. Scope16/19/15 key,
union **21/21 model key**; không suy thành50 workload độc lập.
Chưa có terminal hoặc formal PASS; startup unavailable không tính normal.

Runtime source vẫn **`1c03987`**, 21 model ExtraTrees, feature249, cadence500ms,
history3, alpha0,001 và policy frozen **không đổi**. Crash/resume cùng marker
và single-writer theo run đã kiểm chứng trước đó, không restage run terminal.

Thêm **guard dung lượng riêng**, source SHA`bc5c3ea6…`, không sửa coordinator
frozen hoặc gate đánh giá: preregister trước launch, bind marker thật, probe
hai filesystem/3 worker mỗi30 s. Budget mới available>0/used<90%, unknown≤60 s;
không reserve cố định64 GiB, không xóa dữ liệu, không sửa marker cũ max85%.
Nếu vượt, chỉ dừng coordinator child đang sở hữu; guard không cấp formal PASS.

**Đã đo:** diagnostic dùng guard `pulse-recovery-capacity-diagnostic-c1-20261005`,
180 s/node, terminal **09:04:50 ICT**: integrity gate đạt, node report3/3 valid,
seal coordinator12/12 +guard4/4 khớp. **23.413 decision /19.812 scored /0 alert**;
giữ433 suppressed,2.791 telemetry-degraded,810 warming. Union valid exposure
**0,93272273 workload-hour**, không đủ24h/key; 0 alert không chứng minh FPR=0.
Regression main+guard: subset168/168 host/VM; full host892 passed/7skip/+20subtest,
VM933 passed/+20subtest; số khác do dependency tùy chọn.

**Kỳ vọng, chưa đo:** kernel-to-alert1–2 s. Formal đang chạy là normal exposure,
không blind attack/recall/precision/kernel-to-alert. Không tự mở blind/promote,
không chỉnh model/policy theo holdout. Có thể nhắc tiếp tục khoảng
**10:40 ICT ngày06/10/2026** để kiểm tra terminal và scored exposure thật; đây
là lịch dự kiến có slack finalization, không đảm bảo PASS.

[Toàn bộ luồng và ví dụ log thật](SENTINEL_PULSE_LUONG_VA_MINH_CHUNG.md),
[receipt START formal](validation-evidence/recovery-formal-c1-20261005/START_REMOTE_RECEIPT.json),
[terminal diagnostic guard](validation-evidence/recovery-capacity-c1-20261005/TERMINAL_REMOTE_RECEIPT.json),
[test receipt](validation-evidence/recovery-capacity-c1-20261005/TEST_RECEIPT.json),
[checksum raw đã SSH đọc lại](validation-evidence/recovery-resume-c1-20261005/SOURCE_RECHECK.json).
## Cơ sở timing anchor đã kiểm chứng bằng diagnostic C2

C1 terminal **22:26:48,259 ICT**, exit1 ở coordinator: cả ba worker đã exit0
nhưng evaluator báo `decision outside registered capture interval`.
Receipt `START.json` được ghi **trước** `systemctl start`; timeout600 s tính từ
process thật, trong khi evaluator tính giới hạn cuối từ receipt setup+601 s.
Raw chứng minh có107/137/87 row ở worker237/238/239 vượt giới hạn setup này.
**Không sửa/replay bằng source mới để biến C1 thành PASS.**

Audit readonly trên raw đã seal: **18/18 checksum mỗi node đạt**, tổng
**78.064 decision/75.258 scored/0 alert**, giữ2.356 degraded/450 warming,
union21/21 key. p99 đầu window→sau policy theo237/238/239:
**1,254/1,331/1,276 s**, conditional trên fresh scored row, trước output flush.
Đây là audit của một run bị reject, không formal precision/recall/kernel-to-alert.
Unit experiment/detector inactive, control/resolver active,0 restart.
Timestamp systemd hiện tại đã reset sau khi unit inactive; không giả nhận
posthoc đó là start receipt hợp lệ. Các stream và verdict C1 giữ nguyên.

[Terminal coordinator C1](validation-evidence/recovery-fleet-diagnostic-c1-20261004/TERMINAL_REMOTE_RECEIPT.json),
[audit237](validation-evidence/recovery-fleet-diagnostic-c1-20261004/TERMINAL_WORKER_AUDIT_10.1.16.237.json),
[audit238](validation-evidence/recovery-fleet-diagnostic-c1-20261004/TERMINAL_WORKER_AUDIT_10.1.16.238.json),
[audit239](validation-evidence/recovery-fleet-diagnostic-c1-20261004/TERMINAL_WORKER_AUDIT_10.1.16.239.json).

Bản timing-anchor đã kiểm chứng **`c6631f36228944db0b012c1e3cb111db17878643`**, source riêng
`/home/dat/eBPF-project-recovery-coordinator-r2-20261004` trên master và ba
worker. **Không thay model, alpha, calibration, semantic policy hoặc vector249.**

- Marker mới bind `collector_timing_contract`. Worker ghi immutable
  `COLLECTOR_RUNTIME_START.json` khi service còn active: PID, InvocationID,
  ExecMainStartTimestampMonotonic, clock pair và SHA marker/collector setup.
  Evaluator replay clock pair, kiểm tra startup≤120 s và bind input SHA.
- Upper bound vẫn actual service start+duration+**1 s**; minimum-duration
  slack vẫn **2 s**. Không tăng tolerance, không cho pre-execution rows và
  không dùng duration ngắn để tạo PASS. Clock pair phải trong50 ms.
- Transition detector đã stop nhưng parent đang seal được ghi bounded
  unknown **chỉ khi** collector exit sạch, đủ duration,0 restart và đúng
  ownership/runtime. Không coi crash/startup failure là cleanup hợp lệ.
- Không mint success nếu coordinator bị interrupt giữa finalization. Cleanup
  nhận terminal ownership receipt đã đóng, không báo lỗi stop một transient
  unit đã được systemd unload, không chạm run khác/control/pod.

Regression release mới: host **851 passed,7 skipped,20 subtest/25,32 s**;
VM **892 passed,20 subtest/69,16 s**; subset formal/coordinator/deployment
**127/127** cả hai. Khác full count do dependency tùy chọn. Test timing có
setup delay3,9 s, từ chối missing/changed receipt/clock/identity và dữ liệu
trước actual execution. Bằng chứng synthetic được tách khỏi live receipts.

Diagnostic C2 **`pulse-recovery-fleet-diagnostic-c2-20261004`** đăng ký
**22:39:11,132 ICT**, **180 s/node**, diagnostic-only; same frozen bundle/policy,
scope16/19/15 và union21/21. Terminal **22:42:45,651 ICT**: coordinator exit0,
restart0; `diagnostic_integrity_gate=true`, không có lý do reject.
Marker SHA `b4376fafff20a9d7a8f9f261533c24220a086f523709f0b3a713445d8217213c`.
[Receipt đăng ký C2](validation-evidence/recovery-fleet-diagnostic-c2-20261004/START_REMOTE_RECEIPT.json),
[receipt terminal/report C2](validation-evidence/recovery-fleet-diagnostic-c2-20261004/TERMINAL_REMOTE_RECEIPT.json).

Aggregate giữ **0 alert**, tổng **0,9410136189063389 valid workload-hour**,
21/21 key. Mỗi key khoảng 156–162 giây scored hợp lệ; `exposure_gate=false`
cho tất cả key vì chưa đạt 24 giờ/key. Đây là union exposure, không cộng trùng
replica. `formal_recovery_pass=false`, `legacy_normal_pass=false`,
`false_positive_ground_truth_adjudicated=false`,
`kernel_to_alert_claim_allowed=false`. Không suy ra FPR=0 hoặc recall.

Unit `sentinel-pulse-recovery-fleet-c2-20261004.service` đã inactive; raw/receipt
paths như C1 nhưng run ID là C2. Job tự dừng/finalize, không mở blind/formal24h
hoặc promote tự động. Còn cần kiểm thử failure/resume live và formal scored
exposure. Chưa có run formal24h mới được khởi chạy.

## Checkpoint lịch sử: coordinator ba worker — diagnostic C1

Source frozen **`dd872e706fdae6da50bd3cb551c92278397bbc34`**, branch
`runtime/recovery-coordinator-20261004`, checkout riêng trên master1 và cả ba
worker: `/home/dat/eBPF-project-recovery-coordinator-20261004`.
Host fetch Git ref riêng, không checkout/reset worktree chính hoặc push GitHub.
Model manifest `6ddf7cf9…`, policy `602165bd…`, recovery/freshness contract
không đổi. Không dùng policy mặc định trong source thay artifact đã đóng băng.

Run **`pulse-recovery-fleet-diagnostic-c1-20261004`**, preregistration
**22:16:03,011 ICT**, duration **600 s/node**, `diagnostic_only=true`.
Marker SHA-256:
`113a29a8b0c41dcfbf134b6fd34158f2bee7b00ff3e8d8080f50f9d57515f7e1`.

| Worker IP | Node | Scope workload-container đã bind | Checkpoint 22:17 |
|---|---|---:|---|
| 10.1.16.237 | k8s-worker1.local | 16 key | active, tail ready, restart 0 |
| 10.1.16.238 | k8s-worker4.local | 19 key | active, tail ready, restart 0 |
| 10.1.16.239 | k8s-worker3.local | 15 key | active, tail ready, restart 0 |

Union **21/21 key**, không cộng 16+19+15 thành 50 workload độc lập. Các BPF
object có checksum theo từng worker; worker1 khác worker3/4 nhưng từng artifact
đã qua safety review và được bind riêng, không giả định mọi binary giống nhau.

Luồng triển khai mới:

1. Preflight read-only: Git clean/source SHA, toàn bundle/policy, safety canary,
   scope/revision cgroup, control services, dependency health.
2. Marker immutable mới trên coordinator; truyền **đúng bytes** tới worker,
   kiểm tra lại identity rồi chạy parent systemd riêng cho run.
3. Worker attest → private collector → freshness-bound detector. Startup đang
   cài đặt được ghi `unavailable`, không coi là normal; budget 120 s.
4. Parallel SSH và sáu API query mỗi cycle ~10 s, timeout SSH 12 s/API 10 s;
   giữ supervisor gap ≤30 s, không dùng đường health tuần tự 6×20 s.
5. Ghi health/supervision journal có fsync và API response gzip phục vụ RCA.
   Unknown API là transient/excluded theo budget đã có, không fake healthy;
   known runtime integrity failure reject ngay. Mọi alert được giữ nguyên.
6. Khi ba worker terminal sạch: verify worker seals, gửi cùng final health
   journal, streaming `evaluate_node`, aggregate ba report và seal coordinator.
   Reject/interruption chỉ stop parent chứng minh thuộc run, không stop control
   collector/resolver hoặc pod production.

Coordinator unit trên master:
`sentinel-pulse-recovery-fleet-c1-20261004.service`.
Evidence coordinator tại
`/home/dat/sentinel-pulse-recovery-coordinator-runs/pulse-recovery-fleet-diagnostic-c1-20261004`.
Raw worker tại `/var/lib/sentinel-pulse-500ms/runs/<run_id>`; preregistration và
node report tại `/var/lib/sentinel-pulse-recovery-formal/<run_id>`.
Credential là private file, không lưu trong config/marker/Git hoặc in stderr.

Host regression **832 passed, 7 skipped, 20 subtest/25,11 s**; VM
**873 passed, 20 subtest/94,18 s**, hai warning Torch deprecation. Khác count
vì host thiếu một số dependency tùy chọn, không phải cùng số test đã chạy.
Formal/coordinator subset **83/83** trên cả host và VM. Đây là test phần mềm;
không thay bằng chứng real-time hoặc recall của model.

Dự kiến xem terminal **22:30 ICT 04/10**. Diagnostic tự dừng/finalize, không
mở soak 24 giờ, blind attack hoặc promote model tự động. Trước formal cần
terminal replay/checksum ba node đạt và kiểm thử thêm resume/failure path live.
[START_REMOTE_RECEIPT.json](validation-evidence/recovery-fleet-diagnostic-c1-20261004/START_REMOTE_RECEIPT.json)
chứa marker/launch/live health thực lấy qua SSH; full raw chưa copy về host.

Code: [`recovery_coordinator.py`](sentinel_pulse/recovery_coordinator.py),
[`recovery_worker_probe.py`](sentinel_pulse/recovery_worker_probe.py),
[`test_sentinel_pulse_recovery_coordinator.py`](tests/test_sentinel_pulse_recovery_coordinator.py).

### Checkpoint model thực — 22:21:06–22:21:07 ICT

Đọc trực tiếp decision stream trên từng worker, chỉ đếm JSONL line hoàn chỉnh
và kiểm tra run identity. Không lấy số liệu từ dự đoán của code hoặc test mock.

| Worker | Decision đã đọc | Scored | Degraded | Warming | Alert | Đầu window→sau policy p99 |
|---|---:|---:|---:|---:|---:|---:|
| .237 | 12.208 | 11.393 | 743 | 72 | 0 | 1,282 s |
| .238 | 12.595 | 11.648 | 834 | 113 | 0 | 1,385 s |
| .239 | 12.260 | 11.353 | 764 | 143 | 0 | 1,290 s |

Tổng các checkpoint **37.063 decision/34.394 scored/0 alert**; ba mẫu được
đọc lệch nhau dưới1 s, không phải snapshot atomic cả cụm. Có2.341 degraded
và328 warming, không gộp thành normal hoặc scored exposure. Union scored keys
21/21. Collector START22:16:17,276 (.237),22:16:18,158 (.238),22:16:18,192
(.239); mọi parent/collector/detector/control/resolver active,0 restart.

Quantile nearest-rank chỉ trên row đã score và đủ mới; trước serialization/
output flush. **Không phải kernel-to-alert, không recall hoặc chứng minh FPR=0**.
Diagnostic chưa terminal; availability/scope/duration/consume/health/seals sẽ
được đánh giá lại toàn run, không chỉ dựa vào tail.

[Worker237](validation-evidence/recovery-fleet-diagnostic-c1-20261004/LIVE_WORKER_237.json),
[worker238](validation-evidence/recovery-fleet-diagnostic-c1-20261004/LIVE_WORKER_238.json),
[worker239](validation-evidence/recovery-fleet-diagnostic-c1-20261004/LIVE_WORKER_239.json).

Legacy formal launcher/finalizer vẫn **từ chối recovery profile**, tránh đổi
run cũ thành PASS bằng việc nới điều kiện. Không sửa model ExtraTrees frozen,
calibration, alpha hoặc semantic policy. Blind attack set vẫn đóng.

## Smoke C2: số liệu đã kiểm tra bằng SSH

Run `pulse-recovery-runtime-smoke-c2-20261004`, source `ef056f5742047781e46a761a8477e1f72e43c6a7`,
worker `10.1.16.238 / k8s-worker4.local`, duration đăng ký 600 giây.
Terminal **10:56:48 ICT**, exit 0; kiểm tra lại bằng SSH từ **11:03 ICT**.
Checksum 17 file evidence và 3 file preregistration đều khớp.

- 26.648 quyết định: 25.919 normal, 371 suppressed, 358 warming.
- 26.290 row thực sự inference trên **19 workload/container key** của node
  này, không phải toàn cụm đủ 21 key.
- 0 alert, 0 feature chưa được consume; availability snapshot 1,0.
- Maximum snapshot gap 0,519008 giây; hard integrity counters 0.
- **Không có incident recovery trong run này**: chưa chứng minh tự phục hồi
  sau outage thật, không chứng minh FPR=0 hay production stable.
- Sau run, detector candidate dừng/disabled, collector experiment dừng;
  collector control và `sentinel-pulse-resolver.service` vẫn active.
- Cụm kiểm tra cùng lượt: 6/6 node Ready v1.34.10, 67/67 pod production Ready.

Evidence: [receipt terminal](validation-evidence/recovery-runtime-smoke-c2-20261004/TERMINAL_REMOTE_RECEIPT.json).
Raw features/decisions giữ trên VM; **chưa copy toàn bộ raw về host**. Receipt
host ghi vị trí, checksum và report thực, không giả định có full raw local.

## Vấn đề latency thực sự phát hiện

| Phạm vi dữ liệu | Inference p99 | Đầu window → timestamp sau model p99 | Max |
|---|---:|---:|---:|
| Toàn bộ 26.290 scored row | 31,185 ms | 12,551 s | 13,239 s |
| Sau 120 giây startup đầu, 21.254 scored row | 31,227 ms | 1,907 s | 2,457 s |

Toàn run có 5.191 scored row vượt 2 giây theo phép đo đầu window → sau model;
phân đoạn sau startup vẫn có 156 row vượt 2 giây. Không được bỏ startup khỏi
verdict hoặc chỉ công bố con số đẹp. Phân đoạn 120 giây là diagnostic audit
sau run, không phải tiêu chuẩn acceptance đã đăng ký trước.

`alerted_at` trong source C2 được lấy **ngay sau model.predict, trước policy
và output flush**. Vì vậy các số trên **không phải kernel-to-alert**. Không
inject attack nên không có ground-truth detection latency/recall trong smoke.

Audit reproducible: [LATENCY_AUDIT.json](validation-evidence/recovery-runtime-smoke-c2-20261004/LATENCY_AUDIT.json)
và [`audit_recovery_smoke_latency.py`](sentinel_pulse/audit_recovery_smoke_latency.py).
Quantile dùng nearest rank `ceil(q*n)`, giữ SHA của ba raw input.

## Sửa gì trước formal run tiếp theo?

Capture có thể emit đúng lúc nhưng detector đọc file chậm hơn nhiều giây.
Profile capture cũ không kiểm tra **tuổi dữ liệu tại lúc detector xử lý**.
Vì vậy thêm contract riêng, opt-in `--live-freshness`:

1. Gate tuổi `checked_at - window_end` tại processing start, tối đa 1 giây.
2. Row cũ vẫn lưu journal/feature/decision nhưng trả `telemetry-degraded`,
   không inference và không được tính thành normal hoặc scored exposure.
3. Reset ML history và semantic/confirmation evidence riêng source; chỉ
   lấp lại history bằng window đủ mới. Không nối evidence qua blind spot.
4. Clock bất thường fail closed; terminal evaluator tự tính lại freshness,
   không tin cờ `eligible` do runtime ghi.
5. Preregister contract/hash trước deploy trong **run mới**; installer từ
   chối bật ngược trên run cũ. Legacy runtime/unit không tự bật gate mới.
6. Ghi thêm `decision_completed_at` sau policy, vẫn trước serialization và
   output flush. Không đổi tên phép đo này thành kernel-to-alert.

Đây là sửa luồng runtime, **không train/tune lại trên smoke hoặc blind set**.
Quarantine có thể làm giảm scored exposure/coverage: cần công bố số row bị
loại và thời gian warming, không chỉ latency của các row được giữ lại.

Sau khi canary freshness hợp lệ, vẫn phải nối bốn phần formal còn thiếu,
preregister run mới, kiểm tra recovery với lỗi hữu hạn trên collector thử
nghiệm và đánh giá dài hạn. Mọi alert phải giữ trong tử số; không viện lỗi
hạ tầng để xóa alert pressure C2 trước đó.

## Canary freshness C1 đã terminal — không phải formal soak

Source frozen `f476462519cd7c07131c3ecc2e691d5f74573ada`, regression **483
test +20 subtest trên host/VM**; targeted VM sau chỉnh readiness đạt84 test.
Source được Git commit/fetch qua bundle riêng; không checkout đè worktree host.
Code và báo cáo cũng đã sync chọn lọc vào VM main, không đụng file người dùng
đã xóa hoặc thay đổi ngoài phạm vi.

Run `pulse-recovery-freshness-smoke-c1-20261004`, worker `.238`, unit
`sentinel-pulse-recovery-freshness-smoke-20261004-c1.service`.
Preregister **11:11:14,783 ICT**, collector START **11:11:21,382 ICT**,
duration600 s, model/policy/profile frozen giữ nguyên. Contract freshness SHA:
`a5ca1b229e1c27c43750e8ecaec13f603bee88012c1a197f8424f195b943b3ba`.

Checkpoint SSH **11:12:02,999 ICT**, chưa terminal:

- 1.645 decision: **807 telemetry-degraded do queue stale**, 69 warming,
  765 normal, 4 suppressed; 769 scored row/19 key,0 alert.
- Mọi scored row có processing-start age≤1 s; max0,687700 s.
- Đầu window→decision hoàn tất sau policy p99 **1,154985 s**, max1,217180 s
  trên769 scored row; chưa gồm serialization/output flush, không kernel-to-alert.
- **807 row cũ không biến thành normal**: giữ raw/decision, không inference,
  không tính scored exposure. Con số latency trên là có điều kiện trên row
  đủ mới, không chứng minh toàn stream đạt1–2 s hoặc recall được giữ nguyên.

Checkpoint trên là lịch sử. Run đã terminal **11:21:49 ICT**, exit 0;
lịch nhắc 11:23 đã hết hiệu lực. SSH kiểm tra lại chiều 04/10: **18/18 file
run +3/3 file preregistration** khớp checksum. Collector control/resolver
active; detector candidate và collector experiment inactive. Không có
training dài ngày đang chờ; chưa inject fault/attack trong run C1 này.
Evidence checkpoint: [LIVE_CHECKPOINT.json](validation-evidence/recovery-freshness-dev-20261004/LIVE_CHECKPOINT.json).

### Kết quả terminal freshness C1

- **26.670 decision**, **25.718 scored row /19 workload-container key**:
  25.241 normal, 477 suppressed, 134 warming, **818 queue-stale degraded**,
  **0 alert**, không có feature chưa consume.
- Snapshot availability 1,0; maximum gap **0,518149 s**, bảy hard integrity
  counters đều 0. **Không có recovery incident** trong lượt này.
- Trên 25.718 scored row: đầu window → quyết định hoàn tất sau policy
  p50 **0,840 s**, p95 **1,116 s**, p99 **1,278 s**, max **1,527 s**.
- Đây là latency **có điều kiện trên scored row đủ mới**, trước serialization/
  output flush, **không phải kernel-to-alert**. Không xóa 818 stale row, không
  suy ra recall, FPR=0, hay formal/production PASS từ 0 alert của smoke.

Evidence: [TERMINAL_REMOTE_RECEIPT.json](validation-evidence/recovery-freshness-dev-20261004/TERMINAL_REMOTE_RECEIPT.json).
Raw vẫn nằm trên VM; receipt không giả định đã copy full raw về host.

## Formal core: phần code mới, chưa phải lifecycle hoàn chỉnh

[`recovery_formal.py`](sentinel_pulse/recovery_formal.py) có registration,
worker attestation, resume binding, supervisor state machine, streaming
feature/decision join và aggregate theo interval union. Replica không được
cộng trùng thời gian; warming/stale/quarantine/health-degraded không tính
scored exposure. Mọi alert vẫn ở tử số, kể cả health-degraded.

Aggregate yêu cầu đủ bảy hard counter có giá trị integer 0 và availability
hữu hạn trong [0,999; 1]; không cho report thiếu counter hoặc boolean giả
numeric lọt qua gate. Tiêu chuẩn alert budget hiện hữu được giữ, không bắt
buộc 0 alert để đạt formal rate gate. Diagnostic không được tạo formal PASS.

Chưa có coordinator SSH/systemd nối registration → triển khai ba worker →
live dependency observations → finalizer. Chưa mở run formal recovery 24 giờ,
blind set hay promotion. Các unit test với trace tổng hợp chỉ kiểm chứng logic,
không phải số liệu live của mô hình.

Source formal core frozen riêng `7e1c04cdeb564c1368eb2f2dc97bcb7b8f1aac8c`,
regression host **542 test +20 subtest/21,01 s**, VM **542 +20/41,19 s**.
Host fetch ref `vm-recovery/runtime/recovery-formal-core-20261004` bằng Git;
không checkout đè worktree hiện tại hoặc commit chung thay đổi của người dùng.

## Diagnostic fault hữu hạn đã terminal — lịch 18:50 đã hết hiệu lực

Run `pulse-recovery-fault-smoke-c1-20261004`, source trên, worker `.238`;
collector START **18:18:06,869 ICT04/10**, duration **1.800 s**. Parent unit
`sentinel-pulse-recovery-fault-smoke-20261004-c1.service` có wall cap1.980 s.
Preregister một lần pause1.200 ms sau120 s, scope chính xác private projected
loader của run, chọn qua cgroup/executable và dùng pidfd để tránh PID reuse.
Helper gửi SIGCONT trong finally kể cả SIGTERM; không khẳng định bảo vệ khỏi
SIGKILL của helper trong đoạn pause. Không dừng control collector/pod AIMS.

Checkpoint **18:18:41**: parent, collector experiment, detector candidate,
control collector và resolver active/0 restart. 1.335 decision:516 normal,
4 suppressed,746 stale-degraded,69 warming;520 scored row/19 key,0 alert.
**Fault chưa đến lịch ở checkpoint này**, chưa chứng minh recovery thành công.
Job tự kết thúc/evaluate/freeze evidence; kiểm tra khoảng **18:50 ICT**.

[START_REMOTE_RECEIPT.json](validation-evidence/recovery-fault-smoke-c1-20261004/START_REMOTE_RECEIPT.json).
Đây là diagnostic để chứng minh quarantine/reset/clean recovery, không attack,
training, recall evaluation hoặc formal soak. Model/policy giữ nguyên. Formal
24 giờ chưa bắt đầu; tuyệt đối không sửa run cũ thành PASS.

### Checkpoint sau fault — 18:21 ICT

Helper đã pause thật từ **18:20:03,112** đến **18:20:04,312**, elapsed
monotonic **1,200428 s**, `resume_sent=true`. Tại18:20:42:6.687 decision,
5.541 scored row/19 key,0 alert; parent/experiment/detector/control/resolver
active và0 restart. Source/executable/preregistration SHA được giữ trong event.

Review độc lập **18:21:04** xác nhận quarantine snapshot sequence223 rồi
clean recovery. Tail sequence341: `ready`, epoch1, một incident, hai snapshot
thiếu ước tính; excluded6,950973 s, max gap1,379815 s. Availability tạm thời
**0,994169**: **chưa đạt floor0,999**, watchdog không đánh giá floor giữa run.
Floor vẫn phải đạt khi terminal, không được miễn vì đây là fault injection.
Không đổi tên live recovery checkpoint thành capture/formal PASS.

[Event/checkpoint](validation-evidence/recovery-fault-smoke-c1-20261004/POST_FAULT_REMOTE_CHECKPOINT.json),
[independent live review](validation-evidence/recovery-fault-smoke-c1-20261004/LIVE_FAULT_REVIEW.json).
Sáu file code/test của release cũng đã sync chọn lọc vào VM main sau đối
chiếu hai file cũ với source frozen `f476462`; không xóa hoặc reset worktree.

### Terminal kiểm tra SSH 21:40–21:42 ICT

Run kết thúc **18:49:02**, exit0; **19/19 checksum run,3/3 preregistration,
177/177 source** khớp. Source `7e1c04c` sạch; evaluator chạy lại trên raw VM
cho kết quả giống hệt frozen `RECOVERY_SMOKE_REPORT.json`. Không sửa verdict
hoặc checksum cũ khi thêm source mới.

| Chỉ số terminal | Kết quả |
|---|---:|
| Decision /scored row /workload-container key trên worker4 | 80.084 /78.779 /19 |
| Normal /suppressed /warming /telemetry-degraded | 78.064 /715 /536 /769 |
| Alert /feature chưa consume | 0 /0 |
| Snapshot /snapshot thiếu ước tính | 3.552 /2 |
| Availability | 0,999437254; đạt floor0,999 |
| Incident /excluded time /maximum gap | 1 /6,950973 s /1,379815 s |
| Bảy hard integrity counters | Đều0 |
| Đầu window→sau policy p50/p95/p99/max | 0,820 /1,050 /1,132 /1,351 s |
| Cuối window→sau policy p99/max | 0,625 /0,844 s |

769 degraded gồm746 queue-stale và23 source-cadence row; không tính chúng
thành normal/scored. Latency trên có điều kiện trên78.779 scored row đủ mới,
trước serialization/output flush, không attack injection hoặc kernel-to-alert.
19 key trên một node không có nghĩa đủ21 key trên cả cụm. 0 alert của lượt
30 phút không chứng minh FPR=0 hoặc formal24h/production readiness.

Parent/experiment/detector inactive; control collector/resolver active,
0 restart. SSH cùng lượt xác nhận6/6 node Ready v1.34.10,67/67 pod production
Ready. Không có job diagnostic này hoặc formal recovery soak đang chạy.
[TERMINAL_REMOTE_RECEIPT.json](validation-evidence/recovery-fault-smoke-c1-20261004/TERMINAL_REMOTE_RECEIPT.json).
Raw vẫn trên VM; chưa copy full raw về host.

## Bridge formal installer và launcher worker — bước code mới

`bind_freshness_preregistration` hỗ trợ formal marker riêng dưới
`/var/lib/sentinel-pulse-recovery-formal/<run_id>/START.json`. Marker formal
phải vượt cùng `validate_worker_start` dùng trong terminal evaluator:
run/source/worker/SHA, attestation trước collector, startup budget120 s,
private loader/object và exact recovery profile bytes. Có cả smoke và formal
marker cho cùng run thì từ chối, không sửa smoke cũ thành formal.

[`run_recovery_formal_worker.sh`](sentinel_pulse/run_recovery_formal_worker.sh)
derive duration/model/policy từ marker, kiểm tra hostname, attest trước
install; copy receipt vào capture trước detector freshness binding. Watchdog
cho bounded recovery tiếp tục, giữ mọi alert cho rate budget; cleanup chỉ
stop unit có env chứng minh thuộc run này, rồi seal raw và worker terminal.
Không tự đánh giá formal PASS, inject attack hay promote model.

Smoke evaluator mới từ chối unconsumed feature thay vì chỉ ghi con số rồi
vẫn cho valid. Lượt C1 cũ có0 unconsumed và vẫn được giữ nguyên theo source
frozen của nó; không overwrite report để chạy source mới lên dữ liệu cũ.

Regression host **557 test +20 subtest/19,90 s**, VM **557 +20/42,78 s**;
`bash -n` launcher và `git diff --check` đạt. Launcher mới chưa có evidence
live formal leg. Còn phải nối coordinator đăng ký/khởi động ba worker,
dependency health journal, supervisor/resume và terminal finalization, rồi
chạy bounded end-to-end diagnostic mới trước formal24h. Không chỉ mở một
soak24h khi các phần này chưa được kiểm chứng.

Release worker bridge frozen **`3628e0835d39548441d5548532de409c1a559f0f`**,
branch `runtime/recovery-formal-worker-20261004`; source riêng trên master1
và worker4 ở `/home/dat/eBPF-project-recovery-formal-worker-20261004`.
Host fetch qua Git, không checkout/reset worktree hoặc push GitHub.
Trên worker4, gọi launcher thật với run mới nhưng **không có marker** đã
trả exit1 trước mutation; không tạo run và không đổi trạng thái/restart của
control/resolver/experiment/detector. Đây chỉ là guard test, không phải live
formal worker leg. [Guard receipt](validation-evidence/recovery-formal-worker-dev-20261004/MISSING_MARKER_GUARD.json).
