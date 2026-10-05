
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
## Checkpoint lịch sử 04/10/2026 — 22:21 ICT

Đã viết, kiểm thử và triển khai **coordinator ba worker** + worker probe trên
release Git riêng `dd872e7`, giữ model/policy frozen. Nối marker immutable,
worker attestation, systemd parent riêng, SSH/API probes parallel, journal
health/supervision và finalization verify seal→streaming evaluation→aggregate.
Known integrity failure reject; unknown SSH/API không được tính normal.
Cleanup chỉ tác động parent thuộc run, không pod AIMS/control collector.

Diagnostic mới `pulse-recovery-fleet-diagnostic-c1-20261004` đăng ký22:16:03,
600 s/node; scope per-node16/19/15 key, union21/21. Receipt22:17 xác nhận ba
worker active/tail ready,0 detector restart, coordinator monitoring, health
không degraded. **Chưa terminal, chưa formal24h PASS hoặc recall mới.**
Host832 +20 subtest đạt (7skip), VM873 +20 đạt; subset formal/coordinator83
đạt cả hai môi trường. Count full suite khác do dependency tùy chọn.
Dự kiến đọc terminal22:30 ICT04/10, job tự dừng/finalize. Không đổi model,
không train/tune trên diagnostic, không mở blind/promotion tự động.
[Evidence](validation-evidence/recovery-fleet-diagnostic-c1-20261004/START_REMOTE_RECEIPT.json),
[chi tiết lifecycle](PULSE_RECOVERY_LIFECYCLE_STATUS_20261004.md).

Đọc stream thật22:21:37.063 decision/34.394 scored/0 alert,21/21 key; giữ
2.341 degraded/328 warming. p99 đầu window→sau policy trên row đủ mới:
.2371,282 s/.2381,385 s/.2391,290 s, chưa output flush/kernel-to-alert.
Ba pipeline vẫn active/0 restart, chưa terminal; không claim FPR=0 hoặc recall.

## Checkpoint lịch sử 04/10/2026 — 21:40–21:50 ICT

Fault diagnostic C1 terminal **18:49:02**, exit0. SSHverify19+3+177 checksum
khớp; replay độc lập giống frozen report.80.084 decision/78.779 scored row/
19 key/0 alert,769 degraded và536 warming giữ nguyên. Quarantine→clean
recovery thật, một incident; availability0,999437254 đạt floor0,999.
Đầu window→sau policy p99 **1,132 s**, max1,351 s có điều kiện trên scored
row đủ mới, không output flush/kernel-to-alert hoặc formal PASS.
Candidate/experiment inactive, control/resolver active;6/6 node và67/67 pod
production Ready. Không có diagnostic này hoặc formal24h đang chạy.
[Receipt](validation-evidence/recovery-fault-smoke-c1-20261004/TERMINAL_REMOTE_RECEIPT.json).

Đã nối formal marker/attestation vào freshness installer, thêm worker launcher
riêng và gate unconsumed feature; host/VM557 test +20 subtest đạt. Còn thiếu
coordinator ba worker và chứng minh end-to-end trước formal24h; không đổi
model/policy, không mở blind hoặc promotion.

## Checkpoint lịch sử 04/10/2026 — 18:18 ICT

Freshness C1 đã terminal **11:21:49**, 26.670 decision /25.718 scored row /
19 key /0 alert; **818 queue-stale degraded**, 134 warming được giữ nguyên.
Đầu window→quyết định sau policy p99 **1,278 s**, max1,527 s trên scored
row đủ mới, trước output flush; chưa phải kernel-to-alert hoặc formal PASS.
SSH chiều nay verify18+3 checksum, 6/6 node và 67/67 pod production Ready.

Đã implement/test formal registration/resume/supervisor/streaming exposure/
aggregate core; chưa nối coordinator SSH/systemd ba worker end-to-end.
Source frozen riêng `7e1c04c`, host/VM **542 test +20 subtest đạt**.
Không đổi model/policy hoặc mở blind/promotion. Sửa gate thiếu hard counters
và thêm test SIGTERM bảo đảm helper gửi SIGCONT trước khi thoát.

Diagnostic mới trên `.238`: `pulse-recovery-fault-smoke-c1-20261004`, START
**18:18:06,869**, 1.800 s, chỉ tạm dừng private loader 1.200 ms đúng một lần
sau120 s preregistration. Checkpoint18:18:41: các service cần thiết active,
0 restart, 1.335 decision/520 scored/19 key/0 alert; fault chưa xảy ra ở
checkpoint này. Dự kiến kiểm tra terminal **18:50 ICT 04/10**. Không có
formal recovery soak24h đang chạy; diagnostic không được relabel thành PASS.
[Receipt](validation-evidence/recovery-fault-smoke-c1-20261004/START_REMOTE_RECEIPT.json).

Các checkpoint phía dưới là lịch sử, không mô tả trạng thái active hiện tại.

**Sau fault18:21:** pause1,200428 s đã xảy ra; journal chứng minh quarantine
rồi clean recovery. Checkpoint18:20:42 có6.687 decision/5.541 scored/19 key/
0 alert, servicesactive/0 restart. Availability tạm thời0,994169 do hai snapshot
thiếu, **chưa đạt floor0,999**; phải evaluate terminal, không relabel thành PASS.
[Live review](validation-evidence/recovery-fault-smoke-c1-20261004/LIVE_FAULT_REVIEW.json).

## Checkpoint04/10/2026 — canary C2 reject, triển khai recovery tiếp

C2 terminal00:02:31:179.034 decision,1 alert Redis Sentinel; worker4 capture
gap13,208959 s, availability0,990699. Giữ normal-alert verdict và raw evidence,
không claim FPR=0. Observer cả3 đã hoàn tất01:46–01:47,23 checksum/node đạt;
worker4 có8 late sample, max24,077 s. Trong incident ML observer trễ13,643 s.

Đã nối recovery profile vào installers/rendered units, thêm diagnostic smoke
và evaluator giữ mọi alert; formal lifecycle/exposure integration vẫn thiếu.
Smoke đầu dừng trước deploy vì root Git ownership; sửa scoped trust và dùng
run/source mới. Giữ21 model/calibration/policy frozen, không train/tune trên
run bị reject. [Báo cáo incident](docs/archive/PULSE_PRESSURE_C2_INCIDENT_20261004.md).
Các lịch chờ02:10 dưới đây là lịch sử, không còn job ML C2 đang chạy.

Deployment recovery release`ef056f5`: smoke `.238` terminal **10:56:48 ICT**,
26.648 decision/19 workload scored/0 alert; checksum17+3 file khớp.
Không có incident recovery, chưa formal PASS. Toàn run latency đầu
window→sau model p99 **12,551 s**, sau120 s đầu p99 **1,907 s**, max2,457 s;
không kernel-to-alert. Đã thêm gate processing age riêng để không inference
trên queue item cũ, đang xác minh release mới. Model/policy frozen không đổi.
**Formal recovery lifecycle còn chưa tích hợp**, không có formal recovery
soak chạy ngầm. [Chi tiết](PULSE_RECOVERY_LIFECYCLE_STATUS_20261004.md).

Gate freshness release`f476462`: host/VM483 +20 subtest đạt. Canary `.238`
START11:11:21, checkpoint11:12:03 có1.645 decision/769 scored/19 key/0 alert;
807 queue-stale row được giữ dưới dạng degraded, không normal/exposure.
p99 đầu window→sau policy1,155 s chỉ trên scored row, không kernel-to-alert.
Chạy ngầm600 s; review **11:23 ICT04/10**, không phải formal recovery soak.

## Checkpoint lịch sử 03/10/2026 — khoảng 23:40 ICT

Recovery core đã implement, release `936d3df`, regression host/VM **435 test
+20 subtest đạt**. Có quarantine, rolling/history reset, journal replay,
watchdog và training interlock. Chưa tích hợp vào formal lifecycle; không
thay tiêu chuẩn run cũ, model/policy hoặc mở blind/promotion.

Diagnostic C1 reject sau SSH unreachable, terminal worker4 gap16,485 s và
availability0,976314; 90.343 decision/0 alert là dữ liệu rejected, không FPR.
Observer C1 failed exit126 do launcher gọi script không executable; sửa bằng
interpreter và kiểm tra sample/sar thật. Observer C2 ready3/3 từ23:36; ML C2
START23:37:48, duration7200 s, vẫn strict10 s gap và frozen model/policy.
Nhắc kiểm tra terminal **02:10 ICT 04/10**, không hứa PASS. Chi tiết và phần
chưa làm: [PULSE_TELEMETRY_RECOVERY.md](PULSE_TELEMETRY_RECOVERY.md).

## Checkpoint lịch sử 03/10/2026 — khoảng 23:10–23:18 ICT

Projected operational soak đã chạy từ 12:05:14 và bị infrastructure-reject
**20:13:34** vì gap telemetry **14,030 s >10 s** trên worker3. Counter
consistency/projection/total/target failure 0; không kết luận ML fail. Archive
hoàn tất 20:28:04, START 5/5 và archive 52/52 checksum kiểm tra lại khớp.
Snapshot monitor cuối bất đồng bộ có **3.806.735 decision, 0 alert/restart**,
không được dùng để train/tune hoặc claim FPR/normal PASS. Candidate dừng,
controls phục hồi; cluster lại 6/6 Ready, 67/67 production Ready, 29/29 volumes
healthy. Bổ sung observer service-level PSI/reclaim/clock cho lượt diagnostic
riêng; không đổi model/policy, không nới gap budget hoặc resume run fail.
[Chi tiết](docs/archive/PROJECTED_OPERATIONAL_SOAK_20261003.md).

## Checkpoint terminal lịch sử 03/10/2026 — 11:50:47 ICT

ML canary projected đã hoàn tất: **114.984 decision, 21/21 key, 0 alert và
0 restart**, aggregate valid. START checksum 10/10 và FINAL 76/76 đều khớp.
Inference p99 **30,092 ms**; đầu window → timestamp sau inference p99
**1,053 s**, max 1,376 s; chưa bao gồm policy/output, chưa phải kernel-to-alert.
Không inject attack và chưa mở blind; không claim recall hoặc FPR=0.
Candidate đã dừng, control collectors/resolvers active. Tiếp theo: đăng ký
operational soak projected mới, giữ nguyên model/policy và hard telemetry gates.
[Receipt terminal](validation-evidence/projected-ml-c1-20261003/TERMINAL_RECEIPT_20261003.json).

## Checkpoint lịch sử 03/10/2026 — 10:15 ICT

**ML canary projected đã active trên 3/3 worker**, run mới
`pulse-projected-ml-c1-20261003T031200Z`, cùng 21 model/policy frozen.
Checkpoint bất đồng bộ: 9.172 decision, 0 alert/restart; telemetry tails
valid, checksum control binaries không đổi. Regression host/VM **375 test +
20 subtest pass**. Finalizer/supervisor chạy ngầm, duration 900 s/node; kiểm
tra terminal/archive khoảng **10:35 ICT ngày 03/10**. Chưa claim production
stable, normal gate PASS hoặc kernel-to-alert.

Chi tiết: [PROJECTED_ML_CANARY_20261003.md](docs/archive/PROJECTED_ML_CANARY_20261003.md).

Monitor mới **10:21 ICT** ghi tổng 49.318 decision từ ba snapshot bất đồng bộ,
0 alert; canary/supervisor vẫn active, chưa terminal. Nhắc kiểm tra 10:35.

## Checkpoint lịch sử 03/10/2026 — 10:02 ICT

R10-C3 đã **infrastructure-reject lúc 11:37:15 ICT**, không còn chạy soak:
collector worker1 hết retry consistency và mất một target snapshot RabbitMQ.
Archive/checksum giữ nguyên; control collectors phục hồi, ML candidate dừng.
Lượt này không được dùng để train/tune hoặc claim false-positive rate.

Đã triển khai nhánh **projected counters** opt-in: mỗi syscall tăng một primary
counter, loader suy ra histogram/total từ cùng dữ liệu copy; schema 249 và
bundle ML/policy không đổi. Regression host và VM main **370 test + 20 subtest
pass**, gồm evaluator không chấp nhận thiếu duration/coverage hoặc tamper.
Canary collect-only worker1 đã terminal 17:34:06 ICT ngày 02/10 và được review
lại ngày 03/10: 38.505 row, 1.776 snapshot, 16/16 expected node keys, hard
counters 0; p99 window-start-to-feature-emit 0,547 s, không phải kernel-alert.
Hai canary worker3/4 đã terminal **09:59 ICT ngày 03/10**, full validation
valid (38.832/40.075 row), hard counters 0; safety review tự động **đã đạt**
hai node lúc 10:01. Tổng ba worker có 117.412 row, union 21 key, 3/3 collector
safety review đạt. Không còn chờ canary/review ngầm.
Không thay binaries control hay sửa AIMS; ML đang dừng.

Chi tiết: [PROJECTED_COUNTER_CANARY.md](docs/archive/PROJECTED_COUNTER_CANARY.md).
Cụm tại checkpoint 09:43 ngày 03/10: **6/6 node Ready v1.34.10, 67/67 pod production
Ready, 29 volume Longhorn healthy**. Đây là snapshot, không phải soak pass.

## 1. Kết quả đã phát triển được

Trong giai đoạn này, project đã có RCA connect enrichment được thử bằng traffic thật, pipeline normal dataset gắn chặt với revision AIMS, dataset 500 ms hợp lệ cho 21 workload/container, candidate gồm 21 model ExtraTrees, traffic harness bao phủ cả search service và hai canary R10-C1 có coverage đầy đủ.

Phần còn vướng là xác nhận độ ổn định dài hạn: formal soak R10-C1 bị loại vì integrity/telemetry; R10-C2 dừng vì volume Longhorn degraded; operational R10-C3 bị loại vì consistency collector. Candidate chưa đạt normal gate, chưa được promote và chưa có kết quả blind attack R10. Các timing post-model đã có không bao gồm policy/output; mục tiêu **kernel-to-alert 1–2 giây** vẫn cần đo đầy đủ bằng attack độc lập.

## 2. Mốc phát triển theo thời gian

| Ngày ICT | Công việc/kết quả | Bằng chứng và ý nghĩa |
|---|---|---|
| 18/09 | Hoàn thiện tài liệu các khái niệm Sentinel Pulse, feature, model và decision pipeline | Commit `fcd259c`, [sentinel-pulse.md](sentinel-pulse.md). Đây là bổ sung tài liệu, không phải phiên bản model mới |
| 19–22/09 | Không thấy commit mới trong lịch sử Git được kiểm tra | Không suy ra hệ thống ngừng chạy; cũng không tự gán thêm kết quả phát triển cho các ngày này |
| 23/09 | Sửa kiểu socket FD trong Tetragon policy; mở rộng parser/resolver RCA và thử bằng request thật | Commit `65ac511`; smoke ghi nhận 92 connect edge từ 709 Tetragon record, trong đó 90 đích resolve được và 2 đích unresolved |
| 23–24/09 | Revision observer R9 khóa deployment AIMS và hoàn tất quan sát 24 giờ | Một fingerprint trong 1.428 observation; đây là prerequisite revision ổn định, chưa phải model pass |
| 24/09 | Thu formal normal dataset năm traffic regime cho revision R9 | 390.028 row, 21 workload/container, telemetry availability 1,0; dataset hợp lệ cho training |
| 24–25/09 | Train R9-C1, build semantic policy, benchmark; formal normal run phát 2 alert và bị reject | Commit `56380c8` và `7c19ebc`; lỗi normal gate được giữ nguyên, không đổi nhãn thành infrastructure failure |
| 25/09 | Khôi phục temporal confirmation đã có từ policy B7 cho successor R9-C2 | Commit `fa5c66d`, thêm builder và test; giữ calibration/model R9, yêu cầu đánh giá độc lập successor |
| 25–26/09 | Canary C2 đầu bị reject do frontend coverage; sửa heartbeat frontend độc lập và chạy lại | Commit `d79f43a`; canary R2 đạt 21/21 coverage, 113.555 decision, 0 final alert |
| 26/09 | Formal R9-C2-R2 dừng khi AIMS đổi revision | Snapshot cuối 3.079.504 decision, 0 alert; monitor bắt drift và không trộn hai revision |
| 27–28/09 | Chạy observer R10 cho revision mới và siết binding dataset với observer terminal | Commit `44ebd58`; R10 hoàn tất 24 giờ ngày 28/09, cho phép thu dataset cho đúng revision |
| 28/09 | Sửa runtime thiếu trên worker, tách telemetry gate raw/measured và sửa phạm vi health gate | Commit `60e259a`, `05f0ed8`, `edbc4b9`; các run R1–R3 bị reject vẫn giữ disposition cũ |
| 28/09 | Dataset successor R4 hoàn tất hợp lệ | 391.454 row, 249 feature, 21 workload/container, đủ năm regime |
| 29/09 | Viết tài liệu log; khóa blind contract trước training và train candidate R10-C1 | Commit `aefbc39`, `e525aac`; 21/21 PulseExtraTrees, pipeline audit/train/policy/benchmark hoàn tất trong 9 phút 47 giây |
| 30/09 | Canary R10-C1 pass integrity và coverage; bắt đầu formal normal soak | 113.543 decision, 0 alert; p99 normal window-start-to-decision 1,035 giây |
| 30/09–01/10 | Mở rộng traffic liên tục sang search service, sửa products route; formal C1 sau đó bị reject | Commit `c04232f`, `1a3c4e7`; C1 dừng sau khoảng 17 giờ 8 phút vì integrity/telemetry |
| 01/10 | Tăng bounded retry của map snapshot, sửa freezer resume và hashing capture lớn | Commit `935ca08`, `0f58a66`; áp dụng cho run kế tiếp |
| 01/10 | Chạy lại traffic gate và bounded normal canary với candidate đã khóa | 114.964 decision, 21/21 coverage, 0 final alert; có 1.182 suppressed raw-anomaly signal |
| 01/10 tối | Tạo worktree sạch, khởi chạy formal R10-C2; run dừng lúc 22:51:28 | Source VM `05c09a7`; failure `unhealthy_longhorn_volume`; archive hoàn tất 22:56:33 |
| 02/10 sáng | SSH xác minh R10-C2 terminal, checksum và phục hồi collector | 38/38 checksum đạt; collector chuẩn active trên ba worker; 6 node Ready và 29 volume Longhorn healthy tại thời điểm kiểm tra |
| 02/10, 10:24 | Khoanh vùng R/W timeout tới worker4 và chạy observer hạ tầng 6 giờ | Ba engine timeout 8 giây cùng containerd/kubelet chậm; thêm clock/PSI/network diagnostics, chưa mở lại formal soak |
| 02/10, 11:08–11:38 | Operational R10-C3 khởi chạy rồi bị integrity reject trên worker1 | Snapshot consistency retry exhausted, archive/checksum và disposition giữ nguyên; không tính là normal-pass |
| 02/10, 17:19 | Build/attach projected-counter canary worker1 | Opt-in collect-only 900 s; 355 test + 20 subtest pass; 17:25 có 722 snapshot chưa lỗi, chưa terminal |
| 02/10, 17:34; xác minh 03/10 | Worker1 canary terminal đạt collector safety review | 38.505 row, 1.776 snapshot, 16/16 node key, source/capture hash khớp; không phải ML/normal soak pass |
| 03/10, 09:44–09:59 | Mở hai canary worker3/4, full canary evaluator và timer review | Collect-only 900 s; regression host/VM 370 test + 20 subtest pass; không promote hoặc mở blind |
| 03/10, 10:01 | Timer full safety review hai worker hoàn tất | 15/15 và 19/19 node key, source/raw hash khớp, duration đạt; 3/3 worker collector review đạt, chưa phải ML PASS |
| 03/10, 10:13–10:15 | Mở ML normal canary 3/3 worker bằng collector projected đã kiểm chứng | Model/policy frozen; binary riêng theo run ID; 9.172 decision, 0 alert/restart ở checkpoint đầu; 375 test + 20 subtest pass |

Ngày commit có thể khác ngày chạy thực nghiệm. Ví dụ training R10-C1 diễn ra tối 29/09, còn bản xác minh/báo cáo được commit sáng 30/09.

## 3. Cải tiến kỹ thuật cụ thể

### 3.1. RCA: connect gọi từ process nào, tới đâu

[`rca_connect.py`](sentinel_pulse/rca_connect.py) đã nhận được event shape thật của Tetragon, xử lý `sockaddr_arg.addr`, EndpointSlice có endpoint null và ánh xạ destination sang Pod/Service. Connect event có process identity/lineage, binary và destination IP/port.

Lần smoke ngày 23/09 có request health thật trả HTTP 200, tạo 7 connect event đúng pod của API gateway. Replay 709 record tạo 92 edge; 2 destination chưa resolve được vẫn được giữ unresolved. CLI xuất JSONL kèm checksum và không ghi đè file sẵn có. Parser có thêm test trong [`test_sentinel_pulse_rca_connect.py`](tests/test_sentinel_pulse_rca_connect.py).

Đây là nền cho đồ thị `workload → process → connect → destination`. RCA chưa được chứng minh là hệ thống tự xác định root cause đầy đủ. Payload HTTP/TLS chưa được thu từ `connect`; enrichment chạy riêng với vector ML.

### 3.2. Dataset đa tải và khóa revision

Dataset hiện có năm regime `steady`, `toolmix`, `peak`, `burst`, `recovery`. Peak mô phỏng hình dạng tải cao điểm; burst mạnh hơn. Có dữ liệu peak trong training không đồng nghĩa đã đo false-positive rate trên một peak holdout độc lập.

[`revision_evidence.py`](sentinel_pulse/revision_evidence.py) yêu cầu observer đã `COMPLETE`, checksum hợp lệ và fingerprint live khớp trước collection. Campaign kiểm tra revision trong quá trình chạy và trước finalize. Đây là cải tiến trực tiếp sau khi AIMS rollout khiến formal run R9-C2-R2 bị dừng.

R10-R4 hợp lệ có **391.454 row, 249 chiều, 21 workload/container key**, đủ năm regime cho mọi key. Những run dataset R1–R3 bị loại không được đưa lại vào train hoặc calibration.

21 key tương ứng **19 controller**, vì Kafka entity operator và MinIO có nhiều container identity. Phạm vi gồm frontend, 10 application microservice, Kafka, hai entity-operator container, PostgreSQL, RabbitMQ, Redis, Redis Sentinel, hai MinIO container và Istio waypoint. Con số này không có nghĩa mọi pod trên cụm đã có model.

### 3.3. Model và policy

Candidate R10-C1 gồm **21 PulseExtraTrees**, cửa sổ 500 ms, history 3, conformal alpha 0,001; không có workload trong bundle ở chế độ collect-only. Nó dùng normal dataset R4 và synthetic corruption negatives cho training.

Các bước audit, fit, build policy và benchmark hoàn tất tối 29/09. Benchmark replay có 10.500 scored window, inference p99 **31,27 ms**. Thời gian train ngắn phù hợp với runtime ExtraTrees và kích thước dataset hiện tại; chất lượng phát hiện cần được đánh giá ở các run độc lập.

Policy kế thừa temporal confirmation B7, cùng semantic corroboration và score corroboration. Regression R9-C1 đã cho thấy việc bỏ prior temporal guard tạo normal alert; builder successor được bổ sung provenance và test để khôi phục control đó. Không tăng threshold theo chính holdout bị fail.

Model manifest R10-C1 SHA-256:
`6ddf7cf9b03cb783b82c23272f7046bafa7ab1412b0545b60a2821d1f441cc21`.

Policy SHA-256:
`602165bd48d81f549d3bfb65e5bdb319a11252678cbf484d739afcf2e5bc8143`.

### 3.4. Traffic và độ tin cậy telemetry

Continuous east-west loadgen được bổ sung search service, nâng số service gọi trực tiếp từ 9 lên 10. Products traffic/gate dùng `/api/products/?page=1`; route detail với numeric ID không phù hợp API dùng UUID. Frontend heartbeat chạy nền độc lập để API call chậm không làm mất frontend coverage.

Worker installer đồng bộ đủ runtime module và kiểm tra checksum/CLI trước start. Raw full-span telemetry và measured dataset có contract riêng, giữ integrity counter bắt buộc bằng 0. Health gate ghi auxiliary failures ngoài production và chặn các lỗi có liên quan trực tiếp tới experiment.

Loader tăng retry đọc snapshot từ 8 lên 32, cách nhau 50 µs, xuất retry counter và vẫn reject khi hết retry. Finalizer tính SHA-256 theo stream để tránh nạp capture nhiều GB vào RAM. Freezer có thể tiếp tục archive đã tạo trước đó.

Các mốc regression trong báo cáo tăng từ 583 lên 587, 591 và 592 test pass khi thêm các guard tương ứng. Đây là kết quả test lịch sử trên source/venv đã ghi ở từng checkpoint; không phải lần chạy test mới cho tài liệu này.

## 4. Kết quả thực nghiệm và giới hạn

| Run | Kết quả quan sát | Kết luận hợp lệ |
|---|---|---|
| R9-C1 formal normal | 2 alert trên Kafka/inventory; terminal normal rejection | Policy candidate không qua normal gate |
| R9-C2 canary đầu | 112.757 decision, 0 alert; frontend coverage 92,84% | Reject coverage, chưa đủ điều kiện mở formal soak |
| R9-C2-R2 canary | 113.555 decision, 0 alert; đủ 21/21 coverage | Canary pass; p99 normal decision 1,518 giây, max 2,360 giây |
| R9-C2-R2 formal | 3.079.504 decision ở checkpoint cuối, 0 alert; AIMS revision đổi | Infrastructure/evidence rejection; chưa đánh giá được normal gate |
| R10-C1 canary 30/09 | 113.543 decision, 0 alert, 21/21 coverage | Canary pass; p99 normal decision 1,035 giây |
| R10-C1 formal | Khoảng 17 giờ 8 phút; integrity failure và telemetry gap | Reject; không tính là 24 giờ normal pass |
| R10-C1 retry canary 01/10 | 114.964 decision, 0 alert, 21/21 coverage; 1.182 raw flags bị suppress | Canary pass integrity; raw model còn nhiều tín hiệu cần điều tra |
| R10-C2 formal 01/10 | Khoảng 2 giờ 43 phút; Longhorn degraded | Infrastructure rejection, chưa đạt normal pass |

Canary retry 01/10 có inference p99 **30,77 ms**, window-start-to-decision p99 **1,096 giây**, max **1,570 giây**. Không có attack injection ở các canary R10 này, nên các giá trị trên chưa đo kernel-to-alert của attack.

Trong retry canary, `suppressed` raw flags là 1.182/114.964 decision (**1,028%**), riêng search service 881/6.959 (**12,66%**). Các signal đều không đạt semantic corroboration. Chưa có nhãn độc lập để coi mọi raw flag là false positive; số 0 final alert không chứng minh raw model hết nhiễu hoặc FPR quần thể bằng 0.

Blind contract R10 đã khóa trước training: **5 scenario × 19 controller × 5 trial = 475 trial**. Matrix có các scenario `anonymous_mprotect_churn`, `child_ptrace_handshake`, `invalid_setns_burst`, `seccomp_api_probe`, `execveat_resolution_probe`. Chưa mở blind phase nên chưa có recall/precision của candidate R10 trên matrix này.


## 5. Công việc còn cần hoàn thiện

1. Xử lý độ ổn định storage/node/telemetry trước khi mở formal run mới; căn cứ log và timestamp để xác định cơ chế lỗi.
2. Hoàn tất một normal soak đủ duration, coverage, revision và integrity trên candidate đã freeze; báo exposure cùng số final alert và raw flags theo workload.
3. Điều tra raw signals của search trên các regime và pod identity bằng dữ liệu development riêng; mọi thay đổi model/policy cần candidate mới và holdout mới.
4. Sau normal gate hợp lệ, thực hiện blind matrix 475 trial đã khóa; giữ detection miss, chỉ reject infrastructure failure có evidence.
5. Đo kernel-to-alert từ timestamp attack/kernel event, latency CDF và percentile; tách collector, inference, confirmation và alert emission.
6. Hoàn thiện comparison/ablation, repeated overhead A/B, confidence interval và evaluation ngoài deployment hiện tại để có bằng chứng cho paper.

Chưa có cơ sở định lượng đáng tin cậy để quy toàn bộ project thành một tỷ lệ hoàn thành duy nhất. Code/runtime, dataset và canary đã có kết quả; formal validation và blind attack evaluation vẫn là các gate còn thiếu.
