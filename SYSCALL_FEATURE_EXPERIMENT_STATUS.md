# Thí nghiệm chọn feature/syscall — thuật ngữ, triển khai và tiến độ

Cập nhật bằng SSH **15:12 ngày 15/10/2026, UTC+7**. Đây là nhánh nghiên cứu
chọn feature, chạy song song nhưng không đổi model [Pulse realtime](SENTINEL_PULSE_STATUS.md)
hoặc [RCA](RCA_RUNTIME_STATUS.md). Chỉ cập nhật trạng thái hiện hành, không
thêm checkpoint theo từng lần kiểm tra.

## 1. Câu hỏi nghiên cứu và kết luận hiện tại

Tập 29 syscall tường minh có cần bổ sung, bỏ bớt hoặc thay nhóm nào để phát
hiện tốt hơn trong cùng ngân sách false alert và latency? Không chọn đơn
thuần theo syscall xuất hiện nhiều hoặc biến thể có ít raw flags nhất.

**Chưa có bằng chứng cuối để kết luận syscall nào tối ưu.** R4 đã fit đủ và
được audit integrity; hiện đang thu normal exposure sau thời điểm fit freeze.
Independent normal chưa đủ 24 giờ; fresh paired blind attack và phân tích
thống kê vẫn chưa chạy.

## 2. Tiến trình đang chạy ngầm

| Mục | Trạng thái xác minh |
|---|---|
| VM | 10.1.16.234 — k8s-master.local |
| Unit | pulse-matched-study-parallel-r4-20261015.service |
| systemd | inactive/dead, `Result=success`, `ExecMainStatus=0`, `NRestarts=0` |
| Pha | matched fits hoàn tất; đang thu và chấm normal holdout |
| Fit hoàn tất | **693/693** (21 workload × 11 arm × 3 seed) |
| Audit | `R4_FIT_AUDIT.json`: `fit_set_verified_blind_evaluation_pending`; đã kiểm tra hash 693 artifact |
| Confusion matrix | **Chưa có**; precision/recall vẫn null, không suy diễn từ fit audit |
| Phạm vi | 21 workload/container key, gồm notification/payment |
| Thiết kế | 11 arm × 3 seed × 21 key = 693 model |
| Source cố định | /mnt/sentinel-pulse-archive/runtime-control-981aef3/source |
| Output/checkpoint | /mnt/sentinel-pulse-archive/matched-parallel-r4-20261015/syscall-matched-study |
| Evaluator mới | `pulse-syscall-holdout-r4-20261015.service`, active/running trên .234 |
| Tiến độ evaluator lúc 15:11 | 10 segment hoàn tất; đang chấm worker4/s00027; 2.787.840 context-model đã chấm |
| Tài nguyên evaluator | CPUQuota 4 core, MemoryMax 16 GiB; MemoryCurrent khoảng 8,0 GiB tại snapshot |

R4 fit kết thúc lúc **2026-10-15 05:22:03 UTC**. Audit được ghi lúc
05:32:27 UTC; kết quả audit bind config/index/input/source/terminal và xác minh
693 artifact. Terminal R4 vẫn ghi `fresh_blind_complete=false`, precision/recall
null.

Tại **05:35 UTC**, capture service trên cả ba worker (`.237`, `.238`, `.239`)
đang active, `NRestarts=0`; cùng một NFS archive còn khoảng 267 GiB trống.
Capture bắt đầu 2026-10-14 17:38:49 UTC, chạy 172.800 giây (48 giờ), nên theo
đăng ký hiện tại vẫn phủ hết khoảng holdout. Do stream đã tồn tại trước khi
đăng ký, không gán ngược các row cũ cho holdout. `NORMAL_HOLDOUT_START.json`
được tạo mới theo kiểu no-overwrite trên NFS và bind audit R4, terminal, source
và protocol. Manifest SHA-256:
`ad6d376cca418f350d88c4c411cdcd5cede556c8940d845eb8209af96939e920`.
Mốc bắt đầu là **2026-10-15 05:38:32 UTC**; hết 24 giờ dự kiến
**2026-10-16 05:38:32 UTC (12:38:32 UTC+7)**. Tại snapshot 15:11 UTC+7,
holdout đã chạy khoảng **2 giờ 33 phút (10,6% thời gian đăng ký)**; evaluator
đang ở segment worker4/s00027. STATUS ghi 10 segment hoàn tất và 2.787.840
context-model đã chấm; đây là tiến độ xử lý, chưa phải số window độc lập hay
confusion matrix. Cần chốt segment seal và kiểm tra coverage/health sau mốc này.

Đây mới là thời gian quan sát, chưa phải 24 valid workload-hours: workload
coverage và telemetry/infrastructure intervals phải kiểm tra từ feature records
đã seal. Alert/issue không bị xoá hay tự gán normal; chúng sẽ được giữ để review.
Một interval RCA validation trên worker1 (07:36:34–08:09:19 UTC ngày 15/10)
đã được ghi vào `INSTRUMENTATION_INTERVALS.jsonl` và
[receipt C3](validation-evidence/rca-runtime-validation-20261015-c3/HOLDOUT_INSTRUMENTATION_INTERVAL.json).
Holdout vẫn tiếp tục; interval này không bị gán normal hoặc âm thầm loại khỏi
evidence. Khi tính kết quả cuối, cần báo sensitivity riêng cho phần exposure
worker1 giao với interval này.
Evaluator [matched_holdout.py](sentinel_pulse/matched_holdout.py) đã chạy từ
13:54:41 UTC+7. Đọc các segment đã seal, kiểm tra hash features/decisions/issues,
đối chiếu thứ tự 249 cột với R4 rồi dựng rolling-10 và history-3 cho từng arm.
Mỗi arm dùng đủ ba seed; không refit hoặc thay ngưỡng khi thấy prediction.
Các model chỉ có trên workload thực sự xuất hiện trên node được chấm; coverage
21 key được tổng hợp trên cả ba node sau khi đọc hết dữ liệu.

Output: `/mnt/sentinel-pulse-archive/matched-parallel-r4-20261015/normal-holdout-evaluation`.
`START.json` bind mã evaluator, đăng ký holdout và audit model. `SEGMENTS.json`
ghi segment đã chấm; từng segment có `RESULTS.json` và
`positive-windows.jsonl.gz` giữ đủ prediction dương, identity, timestamp,
tree/support scores và model tag. Thời gian scored được lấy hợp các khoảng
replica/node; episode prediction gộp theo workload/arm/seed với khoảng yên
15 giây. Đây là episode **chưa adjudicate**, chưa phải false alert đã xác nhận.

Job evaluator chạy qua systemd, độc lập SSH. Đây là replay offline nên không
đo kernel→alert live. Capture và Pulse preview vẫn chạy đồng thời; chưa mở
fresh blind campaign. Code đã qua kiểm thử so context với preprocessing R4,
reset khi gap/ineligible, chống sai identity/schema/hash, giữ prediction dương
và không tự biến chúng thành FP/TN. Source/runtime đã được đồng bộ bằng Git.

## 3. Thuật ngữ sử dụng

| Thuật ngữ | Nghĩa và cách hiểu đúng |
|---|---|
| Syscall ID/ABI | Số định danh theo kiến trúc/giao diện kernel; không dùng nguyên ID x86-64 cho ARM/Windows |
| Explicit channel | Feature riêng cho syscall cụ thể, ví dụ log-count/ratio connect |
| Full-ID histogram/delta | Số đếm theo từng ID ngoài cả tập 29; dùng để thử bổ sung kênh |
| Entry/count | Lần gọi được hook quan sát, chưa đồng nghĩa syscall thành công |
| Arm/variant | Một cấu hình feature để so sánh; không phải một attack mới |
| Addition study | Thêm kênh ngoài tập hiện tại và đo lợi ích tăng thêm |
| Ablation/grouped ablation | Bỏ kênh / bỏ cả nhóm tương đương để kiểm tra đóng góp |
| Seed | Hạt ngẫu nhiên đã khóa; phải báo tất cả seed, không chọn seed tốt nhất |
| Observable | Toàn bộ thứ sensor/feature/runtime thực sự nhìn thấy, không chỉ số chiều vector |
| Cohort | Nhóm capture thu cho một vai trò: selection hoặc evaluation |
| Selection/training prefix | Phần normal được phép dùng để rank ID và fit |
| Calibration | Normal suffix riêng để biến score thành p-value/ngưỡng |
| Temporal split/embargo | Tách theo thời gian và chừa khoảng cách giữa hai phần để giảm leakage |
| Holdout | Tập chưa dùng fit/tune; sau khi đã xem để phát triển thì không còn là blind |
| Blind attack | Case/binary/seed chưa dùng tune, khóa trước evaluation; không chỉ đổi tên attack cũ |
| Matched/paired | Các arm được chấm cùng observable, workload, interval và trial |
| Raw positive | Model gắn cờ; chưa có ground truth nên chưa tự gọi là FP |
| Confusion matrix | TP/FP/TN/FN theo cùng đơn vị interval/trial, unknown báo riêng |
| Recall@budget | So recall khi thỏa ngân sách false alert đã đăng ký |
| Non-inferiority | Chấp nhận tập nhỏ hơn nếu recall không kém base quá biên đã định trước |
| Block bootstrap/CI | Lấy mẫu lại theo khối phụ thuộc để ước lượng khoảng bất định, không coi window chồng lấn là IID |
| Feature importance | Mức phụ thuộc của model vào feature; không tự chứng minh root cause hay feature tối ưu |
| SHA-256/seal | Checksum/binding file để phát hiện thay input/artifact, không phải nhãn chất lượng |

## 4. 29 syscall đến từ đâu?

Tên/ID được đối chiếu [bảng ABI Linux x86-64 v6.8](https://raw.githubusercontent.com/torvalds/linux/v6.8/arch/x86/entry/syscalls/syscall_64.tbl).
Tập feature nằm trong [TRACKED_SYSCALLS](sentinel_pulse/features.py), đối chiếu
header [pulse_counter_ids.h](sentinel_pulse/ebpf/pulse_counter_ids.h).
Bảng ABI chứng minh **ánh xạ**, không chứng minh nên chọn đúng tập 29.

| Nhóm giả thuyết | Syscall tường minh |
|---|---|
| File/I/O | read, write, open, close, chmod, openat |
| Bộ nhớ | mmap, mprotect |
| Network | socket, connect, accept, sendto, recvfrom, accept4, recvmmsg, sendmmsg |
| Process | clone, execve, execveat, clone3 |
| Quyền/namespace/sandbox | ptrace, setuid, setgid, capset, pivot_root, mount, unshare, setns, seccomp |

Các ID khác vẫn góp vào other/total, syscall bins và transition bins.
Hash collision không cho phép suy ra count riêng của một ID từ bucket.
Bỏ explicit channel nhưng giữ bins chỉ đo **giá trị tăng thêm của kênh tường minh**,
không phải loại hết mọi thông tin của syscall đó khỏi model.

Frequency C3 selection: **185.303.624 entry, 135 ID quan sát được**; 29 ID
chiếm **35,7347% lượt gọi**, không phải 35,7% danh mục syscall Linux.
Bảy kênh bằng 0 trong normal: ptrace, pivot_root, mount, unshare, recvmmsg,
setns, execveat. Không được loại chúng chỉ vì hiếm: phải đánh giá trên threat
model và attack. Ngược lại futex/epoll nhiều không bảo đảm giúp recall.

Nguồn: [frequency artifact](validation-evidence/pulse-parallel-completion-20261014/selection-frequency-description.json),
[kiểm chứng ID/tên](validation-evidence/syscall-selection-20261007/selection-evidence.json).

## 5. Thiết kế R4 matched với Pulse

Luồng: capture cùng snapshot 500 ms → selection đã seal → temporal split →
feature của từng arm → fit ExtraTrees/support theo workload và seed →
calibration → manifest/artifact. **Không đưa attack evaluation vào fit.**

- Giữ full-ID delta, transition bins, rolling-10, history 3 và idle handling.
  Baseline 249 chiều; arm thêm/bớt kênh có thể đổi số chiều, phải bind schema riêng.
- Selection đăng ký **00:58:40–02:28:40 ngày 15/10, UTC+7**; train/calibration
  chia theo thời gian, embargo ≥2 giây, reset history tại biên/gap/identity.
- Tần suất chọn top ID chỉ lấy training prefix. Các arm dùng cùng nguồn và
  quy tắc lấy context, không rank theo holdout hoặc attack.
- Ba seed **73021, 73022, 73023**. Cap train 3.000 và calibration 1.500
  context theo quy tắc đăng ký; không chọn cấu hình dựa trên kết quả test.

| Arm | Vai trò |
|---|---|
| base29 | Mốc tham chiếu tập hiện tại |
| plus_top8 / plus_top16 / plus_top32 | Thêm syscall ngoài danh sách theo rank training |
| plus_security | Thêm 15 syscall theo threat model, không phụ thuộc tần suất |
| plus_all_observed | Thêm toàn bộ ID quan sát trong training prefix |
| plus_all_defined_native | Xét tập native ABI đã đăng ký, không chỉ ID đã thấy |
| drop_accept_pair | Bỏ accept và accept4 |
| drop_open_pair | Bỏ open và openat |
| drop_exec_pair | Bỏ execve và execveat |
| drop_clone_pair | Bỏ clone và clone3 |

Nhóm rare-security đăng ký gồm init_module, delete_module, kexec_load,
add_key, request_key, keyctl, open_by_handle_at, process_vm_readv/writev,
finit_module, bpf, userfaultfd và io_uring_setup/enter/register.
Việc có arm không có nghĩa đã có blind result hoặc syscall được phép thành công.

R3 đủ index 21 key nhưng fit 627/693: hai Kafka operator chỉ có 678 calibration
context vì đọc thiếu segment cuối. R4 đã chờ sealed segment phủ hết selection;
mỗi operator có 5.734 train và 2.741 calibration context trước cap. Giữ nguyên
R3, không thay unknown cũ bằng kết quả mới.

## 6. Kết quả đã có và giới hạn

| Phần | Kết quả | Được kết luận gì? |
|---|---|---|
| C2 ablation | 608 model = 19 key × 32 variant | Có artifact/replay; thiếu notification/payment so với Pulse 21 key |
| C3 normal | 30 capture, selection/holdout × 5 regime × 3 worker | Có coverage qua steady, toolmix, peak, burst, recovery |
| C4 | Full raw flags 43,57%, rolling-5 khác training rolling-10 | Không hợp lệ để kết luận quality/FPR |
| C6 | Sửa 781.239 rows và chấm 608 model; full 11.989/334.655 = 3,5825% raw positives | Sửa preprocessing, không chứng minh recall tốt hơn |
| A2 addition exploratory | 105/105 model, 0 unknown | Pipeline hoàn tất trên histogram 1 s đã lộ; không matched Pulse 500 ms |
| R4 matched | 693/693 fit; 693 artifact hash đã audit | Bộ fit integrity hợp lệ; chưa có normal metric, chưa chọn arm, chưa có paired blind matrix |

[Receipt C3/C6](validation-evidence/pulse-parallel-completion-20261014/SUMMARY.json),
[C6 verification](validation-evidence/pulse-parallel-completion-20261014/c6-verification.json),
[R3/R4 evidence](validation-evidence/pulse-matched-r3-r4-20261015/README.md).

Holdout C3 đã được xem qua C4/C6 nên chỉ còn exploratory. Normal ablation
không đánh giá được utility bảo mật của kênh luôn bằng 0. Không ghép hàng triệu
normal windows với vài trăm attack intervals để tạo matrix khác đơn vị.

## 7. Luật chọn và tiến độ hoàn thiện

Protocol [v2](sentinel_pulse/protocol/syscall-selection-evaluation-v2.json) đăng ký:

- Endpoint chính: scenario-trial recall tại ngân sách false alert khác 0.
- One-sided 95% upper bound ≤ **0,1 false-alert episode/valid workload-hour**.
  Không nhầm ngân sách này với interval target 5% của development Pulse.
- Chọn tập explicit nhỏ nhất có paired 95% lower bound chênh recall so base29
  **> −3 điểm phần trăm**, đồng thời thỏa ngân sách false alert; thiếu power
  hoặc coverage thì kết luận inconclusive, không ép chọn.
- CI block bootstrap 10.000 lần, clustered/paired; kiểm soát nhiều so sánh
  theo protocol. Không coi hàng trăm nghìn context chồng lấn là độc lập.

| Bước | Trạng thái |
|---|---|
| Full-ID capture, frequency, exploratory ablation/addition | Đã có |
| 21-key matched arms, grouped/threat-model arms, 3 seed | Đã fit đủ 693 model |
| Xác minh đủ artifact/freeze arm | Đã xác minh 693 SHA-256; freeze phục vụ đánh giá, không promote |
| Normal holdout mới độc lập, có health/adjudication | Đã đăng ký lúc 15/10 12:38:32 UTC+7; đang thu, đủ 24 giờ dự kiến 16/10 12:38:32 UTC+7; sau đó seal/review |
| Evaluator mọi arm trên cùng 500 ms | Đang chạy nền; đã có segment đầu, tiếp tục chấm khi segment mới đóng |
| Blind binary/cases/seed mới và benign-exec controls | Chưa chạy; chỉ mở sau normal review và policy/evaluator binding |
| Paired attack/control cho mọi arm | Chưa hoàn tất |
| Matrix, recall@budget, CI, importance trên evaluation tách biệt | Chưa hoàn tất |
| Kết luận giữ/bỏ/thêm syscall | Chưa đủ bằng chứng |
| Xác nhận trên đúng live observable rồi cân nhắc đổi Pulse | Chưa thực hiện |

Kế hoạch prospective có 8 family ×21 key ×3 rate ×5 seed = **2.520 attack
interval**, đây là **kế hoạch chưa chạy xong**, không phải kết quả đo.
OS hiện được kiểm chứng là Linux native x86-64 trên cụm Ubuntu; Windows/ARM,
cross-kernel và cross-distro cần backend/ABI guard và đánh giá riêng.

## 8. Kiểm tra tiếp và nguồn code

    sudo systemctl show pulse-matched-worker-parallel-20261015.service -p ActiveState -p MainPID -p NRestarts
    sudo systemctl show pulse-syscall-holdout-r4-20261015.service -p ActiveState -p MainPID -p MemoryCurrent
    python3 -m json.tool /mnt/sentinel-pulse-archive/matched-parallel-r4-20261015/normal-holdout-evaluation/STATUS.json
    sudo python3 -m json.tool /mnt/sentinel-pulse-archive/matched-parallel-r4-20261015/syscall-matched-study/R4_FIT_AUDIT.json

Code: [matched_study.py](sentinel_pulse/matched_study.py),
[frequency](sentinel_pulse/syscall_frequency_report.py),
[ablation](sentinel_pulse/syscall_ablation.py),
[addition](sentinel_pulse/syscall_addition_experiment.py).
Bước kế tiếp là chờ đủ 24 giờ normal sau freeze; evaluator đồng thời chấm dữ
liệu đã seal. Sau đó xác minh 21 workload keys, valid exposure, alerts và health
intervals, review nhãn và chạy blind paired trials theo protocol. Không thay candidate Pulse chỉ vì arm có ít
raw positives hơn. Không thêm recovery job; capture hiện tại chạy độc lập dưới
systemd và đủ thời gian cho mốc holdout đã đăng ký.
