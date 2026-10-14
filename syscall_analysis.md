# Phân tích syscall và bằng chứng lựa chọn feature của Sentinel Pulse

## Trạng thái thực nghiệm hiện hành

Kiểm tra SSH **14/10/2026 09:10 UTC+7**: bộ C2 đã fit, load và replay **608/608
model** (19 workload × 32 biến thể); score sai lệch lớn nhất 0, p-value và
decision khớp kết quả C2 đã lưu. Đây là kiểm tra tái lập trên dữ liệu đã xem.

Capture normal soak đã hoàn tất 86.400 giây/node trên cả ba worker; shadow đã
đọc tới cuối file, chưa audit đủ decision coverage. Job C3 trên `.234`
enabled/active, đã chấp nhận selection **steady, toolmix, peak, burst**;
**recovery** gặp 16 attempt lỗi cgroup churn do HPA. Đã thêm bước đợi target
ổn định 360 giây qua amendment; attempt 17 đang settling. Tiếp theo là
vòng năm regime holdout riêng. C3 thu full-ID histogram và feature 249 chiều/500 ms.
Nguồn, receipt, ngân sách, schema và lệnh kiểm tra nằm trong
[SYSCALL_CAPTURE_C3.md](SYSCALL_CAPTURE_C3.md).
Phân tích root cause: [SYSCALL_C3_RECOVERY_INCIDENT.md](SYSCALL_C3_RECOVERY_INCIDENT.md).

Preflight trên 12 capture selection đã seal xác minh **313.318 feature rows**:
**269.036 context bốn window** đủ điều kiện schema/identity/revision/cadence;
6.592 warming rows; 37.659 rows không có model C2 (notification/payment);
31 rows ngoài biên probe. Có 2.492 lần reset history vì không liền kề, không nối
giả qua gap. Các bộ đếm này chưa adjudicate health/nhãn normal, không phải TN/FP
hay kết quả đánh giá chất lượng. Tool không chấm model hoặc đọc score holdout.
Evidence: `syscall-capture-c3-r2/selection-preflight-20261014.json` trên NFS.

Chưa có kết quả blind mới cho từng biến thể, nên **chưa kết luận syscall nào
nên giữ/bỏ từ thực nghiệm hoàn chỉnh**. Histogram cung cấp tần suất; ablation
và paired blind evaluation mới trả lời đóng góp phát hiện. Kế hoạch chấm đã
đăng ký interval workload 30 giây, bootstrap block 10.000 lần, CI 95% và Holm;
không dùng normal holdout/blind để tune rồi báo lại như kiểm định độc lập.

## Nguồn định nghĩa và cơ sở lựa chọn

ID/tên syscall được đối chiếu với bảng ABI x86-64 chính thức của [Linux v6.8](https://raw.githubusercontent.com/torvalds/linux/v6.8/arch/x86/entry/syscalls/syscall_64.tbl). Các worker đang chạy kernel 6.8.0-138-generic. Bảng ABI chứng minh ánh xạ ID/tên, không chứng minh tập syscall được chọn là tối ưu để phát hiện attack.

`sentinel_pulse/features.py::TRACKED_SYSCALLS` định nghĩa **29** syscall tường minh:

| Nhóm giải thích kỹ thuật | Syscall (ID x86-64) |
|---|---|
| File/I/O | read(0), write(1), open(2), close(3), chmod(90), openat(257) |
| Bộ nhớ | mmap(9), mprotect(10) |
| Socket | socket(41), connect(42), accept(43), sendto(44), recvfrom(45), accept4(288), recvmmsg(299), sendmmsg(307) |
| Process | clone(56), execve(59), execveat(322), clone3(435) |
| Quyền, namespace, sandbox | ptrace(101), setuid(105), setgid(106), capset(126), pivot_root(155), mount(165), unshare(272), setns(308), seccomp(317) |

Các nhóm trên giải thích giả thuyết thiết kế: quan sát I/O thông dụng và các hoạt động có thể liên quan security. Chưa có bằng chứng rằng 29 syscall này là tập tối ưu. `SENSITIVE_IDS` cũng là lựa chọn engineering; syscall nhạy cảm có thể hoàn toàn hợp lệ. Đếm `sys_enter` ghi nhận lần gọi, không tự chứng minh syscall thành công hoặc là attack.

**Giới hạn visibility đã kiểm chứng:** fixture trên ba worker cho thấy syscall
bị seccomp ERRNO/EPERM chặn có thể không xuất hiện ở `raw_tp/sys_enter`.
Collector riêng đã bổ sung `fexit/__seccomp_filter` và đếm đúng 20 setns +20
seccomp skip mỗi proof. [Receipt và job 500 ms mới](EXTENDED_TELEMETRY_STATUS.md).
Bảng tần suất/importance bên dưới vẫn dùng capture theo contract entry cũ;
không cộng số liệu skip mới vào mẫu số cũ hoặc gọi count=0 là không có attempt.
Contract mới cần baseline/calibration riêng; skip không mặc nhiên là attack.

Syscall ngoài danh sách được gom thành `other`, 64 syscall hash bins và 64 transition bins. Do collision, không thể suy ra tần suất riêng của futex/epoll/... từ bins. Muốn so sánh tập 29 syscall với một tập khác, cần capture thêm histogram theo syscall ID trong thí nghiệm riêng rồi train các biến thể; dữ liệu hiện tại không đủ để khẳng định tập thay thế tốt hơn. Ánh xạ trên không áp dụng trực tiếp cho ARM hay process dùng ABI compat.

## Phạm vi OS, architecture và khả năng chuyển model

Danh sách hiện tại gắn với **ABI native Linux x86-64**, không gắn riêng với Ubuntu. Cần tách ba câu hỏi: ID/tên syscall có đúng không, collector có chạy được không, và model có còn phát hiện tốt không. Đúng ABI không tự chứng minh hai điều còn lại.

| Môi trường đích | Ánh xạ 29 ID/tên hiện tại | Collector và model |
|---|---|---|
| Ubuntu x86-64 native, cụm hiện hành | Đã đối chiếu bảng ABI | Có bằng chứng vận hành trong cụm hiện tại; chưa thay thế blind evaluation |
| RHEL/Fedora x86-64 native | Cùng ABI Linux; đối chiếu UAPI và khả năng syscall của kernel đích | Cần kiểm tra eBPF/BTF, cgroup, quyền và snapshot integrity; đánh giá normal/calibration và blind test của môi trường đích trước reuse model |
| Linux ARM64 hoặc process compat/x32 | Không được dùng nguyên bảng ID hardcode x86-64 | Cần mapping/guard ABI riêng, collector phù hợp và schema/model đã kiểm chứng |
| Windows worker/container native | Không phải ABI Linux | Collector `raw_tp/sys_enter` và schema syscall hiện tại không dùng trực tiếp; chưa triển khai backend Windows |

Nguồn: [Linux syscall ABI](https://www.man7.org/linux/man-pages/man2/syscall.2.html), [eBPF for Windows — giới hạn tương thích hooks/helpers Linux](https://github.com/microsoft/ebpf-for-windows#frequently-asked-questions), [Windows containers trong Kubernetes](https://kubernetes.io/docs/concepts/windows/intro/).

Container Linux không mang một Linux kernel riêng. Ví dụ image Ubuntu hoặc RHEL/UBI chạy trên worker Linux vẫn dùng kernel của worker; thư viện/runtime trong image có thể đổi tần suất syscall và các đường fallback. Windows chỉ là máy người dùng truy cập AIMS thì collector ở server vẫn thu syscall Linux; khác với AIMS chạy trên Windows worker.

Tập 29 có thể giữ đúng tên/ID ở distro Linux cùng ABI nhưng không nhất thiết vẫn là tập feature tốt nhất. Kernel, libc/runtime, probe, traffic và revision khác có thể làm baseline thay đổi. Collector phải phân biệt ABI không hỗ trợ, telemetry không quan sát được và count thực sự bằng 0; syscall entry không chứng minh syscall thành công.

Đối với paper, bằng chứng hiện tại chỉ thuộc cụm Ubuntu Linux x86-64 đã đo. Cross-distro và cross-kernel evaluation là thí nghiệm riêng chưa chạy: khóa source/feature schema, dùng cùng workload và traffic trên môi trường đích, so sánh reuse model với calibration/train normal của môi trường đó, rồi test blind. Không công bố hỗ trợ Windows/ARM hoặc recall đa-OS dựa vào sáu node Ubuntu.

Nếu sau này mở rộng Windows, hướng thiết kế là backend telemetry riêng, chẳng hạn [ETW](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal), cùng schema sự kiện hành vi có version/khả năng quan sát và calibration riêng. Đây là hướng nghiên cứu, không phải luồng đang deploy; không ánh xạ giả Windows thành 29 syscall Linux hay đưa dữ liệu đó vào model 249 chiều hiện hành.

## Kiểm chứng nguồn và đủ 29 syscall

Kiểm tra ngày 07/10/2026 bằng `sentinel_pulse.verify_syscall_selection`. **Trong project chưa có nguồn thống kê chứng minh AIMS phải dùng đúng 29 syscall này.** Đây là tập feature engineering do project chọn trước. Nguồn Linux cung cấp tên/ID, còn dữ liệu capture cung cấp tần suất thực tế; hai loại bằng chứng khác nhau.

Tool kiểm tra ba lớp: bảng ABI native x86-64 Linux v6.8 → `features.py` → `ebpf/pulse_counter_ids.h`. **29/29 ID/tên và thứ tự slot khớp**. Bảng Linux được tải có SHA-256 `4c30abea9a4b69f3409bea7a0c910a8c8feb9a44b22a448b5c82f2bfdd8249c8`. SSH kiểm tra worker .238 là x86_64, kernel 6.8.0-138-generic; hash analysis/ablation trên VM trùng các input report trong Git. Điều này không xác minh mọi process đều dùng native ABI; compat/x32 cần kiểm tra/guard riêng trước khi claim hỗ trợ.

Bằng chứng: [selection-evidence.json](validation-evidence/syscall-selection-20261007/selection-evidence.json). Đây là **tổng hợp số đo capture ngày 05/10 đã phân tích ngày 06/10**, không phải capture mới ngày 07/10. Tool kiểm tra hash liên kết, tổng count, mẫu số rate và đầy đủ 171 kết quả fit; không tự audit lại raw seals.

### Tần suất toàn bộ tập syscall tường minh

Mẫu số: 45.028.993 lần syscall entry, 143.447 rows hợp lệ, 19 workload trên worker .238. “Workload có xuất hiện” nghĩa là count > 0 trong capture này, không phải tổng số workload của cả cụm. Tỷ lệ làm tròn sáu chữ số thập phân.

| Syscall (ID) | Tổng lần gọi | Tỷ lệ toàn capture | Workload có xuất hiện |
|---|---:|---:|---:|
| read (0) | 3,719,902 | 8.261126% | 19/19 |
| write (1) | 774,848 | 1.720776% | 19/19 |
| open (2) | 89,243 | 0.198190% | 2/19 |
| close (3) | 1,886,537 | 4.189605% | 19/19 |
| mmap (9) | 1,567,540 | 3.481179% | 16/19 |
| mprotect (10) | 361,418 | 0.802634% | 15/19 |
| socket (41) | 58,906 | 0.130818% | 17/19 |
| connect (42) | 60,784 | 0.134989% | 17/19 |
| accept (43) | 4,080 | 0.009061% | 5/19 |
| sendto (44) | 662,680 | 1.471674% | 14/19 |
| recvfrom (45) | 2,007,166 | 4.457497% | 14/19 |
| clone (56) | 4,413 | 0.009800% | 4/19 |
| execve (59) | 20,964 | 0.046557% | 13/19 |
| chmod (90) | 1 | 0.000002% | 1/19 |
| ptrace (101) | 0 | 0.000000% | 0/19 |
| setuid (105) | 76,064 | 0.168922% | 11/19 |
| setgid (106) | 76,064 | 0.168922% | 11/19 |
| capset (126) | 12,257 | 0.027220% | 11/19 |
| pivot_root (155) | 0 | 0.000000% | 0/19 |
| mount (165) | 0 | 0.000000% | 0/19 |
| openat (257) | 2,261,640 | 5.022631% | 18/19 |
| unshare (272) | 0 | 0.000000% | 0/19 |
| accept4 (288) | 36,886 | 0.081916% | 15/19 |
| recvmmsg (299) | 0 | 0.000000% | 0/19 |
| sendmmsg (307) | 16,053 | 0.035650% | 6/19 |
| setns (308) | 0 | 0.000000% | 0/19 |
| seccomp (317) | 25,259 | 0.056095% | 11/19 |
| execveat (322) | 0 | 0.000000% | 0/19 |
| clone3 (435) | 6,526 | 0.014493% | 11/19 |
| other | 31,299,762 | 69.510242% | 19/19 |

**22/29 syscall xuất hiện**, bảy syscall chưa xuất hiện: `ptrace, pivot_root, mount, unshare, recvmmsg, setns, execveat`. Tập 29 chiếm **30,49%** số lần gọi; `other` chiếm **69,51%**. Không được suy ra 69,51% telemetry bị mất: chúng vẫn nằm trong total/other và hash bins, nhưng chưa có tần suất riêng từng ID.

Không xuất hiện trong một capture normal ngắn không chứng minh syscall vô ích. Syscall hiếm có thể quan trọng khi attack, nhưng đó là giả thuyết phải kiểm tra bằng blind attack. Ngược lại, `setuid/setgid/capset` xuất hiện trong dữ liệu normal cho thấy không thể dùng riêng “có syscall nhạy cảm” để kết luận attack.

### Điều ablation hiện tại thực sự chứng minh

Gộp 19 workload, bản full có **274 raw anomaly / 19.456 context (1,4083%)**. Bỏ syscall bins: **354 (1,8195%)**; bỏ count: **335 (1,7218%)**; bỏ transition bins: **169 (0,8686%)**. Đây là thống kê mô tả normal-only, không phải policy FPR hay precision. Các window gần nhau tương quan; không gắn confidence interval IID hoặc kết luận significance từ các tổng này.

Ít anomaly hơn chưa chắc model tốt hơn: mô hình không bao giờ alert cũng đạt normal anomaly rate bằng 0 nhưng không detect attack. Tám nhóm ablation còn chồng lấn (security/volume/count), không tương đương bỏ từng syscall. Phải đo đồng thời FP, recall, latency và overhead trên cùng trial để đánh giá trade-off.

### Thí nghiệm xác nhận vì sao chọn các syscall

Kế hoạch máy đọc được: [syscall-selection-evaluation-v1.json](sentinel_pulse/protocol/syscall-selection-evaluation-v1.json). **Đây là kế hoạch chưa chạy**, không phải kết quả đã đo hay registration hồi tố cho capture đã xem.

Đã thêm collector pilot riêng để thu histogram theo syscall ID chính xác, thay
vì suy ra ID từ hash bins: [runbook pilot](sentinel_pulse/SYSCALL_SELECTION_PILOT.md).
Capture preregistered một node trên worker3 đã hoàn tất và vượt kiểm tra
integrity; kết quả exploratory bên dưới chưa đại diện toàn cluster và không
phải overhead benchmark A/B. Không xem việc biên dịch thành công tự nó là kết
quả thực nghiệm.

1. Thu normal mới với histogram exact theo từng syscall ID trên từng workload/container, có nhãn traffic thật cho steady/toolmix/peak/burst/recovery. Không thể giải mã histogram đầy đủ từ hash bins cũ. Collector bổ sung chỉ gắn trong run riêng sau soak hiện hành; đo CPU/RAM/map integrity và ảnh hưởng throughput trước thu dài.
2. Tách dữ liệu lựa chọn feature, train/calibration normal và evaluation chưa xem theo thời gian/nguồn/revision. Xếp hạng tần suất và chọn top-K chỉ trên dữ liệu phát triển. Không dùng normal test hoặc attack để chọn syscall/threshold.
3. Giữ bản full29; train lại các bản bỏ nhóm, 29 bản bỏ kênh tường minh từng syscall, bản không có kênh tường minh, top-K tần suất + rare-security whitelist và candidate full-ID. Các bản dùng cùng normal source/split/history/alpha/seed/hyperparameter; calibration riêng chỉ từ calibration normal.
4. Chạy cùng một blind attack catalog đã khóa binary/case checksum, nhiều rate/seed, tối thiểu năm trial/scenario/workload. Safety contract vẫn giữ; không tiêm attack trong normal soak. Ghi TP/FP/TN/FN/uncertain, raw model và alert sau policy riêng, cùng kernel-to-alert và overhead. Khoảng attack thiếu telemetry là miss end-to-end; khoảng normal unknown không tính TN.
5. So sánh có cặp theo trial/workload; bootstrap theo block/trial, CI 95% và correction nhiều so sánh. Báo cả latency của detection và số miss, không loại miss khỏi recall. Chỉ gọi nhóm có lợi khi bằng chứng chỉ ra trade-off security/chất lượng/overhead, không chỉ vì score biến động.

**Giới hạn của “bỏ từng syscall”:** mask bốn kênh count/ratio/rolling mean/std không xóa mọi thông tin syscall đó; hash bins, sensitive_ratio và policy vẫn có thể giữ tín hiệu. Thí nghiệm này chứng minh vai trò **kênh tường minh**, không phải việc syscall hoàn toàn không còn được quan sát. Nếu muốn loại hoàn toàn ID/transition liên quan, cần dữ liệu trước hashing đủ để xây lại total/bins/transition; histogram đơn syscall không tái dựng được adjacent transitions.

Cách diễn đạt phù hợp paper hiện tại: “Tập syscall tường minh được chọn từ các nhóm hành vi I/O, mạng, process và privilege; ánh xạ ABI đã xác minh. Capture normal độc lập và ablation normal-only cung cấp bằng chứng tần suất/độ nhạy. Chưa xác nhận tập 29 là tối ưu hoặc mọi syscall đều cải thiện blind recall.”

### Lệnh tái lập tổng hợp, không thay runtime

```bash
python3 -m sentinel_pulse.verify_syscall_selection \
  --analysis validation-evidence/syscall-analysis-20261006/analysis-worker4.json \
  --ablation validation-evidence/syscall-analysis-20261006/ablation.json
```

Dùng `--abi-table <file bảng v6.8>` khi offline. Model và policy trong soak giữ nguyên; JSON kết quả để precision/attack recall/kernel-to-alert là `null`, không thay giá trị kỳ vọng bằng số đo.

## Dữ liệu đánh giá tách biệt

Bundle đang kiểm tra là R10C1, alpha 0,001, window 500 ms, 21 workload/container. Manifest, dataset manifest, training contract và artifact checksum được kiểm tra trước khi phân tích. Capture đánh giá cần khác hash các nguồn training/calibration và nằm sau ngày đóng băng training contract.

Capture sau train của run `pulse-recovery-formal-c1-20261005` được dùng cho phân tích normal độc lập, có seal raw riêng. Run đã kết thúc sớm vì gap; chỉ các snapshot/feature recovery hợp lệ và revision được model chấp nhận mới vào phân tích. Không dùng capture này train/tune candidate đang đo. Vì sự cố đã được xem xét, kết quả này là phân tích exploratory; cần một evaluation mới đã đăng ký để xác nhận kết luận paper.

## Các phép đo đã triển khai trong code

Thí nghiệm offline bỏ từng kênh syscall đã chuyển sang service cố định trên VM `.234`, tiếp tục checkpoint 59 fit sau shutdown host; không thay model production. Phạm vi 19 workload × 32 biến thể và đường dẫn job trong [SYSCALL_FEATURE_EXPERIMENT_STATUS.md](SYSCALL_FEATURE_EXPERIMENT_STATUS.md). Đây là normal-only exploratory, chưa cung cấp blind recall hoặc tập syscall tối ưu. Danh sách VM full-ID/cross-distro tiếp theo tại [SYSCALL_EXPERIMENT_VM_PLAN.md](SYSCALL_EXPERIMENT_VM_PLAN.md); các VM đó chưa được tạo/kiểm chứng trong lượt này.

`sentinel_pulse/syscall_analysis.py` thực hiện:

- Tần suất exact: tổng count, tỷ lệ trên tổng syscall và count/container-second, tách từng workload/container và regime. `other` được giữ nguyên, không suy diễn syscall bên trong. Mẫu số container-second khác union workload-hour dùng trong soak.
- Đọc impurity importance từ ExtraTrees, cộng qua bốn vị trí temporal cho mỗi feature. Đây là thống kê về split của mô hình học normal/corruption; không phải tác động nhân quả hoặc recall attack.
- Trên tối đa 1.024 context temporal mỗi workload từ capture độc lập, đo độ thay đổi score khi hoán vị theo block 16 context, ba lần lặp; đồng thời đo độ nhạy khi mask một nhóm feature bằng median. Các context liền nhau vẫn tương quan. Các nhóm gồm count, ratio, syscall bins, transition bins, rolling mean, rolling std, security và volume.
- Xuất context archive có checksum cho ablation retrain riêng. Mẫu context là phần đầu hợp lệ có giới hạn của capture; kết quả không đại diện mặc định cho toàn bộ regime hay cả ngày.

Hoán vị trên tập normal không có nhãn attack chỉ đo **độ nhạy score**. Theo [tài liệu scikit-learn về permutation importance](https://scikit-learn.org/stable/modules/permutation_importance.html), đánh giá importance theo hiệu năng cần scoring phù hợp trên tập đánh giá; feature tương quan còn có thể che vai trò của nhau. Không gọi kết quả normal-only này là predictive permutation importance.

`sentinel_pulse/syscall_ablation.py` train lại baseline full và các biến thể bỏ nhóm feature, dùng đúng dataset normal đã khóa và temporal train/calibration split. Threshold được calibration riêng trên phần calibration; holdout không tham gia fit. Sau đó đo raw-model FP/TN có điều kiện benign trên context holdout. Đây là ablation model; policy semantic đang deploy vẫn giữ nguyên, nên chưa cung cấp hiệu quả end-to-end khi bỏ semantic gate.

## Đánh giá confusion matrix và phần còn cần bổ sung

Normal soak ghi mọi alert nhưng chưa thể kết luận tất cả là FP. Cần adjudication bằng traffic/incident evidence, giữ nhãn uncertain riêng. Đơn vị benchmark đã đăng ký là scenario interval, khác raw-model window và khác alert incident. Không trộn các đơn vị trong một confusion matrix.

Precision = TP/(TP+FP), recall = TP/(TP+FN), FPR = FP/(FP+TN). Chỉ normal data thì thiếu TP/FN; precision/recall để `null`. Mask/permutation làm score thay đổi cũng không chứng minh feature giúp phát hiện attack.

Để chứng minh lợi ích security của tập syscall, còn cần blind attack evaluation tách biệt cho từng ablation, cùng scenario/rate/seed, latency và confidence interval. Trial thiếu telemetry tính là miss trong recall end-to-end, đồng thời báo recall có điều kiện telemetry hợp lệ. Khoảng normal thiếu dữ liệu là unknown, không tính TN. Bootstrap nên theo block thời gian hoặc trial/workload để tránh coi các window liên tiếp là mẫu độc lập.

## Kết quả thực nghiệm hiện hành

Đã chạy trực tiếp trên VM, lấy kết quả và kiểm tra liên kết checksum giữa analysis và ablation. Bằng chứng lưu trong [analysis-worker4.json](validation-evidence/syscall-analysis-20261006/analysis-worker4.json) và [ablation.json](validation-evidence/syscall-analysis-20261006/ablation.json). Analysis SHA-256: `4a7c62b3a854c5150d928aaea6cbc7da843f4bdd0002434de51e4ec17e908f49`; capture SHA-256: `37c7662a49fd14976d51a3c7e420522de57907eb1178dc35e45b6f0c9bc620c2`. Hai hash này được ghi lại trong ablation; không dùng số kỳ vọng thay cho số đo.

Capture nằm trên worker `.238`, có **143.447 feature rows hợp lệ và 45.028.993 syscall**, phủ 19 workload/container trong bundle 21 workload. 253 rows bị loại theo eligibility/revision. Đây không phải coverage toàn cụm. Regime trong capture này là `unlabelled`; chưa có bằng chứng riêng cho từng chế độ peak/burst/recovery. Context đánh giá lấy tối đa 1.024 lịch sử liên tiếp hợp lệ mỗi workload, tổng 19.456 context; mỗi context gồm bốn vector 249 chiều.

### Ví dụ tần suất RabbitMQ

`production/aims-rabbitmq-server:rabbitmq`: 6.367 rows, tổng 1.445.750 syscall.

| Counter | Tổng lần gọi | Tỷ lệ tổng syscall |
|---|---:|---:|
| other | 1.061.410 | 73,42% |
| read | 186.796 | 12,92% |
| write | 92.493 | 6,40% |
| recvfrom | 66.161 | 4,58% |
| openat | 15.923 | 1,10% |
| close | 13.397 | 0,93% |

Các số này chứng minh read/write/recvfrom có mặt đáng kể trong capture này, không chứng minh đó là feature tối ưu. Tỷ lệ `other` giữa các workload từ 55,13% đến 97,45%: tập syscall tường minh chưa giải thích đầy đủ hành vi. Hash bins giữ tín hiệu tổng hợp nhưng không thay thế histogram syscall ID để diễn giải từng syscall.

### Feature quan trọng theo mô hình đã đóng băng

Importance cộng qua bốn vị trí temporal, tính bằng impurity importance của các cây. Với RabbitMQ, feature đầu bảng là `log_count:recvfrom` (0,04249) và `rolling_mean:recvfrom` (0,04173). Với search-recommendation, đầu bảng là `rolling_std:openat` (0,03511) và `rolling_std:setuid` (0,03122). Không có một feature đứng đầu chung cho mọi workload.

Đây là importance đối với **bài toán normal/corruption tự giám sát**, không phải bằng chứng `setuid` gây attack. Feature của một syscall ít xuất hiện vẫn có thể được model sử dụng khi phân biệt dữ liệu bị corrupt. Muốn diễn giải một alert cụ thể cần thêm attribution trên đúng context đó và kiểm tra counts/policy.

### Ablation train lại: kết quả normal holdout

Đã hoàn thành **19 workload × 9 biến thể = 171 fit**: full và bỏ tám nhóm feature. Fit dùng dataset normal gốc; threshold calibration lại trên calibration split, không trên holdout. Cột bên dưới là số context được raw model gọi anomalous trong 1.024 context normal của mỗi workload. Chúng **không phải số alert sau semantic/temporal policy**, và không dùng để sửa model đang soak.

| Workload/container | Full | Bỏ count | Bỏ ratio | Bỏ rolling mean | Bỏ rolling std | Bỏ security | Bỏ syscall bins | Bỏ transition bins | Bỏ volume |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| search-recommendation/app | 157 | 225 | 146 | 153 | 165 | 186 | 189 | 115 | 173 |
| Kafka user-operator | 44 | 13 | 11 | 22 | 7 | 38 | 14 | 22 | 0 |
| Redis Sentinel | 33 | 51 | 56 | 43 | 22 | 41 | 113 | 2 | 55 |
| Kafka broker | 7 | 10 | 3 | 5 | 6 | 8 | 4 | 3 | 4 |
| RabbitMQ | 1 | 0 | 1 | 1 | 0 | 1 | 1 | 1 | 1 |

Full raw-model anomaly rate của search-recommendation là **157/1.024 = 15,33%**, Redis Sentinel **3,22%**, RabbitMQ **0,098%**. Đây là dấu hiệu cần phân tích drift và hiệu quả gate; chưa thể nói hệ thống end-to-end có FPR tương ứng. Bỏ nhóm feature đôi khi giảm anomalous rate, nhưng cũng có thể làm giảm khả năng phát hiện attack. Không lựa chọn biến thể chỉ vì nó cho ít anomaly trên normal holdout.

Tổng hợp mô tả trên đủ **19 workload × 1.024 context = 19.456 context cho mỗi biến thể** cho thấy raw-model anomalous contexts như sau:

| Biến thể | Raw anomalous contexts / 19.456 | Tỷ lệ gộp mô tả |
|---|---:|---:|
| Full | 274 | 1,41% |
| Bỏ `log_count` | 335 | 1,72% |
| Bỏ `ratio` | 252 | 1,29% |
| Bỏ `rolling_mean` | 250 | 1,28% |
| Bỏ `rolling_std` | 228 | 1,17% |
| Bỏ `security` | 305 | 1,57% |
| Bỏ `syscall_bin` | 354 | 1,82% |
| Bỏ `transition_bin` | 169 | 0,87% |
| Bỏ `volume` | 259 | 1,33% |

> Đây là tỷ lệ gộp mô tả của **raw model trên normal holdout**, không phải FPR của alert sau policy và không phải ước lượng độc lập: các context thời gian liên tiếp có tương quan, đồng thời mỗi workload được lấy cùng số context. Không dùng bảng này để chọn biến thể hay tuyên bố bỏ `transition_bin` tốt hơn; cần so sánh paired trên blind attack mới và normal test chưa xem, kèm bootstrap theo block/trial.

**Chưa đo:** blind attack recall của từng biến thể, precision end-to-end đã adjudication, latency kernel-to-alert và confidence interval của so sánh attack. Kết quả hiện tại cung cấp bằng chứng tần suất và độ nhạy, chưa đủ chứng minh 29 syscall là tập tối ưu cho paper.

### Tiến độ harness exact-ID và các bước kế tiếp

Đã bổ sung runner/analyzer cho probe exact syscall-ID tại
`sentinel_pulse/syscall_histogram_pilot.py` và
`sentinel_pulse/syscall_histogram_analysis.py` và
`sentinel_pulse/syscall_histogram_cohort.py`. Runner lưu baseline/probe/post,
host/cgroup metrics, cgroup identity snapshots, START/TERMINAL và SHA256SUMS.
Traffic regime chỉ được gán từ receipt preregistered, hash-bound trước khi
attach; interval không nằm trọn trong một regime, sai coverage target, map drop,
telemetry gap hoặc identity thiếu sẽ vẫn được ghi nhận nhưng không được đưa vào
ranking. Không có receipt thì capture là engineering/unlabelled.

Mười regression test tổng hợp cho harness/analyzer/cohort pass trên host; đây
chỉ là kiểm thử logic, tách biệt với capture thật. Run
`syscall-id-histogram-worker3-steady-20261012-001` hoàn tất ngày 12/10/2026:
baseline 300 s, probe 120 s, post 300 s; 119 chu kỳ khoảng 1 s; terminal exit 0.
Analyzer trả `capture_valid_for_feature_selection=true`, không có integrity
problem, telemetry drop, thiếu workload identity hay lỗi traffic receipt. Có 21
cgroup identity trong allow-list, trong đó 7 workload/container có syscall;
tổng **519.421 syscall entries**. 14 identity còn lại không có count trong
capture này; không diễn giải đó là workload chưa chạy hoặc syscall không tồn
tại nói chung.

Capture độc lập worker1
(`syscall-id-histogram-worker1-steady-20261012-001`) hoàn tất exit 0: 117 chu kỳ,
82 cgroup targets, 28 workload/container có count và **2.830.672 entries**.
Analyzer ghi 117/117 integrity record, 48 metadata snapshot dùng được, không có
integrity problem, dropped update, identity gap hay receipt error; map cao nhất
2.142 entries, scan snapshot tối đa 23,63 ms. Capture này có 128 syscall ID
khác nhau; số ID không đồng nghĩa 128 feature tốt hoặc hữu ích.

Cohort analyzer nhận **2/2 capture** trên hai node worker1/worker3, không overlap
hoặc loại run. Tổng **3.350.093 syscall entries**, 128 ID khác nhau, 18 workload
name và 41 hàng workload × container × revision × regime. Trong cohort steady
này, ID/tên syscall native x86-64 được đối chiếu với bảng ABI/header Linux:

| Syscall | ID | Số entry |
|---|---:|---:|
| read | 0 | 333.183 |
| futex | 202 | 315.742 |
| epoll_wait | 232 | 269.977 |
| newfstatat | 262 | 253.636 |
| recvfrom | 45 | 233.544 |
| openat | 257 | 159.523 |
| close | 3 | 150.811 |
| epoll_ctl | 233 | 144.179 |
| fstat | 5 | 143.790 |
| epoll_pwait | 281 | 143.616 |
| nanosleep | 35 | 119.643 |
| mmap | 9 | 103.585 |
| lseek | 8 | 100.592 |

Đây mới là hai capture steady ngắn, trên hai node và một revision/regime tại mỗi
thời điểm; không phủ peak/toolmix/burst/recovery hay mọi replica của AIMS. Count
bằng 0 ở một cgroup hoặc syscall trong hai phút không chứng minh syscall không
được dùng ngoài khoảng đó. Kết quả chỉ mô tả tần suất, không chứng minh syscall
nào nên bị bỏ/giữ và không phải feature importance hay blind detection result.

SHA-256 của cả hai capture, ANALYSIS và COHORT đã xác minh tại NFS
`10.1.16.233:/sentinel-pulse`; raw data nằm ngoài Git. Max snapshot scan lần
worker3 là 4,52 ms, worker1 là 23,63 ms. Pilot process CPU trung bình pha probe
lần lượt 2,01% và 2,33% của một core, peak RSS 47,7 và 52,1 MiB. Đây là tài
nguyên tiến trình pilot, không phải tác động nhân quả lên workload; chưa có A/B
throughput/p99 để ước lượng overhead nhân quả.
Hai offline normal-only refit C1/C2 đều hoàn tất **608/608 fits** (19 workload ×
32 variants), terminal `completed`, errors rỗng; không tự promotion. C1 chỉ có
prediction/score `.npz`, không có model pickle. C2 có 608 model pickle, mọi
SHA-256/size khớp `RESULTS.json`. Manifest gốc C2 lặp prefix `models/`; đã tạo
sidecar `VARIANT_MODEL_MANIFEST.derived.json` trên NFS bằng verifier: kiểm tra
START/RESULTS/TERMINAL binding và đủ 608 model, chỉ sửa path trong sidecar;
file gốc không đổi. SHA-256 sidecar là
`4c379dcabd8ea2c8ca0c19f9e13e186dfa9fe63f0df1ea1a2d4d591e946c4408`.
Đã nạp tuần tự 608/608 pickle bằng venv C2 khớp Python 3.12.3,
scikit-learn 1.9.1, NumPy 2.5.3; mỗi object có estimator `predict_proba` và
calibration scores. Đây chỉ là deserialization/schema check, không phải đo
inference hoặc detection. C1/C2 có cùng input hashes và cùng
model/features/train/encoding hashes, nên không phải hai xác nhận độc lập.
Ablation còn exploratory; precision/recall/kernel-to-alert chưa đo từ blind set
mới. Repo chứa generator và tests; 41 test liên quan pass.

SSH **13/10 02:08 UTC** xác nhận `normal-a1-20261013` capture/shadow unit còn
active/running trên cả ba worker. Không gắn histogram probe hay tiêm attack vào
run đó; Sentinel Pulse không được tinh chỉnh cho đến khi hoàn tất syscall
selection evaluation. Cluster có 6/6 node `Ready`; trạng thái soak ở
[`CANDIDATE_SHADOW_STATUS.md`](CANDIDATE_SHADOW_STATUS.md). Incident
Evicted/DiskPressure trước đó và cleanup được lưu tại `CLUSTER_READINESS.md`.
Checklist thực hiện và điều kiện hoàn tất ở
[`SYSCALL_EXPERIMENT_TODO.md`](SYSCALL_EXPERIMENT_TODO.md); trạng thái C2/pilot
ở [`SYSCALL_FEATURE_EXPERIMENT_STATUS.md`](SYSCALL_FEATURE_EXPERIMENT_STATUS.md).
