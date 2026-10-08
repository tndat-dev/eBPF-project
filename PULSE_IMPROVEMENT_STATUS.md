# Sentinel Pulse — cải thiện theo confusion matrix kỳ vọng

Cập nhật trạng thái hiện hành từ SSH ngày **08/10/2026, 09:07 ICT**.
Bằng chứng và checksum: [inspection](validation-evidence/pulse-improvement-20261008/inspection.json),
[kết quả paired cuối](validation-evidence/pulse-improvement-20261008/paired-final-inspection.json).
Không thay model/policy của phép đo baseline đã hoàn thành.

## 1. Mục tiêu, không phải kết quả

Protocol mới: [pulse-improvement-expectations-c1.json](sentinel_pulse/protocol/pulse-improvement-expectations-c1.json).
Precision ≥95%, recall ≥95%, interval FPR ≤5%; kernel-to-alert p95 ≤2 giây.
Đơn vị accuracy là interval của target 45 giây, prediction horizon 15 giây.
Không ghép TN theo window với TP theo interval. Không yêu cầu FP=0 và không
dừng thu chỉ vì chất lượng chưa đạt. Safety/integrity vẫn phải được bảo vệ.

Ví dụ kỳ vọng nếu có đủ **475 positive và 475 negative interval có nhãn**:

| Nhãn | Có alert | Không alert |
|---|---:|---:|
| Attack | TP ≥452 | FN ≤23 |
| Normal | FP ≤23 | TN ≥452 |

Đây là ngân sách minh họa, không phải confusion matrix đã đo. Với coverage
khác, phải dùng mẫu số thực. Unknown được công bố riêng và không bị xóa
khỏi tỷ lệ phát hiện end-to-end. Precision benchmark không đại diện mặc nhiên
cho precision production với attack prevalence rất thấp.

## 2. Kết quả baseline đã chốt

Attack đủ **475/475 receipt**, normal-control đủ **475/475 receipt**, finalizer
đã xuất `/home/dat/sentinel-pulse-paired-results/pulse-paired-c1-20261008/RESULTS.json`.
Cả hai service đã `active/exited`, `ExecMainStatus=0`, `NRestarts=0`; không còn
đợi soak/attack/control ngầm ở các campaign này.

| Nhãn protocol, interval đủ chứng cứ | Có alert | Không alert |
|---|---:|---:|
| Attack | 140 | 257 |
| Normal theo protocol | 0 | 431 |

Còn **78 attack unknown** và **44 normal unknown/uncertain**. Normal label
là giả định protocol cùng health context, chưa phải review nhãn độc lập.
Precision protocol tạm tính **100%**, FPR protocol **0%**; các chỉ số
adjudicated vẫn `null`. Không suy từ đây rằng production không false positive;
alert Redis ở soak vẫn chưa adjudication.

Recall có điều kiện **140/397 = 35,26%**. Phát hiện end-to-end
**140/475 = 29,47%**. Latency trên riêng **140 hit**: p50 **0,650 s**,
p95 **1,538 s**, p99 **4,511 s**. Timestamp bắt đầu từ Tetragon kernel
exec-entry của binary thử, không chứng minh timestamp syscall độc hại đầu tiên.
**Baseline chưa đạt kỳ vọng recall**, không được tuyên bố stable/production-ready.

Controller seals và raw provenance/decision tails trên master đã được audit.
Finalizer chưa rehash từ xa tất cả raw artifact của worker; giới hạn này giữ
nguyên trong báo cáo. Một vòng đánh giá hoàn chỉnh không đồng nghĩa chất lượng đạt.

## 3. Nguyên nhân đã có bằng chứng

### 3.1. Điểm mù của collector đối với seccomp

Probe riêng trên worker `.238`, kernel **6.8.0-138-generic**, chỉ theo dõi
cgroup của chính unit thử nghiệm. Child tự cài filter ERRNO/EPERM, không
đổi seccomp của AIMS, không external network hay persistent write.

| Lời gọi trong probe kiểm chứng | Kết quả fixture | `raw_tp/sys_enter` | `fexit/__seccomp_filter`, return −1 |
|---|---:|---:|---:|
| `mprotect` được phép | 40 thành công | 40 | 0 |
| `setns` bị filter chặn | 20 EPERM | 0 | 20 |
| `seccomp` bị filter chặn | 20 EPERM | 0 | 20 |

[Receipt, BTF/build checksum và exit status](validation-evidence/pulse-improvement-20261008/seccomp-visibility.json).
Đây là phép kiểm chứng visibility, **không phải thêm 40 TP vào attack matrix**.

Linux 6.8 kiểm tra seccomp trước `trace_sys_enter`; nhánh skip có thể trả về
trước tracepoint. [Mã kernel entry](https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/entry/common.c),
[mã seccomp](https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/seccomp.c).
Do đó phải thu bổ sung trước khi đòi model phát hiện lời gọi không xuất hiện
trong dữ liệu. Return −1 có thể là skip/emulation, không luôn đồng nghĩa denied;
KILL không nhất thiết quay lại fexit, TRACE recheck phải tránh đếm đôi.

Collector frozen hiện chưa ghi giá trị thực cho `seccomp_denied`; giá trị
mặc định 0 ở feature không phải bằng chứng không có syscall bị chặn. Hook
probe chưa được ghép vào collector/model production. RuntimeDefault kiểm tra
trước đó cho phép syscall `seccomp`; **không suy rằng scenario seccomp API
cũng bị chặn như fixture**. Nó còn có vấn đề policy/model riêng.

### 3.2. Policy và khả năng nhận diện của model

Policy frozen không có `mprotect`/`seccomp` trong security activity fields.
Ngoài conformal anomaly còn có score > calibration maximum + margin,
semantic corroboration và temporal confirmation. Vì vậy raw anomaly chưa
chắc ra alert, kể cả telemetry đủ.

Phân tích stream đã hoàn tất trên prefix **467 interval**, không phải full
475. Receipt trong `inspection.json`, trường `gate-diagnosis-streamed.json`.
Đây là mô tả test đã nhìn thấy, không dùng để fit/tune hay chứng minh candidate mới:

| Điểm giới hạn đầu tiên trên prefix | Interval |
|---|---:|
| Có phát hiện | 136 |
| Không có raw model anomaly trong horizon | 31 |
| Bị score-excess veto | 13 |
| Semantic hoặc event-time join không đồng thời | 168 |
| Có same-window evidence nhưng thiếu confirmation/attribution | 42 |
| Infrastructure unknown | 77 |

Không được cộng các veto thành TP giả nếu bỏ gate: policy khác phải đo normal
và attack lại. Giảm gate có thể tăng cả recall và false alert.

Nhiều feature bằng hằng số trong normal training. Swap/multiply không tạo
giá trị khác cho tọa độ luôn bằng 0; ExtraTrees không học split cho tọa độ
không biến thiên. Đây là lý do thử nhánh learned support, không phải khẳng
định mọi miss đều xuất phát từ feature hằng số.

### 3.3. Lỗi thực thi thí nghiệm

Đã sửa `attack_trial.select_target`: dùng namespace/controller/container từ
cgroup resolver, không chọn pod bằng prefix đơn thuần. Test chứng minh Redis
không chọn nhầm Redis Sentinel ngay cả khi trùng tên container. **Source frozen
đã chạy matrix không bị sửa**, unknown cũ không được rerun/xóa.

RabbitMQ read-only root và waypoint thiếu môi trường staging vẫn cần một
execution contract phù hợp trước phép đánh giá mới. Không tắt hardening hoặc
tiêm sang cgroup khác rồi nhận là coverage của container chính.

## 4. Nhánh model bổ sung đã thực nghiệm

Code: [support_model.py](sentinel_pulse/support_model.py),
[support_experiment.py](sentinel_pulse/support_experiment.py).
Tên artifact **PulseSupportEnsemble**, không đổi tên/chèn đè PulseExtraTrees.

Giữ nguyên trọng số forest. Học khoảng support q01–q99 của từng feature từ
normal training prefix, tính max standardized excess trên 249 tọa độ của
window hiện tại. Calibration normal suffix chuyển support score thành p-value.
Kết hợp hai nhánh bằng `min(1, 2 × min(p_tree, p_support))`.

Ngân sách đăng ký 5%/interval 30 window: alpha chung `0,05/30`, mỗi nhánh
chịu correction ×2; cần tối thiểu **1.199 calibration examples/nhánh**.
Không dùng attack sample, không ép threshold khi thiếu calibration.
Đây chỉ là ngân sách thiết kế; drift hoặc mất tính exchangeability có thể
làm FPR thực tế khác kỳ vọng, phải đo trên dữ liệu mới.

### Kết quả normal holdout, không phải confusion matrix live

Fit **21/21 artifact**, service `sentinel-pulse-support-experiment.service`
đã completed thành công. Dữ liệu holdout có **19 workload × 1.024 context =
19.456**; notification/payment thiếu holdout, không tính chúng là 0 FP.
Holdout độc lập với training theo nguồn/hash/thời gian, nhưng đã được xem
trong phân tích trước: chỉ dùng như evidence phát triển exploratory.

| Cách score trên cùng normal contexts | Raw anomaly |
|---|---:|
| Tree ở alpha original 0,001 | 274 / 19.456 = 1,408% |
| Tree ở ngân sách nhánh mới 0,0008333 | 142 / 19.456 = 0,730% |
| Ensemble ở ngân sách chung mới | 152 / 19.456 = 0,781% |
| Chỉ support thêm, tree nhánh mới không flag | 10 context |

Nhánh support flag tổng 18 context, 8 trùng tree. **Giảm 274 →152 chủ yếu
đến từ đổi ngân sách ngưỡng, không phải chứng minh support giảm false positive.**
Ở matched branch budget, support làm tăng 142 →152 raw anomaly normal.
Các đóng góp support trên normal tập trung ở syscall/transition hash bins.
Chưa có policy alert FPR, recall hay precision của ensemble; các trường đó
giữ `null`. Không dùng batch time/1.024 để gọi là latency inference live.

Code phân tích đúng ngân sách: [support_analysis.py](sentinel_pulse/support_analysis.py).
Benchmark riêng [benchmark_support.py](sentinel_pulse/benchmark_support.py)
đo từng context, gồm tree/support/p-values; không đo kernel-to-alert.
Đã đo **19 workload ×64 =1.216 single-context inference** trên master `.234`:
p95 lớn nhất giữa các workload **29,998 ms**, p99 lớn nhất **33,744 ms**.
[Receipt có từng mẫu và checksum](validation-evidence/pulse-improvement-20261008/support-inference-benchmark.json).
Không phải pooled percentile hay benchmark trên worker/attack. Chỉ 64 mẫu
mỗi workload nên p99 là exploratory, không chứng minh tail production.
Launcher yêu cầu CPU quota 100%, RAM 1 GiB; unit transient đã được GC sau
khi hoàn thành, giá trị quota đọc lại lúc kiểm tra không tái lập config lúc chạy.
Artifact ensemble chưa được serving runtime v2 chấp nhận và chưa deploy để
phát alert production. Không bypass manifest/type checks để ép chạy.

## 5. Công việc tiếp theo để tiến đến kỳ vọng

1. Thu bổ sung seccomp skip/emulation với semantic/schema đúng; kiểm chứng
   double-count, task identity, coverage và overhead. Không gắn nhãn tất cả
   skip là attack. Feature contract thay đổi thì cần normal baseline mới.
2. Candidate mới phải khai báo các security field thực sự hỗ trợ, calibration
   và decision policy cùng nhau. So sánh model-only và full policy; không
   sửa ngưỡng để vừa khít 475 interval đã nhìn thấy.
3. Thu normal độc lập có peak/burst/recovery/rollout cho cả 21 container, rồi
   kiểm tra nhánh support có gây alert do thay đổi tải hợp lệ hay không.
4. Đóng băng candidate hoàn chỉnh trước bộ attack/normal mới; giữ mọi miss,
   alert và unknown. Lấy confusion matrix/CI theo đơn vị interval, phân nhóm
   workload/scenario/regime và công bố detection-within-2s cùng recall.
5. Chỉ công bố đạt kỳ vọng khi cả accuracy, coverage và latency có evidence.
   Không đặt trần thời gian hoàn thiện bằng cách loại các khoảng xấu khỏi mẫu.

Thí nghiệm chọn kênh syscall **608/608 fit đã hoàn thành**; chưa deploy subset.
[Trạng thái riêng](SYSCALL_FEATURE_EXPERIMENT_STATUS.md). Các artifact/evidence
vẫn giữ, không xóa dữ liệu cũ để che kết quả.

## 6. Vận hành và giới hạn

Fit support chạy trên VM `.234` bằng system service enabled, checkpoint/hash
binding, CPU quota 150%, RAM 4 GiB, nice 15. Source fit pinned
`025b37e7108b11f86a28b9bb9e37f6e1b70a3665`; đóng SSH/tắt laptop không dừng job.
Sau terminal, khởi động lại chỉ kiểm tra kết quả, không train lại; chưa chủ
động reboot cụm để test. Phân tích matched-budget chạy source `2fabcf2` riêng.

Job chẩn đoán ban đầu materialize decision tails; đã đổi sang đọc streaming
để giới hạn bộ nhớ theo record thay vì kích thước tail. Đã dừng
**chỉ unit chẩn đoán cũ**, unit streaming mới thành
công. Không dừng/restart soak, attack hay control để sửa job phân tích.

Git giữ source hiện hành trên host và reporting checkout của VM; các source
runtime đã đăng ký/frozen giữ commit riêng. “Đồng bộ code” không đồng nghĩa
ghi đè source của một thí nghiệm đang/chạy xong.

Regression host: **1.049 test qua, 7 skipped, 20 subtest qua** trong 26,07 s
(`python -m pytest tests -q`). Bao gồm binding/checksum, calibration resolution,
matched-budget analysis, target selection và timing. Test fixture không được
đưa vào số liệu precision/recall thực nghiệm.
