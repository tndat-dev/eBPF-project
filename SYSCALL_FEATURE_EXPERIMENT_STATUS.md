# Trạng thái thực nghiệm chọn kênh syscall

Hiện hành xác minh qua SSH **14/10/2026**. Nhánh syscall và Sentinel Pulse
tiếp tục song song; không đợi chọn xong syscall mới triển khai Pulse.
[Lịch/job hiện hành](PULSE_PARALLEL_EXECUTION.md).

## Đã hoàn tất

- C2 lưu đủ **608 model pickle = 19 workload × 32 biến thể**, tổng
  2.362.081.485 byte; terminal `completed`, errors=[].
- Manifest gốc dư prefix `models/models/`. Sidecar dẫn xuất giữ nguyên
  evidence gốc, đã kiểm tra START/RESULTS/TERMINAL và hash/size 608 artifact.
  SHA-256: `4c379dcabd8ea2c8ca0c19f9e13e186dfa9fe63f0df1ea1a2d4d591e946c4408`.
- Load và replay **608/608** bằng Python 3.12.3, NumPy 2.5.3,
  scikit-learn 1.9.1, joblib 1.6.0: score sai lệch lớn nhất **0**,
  conformal p-value/decision khớp prediction C2 đã seal. Đây là consistency
  replay trên dữ liệu đã xem, không phải test chất lượng độc lập.
- C3 hoàn tất **10/10 phase, 30/30 capture worker** trên `.237/.238/.239`:
  selection và holdout, mỗi phần gồm steady/toolmix/peak/burst/recovery.
  Terminal `completed_frequency_collection`, service kết thúc bình thường.
- Recovery attempt 17 đã pass sau khi thêm chờ target cgroup ổn định 360 s;
  giữ cả 16 attempt bị từ chối vì HPA churn và START gốc.
- Audit đầu vào đủ 15/15 capture mỗi split; không nối history qua gap.

| Split | Feature rows | Context bốn window | Warming | Không có model C2 | Gap reset |
|---|---:|---:|---:|---:|---:|
| Selection | 390.195 | 333.877 | 9.191 | 47.096 | 3.472 |
| Holdout | 391.044 | 334.655 | 9.192 | 47.197 | 3.401 |

Selection có thêm 31 rows ngoài biên probe. Notification/payment chưa có model
trong C2; không gán các row này thành normal/TN. Idle-aware Pulse có bundle
21 model khác, không tráo hai bundle chỉ vì cùng 249 chiều.

## C4 đã chạy hết nhưng không hợp lệ để đánh giá chất lượng model

Unit trên `.234`: `pulse-syscall-normal-evaluation-c4.service`, enabled,
checkpoint theo capture và model. Source `3995962` tại
`/home/dat/pulse-syscall-normal-c4/source`. Output NFS:
`/mnt/sentinel-pulse-archive/syscall-variant-normal-c4`.

Job xác minh audit/manifest/software/source `model.py`, kiểm tra capture
sau thời điểm C2 đóng băng, trích đúng 334.655 context holdout. Cùng context
và mask bốn vị trí temporal được dùng cho từng biến thể; không fit, đổi alpha,
calibration hoặc chọn feature theo holdout. Prediction có hash và index về
capture/metadata gốc. Kết quả dương vẫn là **raw positive pending adjudication**,
không tự tính FP/FPR, precision hoặc recall.

Terminal lúc **14:46 ngày 14/10: 608/608 model đã chấm**. Hậu kiểm độc lập
xác minh hash toàn bộ context/metadata và 608 prediction archives, shape,
positive counts, p-value/decision ở alpha 0,001 và nguồn từng capture.
Giới hạn CPU 200%, RAM 3 GiB, Nice=19, IOWeight=1. Job không phụ thuộc
SSH/laptop; reboot tự khởi động và xác minh checkpoint trước khi tiếp tục.
Không zero-alert gate, không auto-promotion.

Bản full có **145.820 raw positive / 334.655 context (43,57%)**, nhưng đã
xác minh training dùng **rolling-10**, C3/C4 dùng **rolling-5**. Do đó số này
chỉ là phép chấm trên preprocessing không tương thích, **không dùng để kết luận
FPR, model stability hoặc utility syscall**. Không nới threshold theo holdout.
Bằng chứng:
[c4-verification.json](validation-evidence/pulse-parallel-completion-20261014/c4-verification.json).
Đây là bộ ablation legacy C2, không phải candidate idle-aware 21 model của Pulse.

## C5/C6 đã hoàn tất; thêm nhánh kiểm tra syscall ngoài danh sách

Unit `.234`: `pulse-syscall-distribution-audit-c5.service`, source frozen
`6f2b9ae` tại `/home/dat/pulse-distribution-audit-c5/source`, output NFS
`/mnt/sentinel-pulse-archive/syscall-development-distribution-c5`.
Job chỉ so mean/std của từng feature trong dataset normal tham chiếu với
**selection C3**, không dùng holdout/C4 scores, không fit hoặc đổi threshold.
Đã tổng hợp đủ 19 workload. Chênh rolling mean/std trong C5 chịu confound
rolling-10/5; không được diễn giải thành drift tự nhiên hay causal importance.

C6 đã hoàn tất lúc khoảng **15:53 ngày 14/10**, Result=success, NRestarts=0.
Replay/sửa đủ 30 capture, 781.239 rows; 191 chiều không rolling giữ nguyên,
58 chiều rolling được derive về rolling-10 đúng training. Chấm đủ 608 model;
full có **11.989/334.655 raw positives (3,5825%)**, chưa có nhãn FP/FPR.
Không thay raw/model/alpha/mask. Bằng chứng:
[C6 terminal](validation-evidence/pulse-c6-completion-evidence-20261014/evaluation-TERMINAL.json),
[hậu kiểm](validation-evidence/pulse-parallel-completion-20261014/c6-verification.json).

**608 model chỉ ablate tập 29; chưa đủ trả lời có cần thêm syscall khác.**
Addition A1 đã đọc cohort nhưng kết thúc **0/105 fit**: `build_contexts`
đòi biên timestamp liền nhau sai số dưới 100 µs, trong khi capture thật có
khoảng nghỉ đọc snapshot 0,6–1,4 ms. History bị reset ở hầu hết mỗi row nên
không đủ rolling-10. Terminal A1 được giữ nguyên, nhưng đây **không phải kết
quả model**. Đã sửa ngưỡng continuity thành tối đa 50 ms, giữ reset khi gap lớn,
và thêm test cho jitter/gap. Regime cũng lấy từ traffic receipt theo timestamp,
không chọn tùy tiện regime đầu tiên của workload.

A1/C3 dùng histogram entry-only **1 s**, rolling-10, history 3, alpha 0,005;
không có transition features. Holdout C3 đã xem trong C4/C6 nên chỉ là dữ liệu
exploratory. Nhánh này không thay Pulse 500 ms/249 chiều và không được dùng để
tuyên bố thêm syscall cải thiện recall. A2 chạy lại có output mới riêng, không
ghi đè A1; kết quả chỉ là kiểm tra pipeline/normal-score exploratory.

Đã thêm protocol v2 với metric chính **recall tại ngân sách false-alert khác
0**, luật chọn tập nhỏ nhất không kém base29 quá 3 điểm phần trăm theo CI paired,
ablation nhóm tương đương, nhóm syscall bảo mật hiếm, 3 seed, bootstrap theo
block và yêu cầu phủ đủ **21/21** workload của bundle Pulse hiện hành. C2 chỉ có
19 workload; notification/payment phải có model/coverage riêng, không được suy
ra từ 19 model cũ. Xem
[protocol v2](sentinel_pulse/protocol/syscall-selection-evaluation-v2.json).

### A2 pipeline retry đang chạy nền

A2 dùng source cố định đã sửa, input C3 giữ nguyên, output mới
`/mnt/sentinel-pulse-archive/syscall-addition-a2-20261014`; systemd
`pulse-syscall-addition-a2.service` đã `enabled` để VM boot có thể tiếp tục.
SSH lần kiểm tra hiện tại thấy `activating/start`, `NRestarts=0`,
`ExecMainStatus=0`; checkpoint đạt **99/105 fit**, 0 workload/arm unknown.
Chưa có terminal; A2 tiếp tục nền.
Cả 9 unit tests đã pass trên VM venv trước start. Đây là pipeline
retry/exploratory trên C3, không phải blind confirmation; model flags không
được diễn giải thành FP. Service chưa terminal; không sửa input/source khi
đang chạy.

A2 chỉ lặp các 5 arm frequency đã đóng băng trong A1; **chưa** chạy threat-model
arm, grouped ablation, nhiều seed hoặc metric recall@FPR. Không đổi input/binding
đang chạy. Các phần đó thuộc protocol v2 và cần capture matched Pulse 500ms
mới; không tự sửa tiếp service A2 giữa chừng.

Protocol cuối yêu cầu observable khớp Pulse: 500 ms, exact full-ID deltas,
syscall + transition bins, rolling/history, cùng support/policy. Histogram C3
1 giây không thể nội suy thành 500 ms; cần capture full-ID đồng bộ mới trước khi
chạy blind comparison chính thức. C3/A2 không trả lời addition study cuối.

Source [syscall_addition_experiment.py](sentinel_pulse/syscall_addition_experiment.py)
đã qua 6 unit tests trong VM venv. Service riêng `.234`:
`pulse-syscall-addition-a1.service`, có checkpoint, enable khi boot và giới hạn
CPU 150%, RAM 3 GiB; output NFS `syscall-addition-a1-20261014`.
Hard integrity mismatch dừng bước evaluation và giữ bằng chứng, không sửa source
frozen, không fail/xóa soak đã thu. Cần blind attack/control mới trước kết luận
giữ/bỏ/**bổ sung** syscall. Tổng hợp:
[báo cáo đầy đủ](SENTINEL_PULSE_VA_THI_NGHIEM_SYSCALL.md).

```bash
systemctl status pulse-syscall-profile-repair-c6.service --no-pager
python3 -m json.tool /mnt/sentinel-pulse-archive/syscall-feature-profile-repair-c6/STATUS.json
# Sau repair, đọc STATUS.json dưới syscall-variant-normal-c6-corrected.
```

## Kết quả tần suất và phần còn thiếu

Selection độc lập mới: **185.303.624 syscall entry, 135 ID xuất hiện**.
29 ID tường minh chiếm **35,7347%**. Tần suất chi tiết và nguồn ABI:
[syscall_analysis.md](syscall_analysis.md). Tần suất không chứng minh tập
29 tối ưu hoặc cho phép loại syscall hiếm.

Chưa có blind attack mới cho từng biến thể, nhãn normal/health hoàn chỉnh,
paired confidence intervals/significance hoặc live kernel-to-alert của C2.
Confusion matrix/precision/recall giữ null tới khi có đúng đơn vị và nhãn.
Không so hàng triệu normal window trực tiếp với vài trăm attack interval.

Cần khóa binary/cases/target/seed/rate mới trước execution; giữ cùng trial cho
mọi biến thể, báo miss/unknown/coverage và model-only khác policy. Sau đó
bootstrap theo block 10.000 lần, CI 95%, Holm/McNemar theo kế hoạch, không tune
rồi gọi test đã xem là blind mới. Đây là thực nghiệm utility kênh tường minh,
không phải tìm tối ưu toàn bộ syscall toàn cầu; hash bins/aggregates vẫn còn.

## Nguồn và bằng chứng

- [C3 runbook](SYSCALL_CAPTURE_C3.md), [recovery root cause](SYSCALL_C3_RECOVERY_INCIDENT.md).
- [Completion evidence](validation-evidence/pulse-parallel-completion-20261014/SUMMARY.json)
  bind SHA-256 terminal, cohort và hai audit đầy đủ.
- C2 model root: `/mnt/sentinel-pulse-archive/syscall-variant-artifacts-c2/runs/attempt-000002`.
- C3 root: `/mnt/sentinel-pulse-archive/syscall-capture-c3-r2`.
- [Evaluator](sentinel_pulse/variant_independent_normal.py),
  [input auditor](sentinel_pulse/variant_capture_audit.py),
  [protocol](sentinel_pulse/protocol/syscall-selection-evaluation-v1.json).
- Cross-OS/ABI vẫn chưa chạy: [VM plan](SYSCALL_EXPERIMENT_VM_PLAN.md).
  Bằng chứng hiện tại chỉ Ubuntu/Linux native x86-64; không suy rộng Windows/ARM.
