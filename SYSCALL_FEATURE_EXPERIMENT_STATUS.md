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

## Đang chạy: C4 independent normal inference

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

Checkpoint lúc 14:36: **80/608 model đã chấm**, service running, NRestarts=0.
Tiến độ mới phải đọc STATUS, không dùng con số checkpoint này như trạng thái
realtime. Giới hạn CPU 200%, RAM 3 GiB, Nice=19, IOWeight=1. Job không phụ thuộc
SSH/laptop; reboot tự khởi động và xác minh checkpoint trước khi tiếp tục.
Không zero-alert gate, không auto-promotion.

```bash
systemctl status pulse-syscall-normal-evaluation-c4.service --no-pager
python3 -m json.tool /mnt/sentinel-pulse-archive/syscall-variant-normal-c4/PREPARE_STATUS.json
# STATUS chứa completed_models và expected_models; TERMINAL chỉ có khi chấm hết.
python3 -c 'import json; p="/mnt/sentinel-pulse-archive/syscall-variant-normal-c4/STATUS.json"; d=json.load(open(p)); print(d["state"], d["completed_models"], "/", d["expected_models"])'
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
