# Bằng chứng thực nghiệm ngày 06/10/2026

Các JSON được lấy từ VM sau khi chạy công cụ; không phải giá trị kỳ vọng. Mô tả phương pháp và giới hạn ở [syscall_analysis.md](../../syscall_analysis.md) và [SOAK_OBSERVATION_STATUS.md](../../SOAK_OBSERVATION_STATUS.md).

| File | Nguồn và ý nghĩa |
|---|---|
| `analysis-worker4.json` | `/home/dat/sentinel-pulse-syscall-analysis-20261006/analysis.json` trên `.238`: tần suất, impurity importance, độ nhạy score trên capture normal độc lập |
| `ablation.json` | Cùng thư mục trên `.234`: 19 workload × 9 biến thể fit trên dataset normal gốc, đánh giá context holdout; không đánh giá attack/policy |
| `current-segment-corrected-audit.json` | Cùng thư mục trên `.234`: audit raw đã seal của đợt `pulse-observation-c1-20261006-s0014`, cả ba worker thành công |
| `old-soak-prefix-audit.json` | Biên bản audit **không thành công** của run ngày 05/10, lưu để truy nguyên; không dùng cộng exposure |
| `old-soak-forensic-prefix-audit.json` | Chẩn đoán audit **không thành công** trước sửa cách biểu diễn cgroup ID; không phải đo FP/recall |

Analysis và ablation chạy từ checkout `1a2817f`; auditor sửa dùng checkout `529d207`. Runtime đang thu vẫn dùng `a3cdbfb`, model R10C1 và policy không thay đổi. Hash capture và analysis được liên kết trong `ablation.json`. Context archive/raw streams lớn giữ trên VM; chưa đưa vào Git.

Analysis chứa 143.447 rows, 45.028.993 syscall, 19 workload/container trên một worker. Capture mang regime `unlabelled`; không claim coverage riêng peak/burst. Ablation chứa 19.456 context đánh giá và không có attack labels. `FP_raw_model` là số raw anomaly khi giả thiết context benign, không phải alert end-to-end đã adjudication.

Đợt s0014 có 234.702 decision, không có alert trong riêng đợt đó. Telemetry-degraded và warming vẫn loại khỏi exposure. Biên bản không phải formal legacy PASS, không chứng minh precision 100% hay recall/latency của attack.
