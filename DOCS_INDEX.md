# Mục lục tài liệu Sentinel Pulse

Cập nhật bố cục: 08/10/2026. Tài liệu ở thư mục gốc phục vụ phát triển hiện
tại; báo cáo của các lượt chạy đã kết thúc nằm trong `docs/archive/`.
Mục lục này phân loại tài liệu, không xác nhận trạng thái live của cụm.

## Tài liệu đang dùng

| Tài liệu | Đọc khi cần |
|---|---|
| [README.md](README.md) | Điểm vào repo, bố cục source và giới hạn claim |
| [SOAK_OBSERVATION_STATUS.md](SOAK_OBSERVATION_STATUS.md) | Campaign 24 giờ, recovery, ngân sách alert, confusion matrix kỳ vọng và trạng thái live |
| [SOAK_INCIDENTS.md](SOAK_INCIDENTS.md) | Lỗi/alert trong campaign hiện hành, nguyên nhân đã xác minh, phần chưa biết và bằng chứng từ VM |
| [ATTACK_EVALUATION_STATUS.md](ATTACK_EVALUATION_STATUS.md) | Luồng attack đã soak → paired normal-control → audit/precision/recall; không zero-alert gate |
| [syscall_analysis.md](syscall_analysis.md) | Nguồn ABI syscall, tần suất capture độc lập, importance và ablation |
| [SYSCALL_EXPERIMENT_VM_PLAN.md](SYSCALL_EXPERIMENT_VM_PLAN.md) | Danh sách OS/VM cần cấp, phần cứng và phạm vi cross-distro/cross-ABI |
| [SYSCALL_FEATURE_EXPERIMENT_STATUS.md](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) | Job offline chọn kênh syscall, source frozen, tiến độ và giới hạn kết luận |
| [WORKLOAD_TELEMETRY_LOG_FORMAT.md](WORKLOAD_TELEMETRY_LOG_FORMAT.md) | Schema telemetry, nhận diện workload và cách đọc log |
| [example.md](example.md) | Ví dụ feature/log và lệnh lấy dữ liệu |
| [OPERATIONAL_SOAK_RUNBOOK.md](OPERATIONAL_SOAK_RUNBOOK.md) | Protocol và thao tác operational soak |
| [PULSE_TELEMETRY_RECOVERY.md](PULSE_TELEMETRY_RECOVERY.md) | Quarantine, tính toàn vẹn và recovery telemetry |
| [PULSE_RECOVERY_LIFECYCLE_STATUS_20261004.md](PULSE_RECOVERY_LIFECYCLE_STATUS_20261004.md) | Trạng thái tích hợp formal recovery và các receipt kiểm chứng |

Hướng dẫn riêng theo module: [Pulse](sentinel_pulse/README.md),
[pipeline legacy](sentinel/README.md), [benchmark legacy](sentinel/benchmarks/README.md),
[Agent extension](agent_runtime/README.md).

## Tài liệu lưu trữ

[Mục lục lưu trữ](docs/archive/README.md) gồm báo cáo V8/retirement, ba báo
cáo projected counter/ML/operational và incident pressure C2, cùng đặc tả
Agent V1→V2. Đây là lịch sử thiết kế/thử nghiệm, không phải trạng thái live.

Nội dung và verdict được giữ; chỉ điều chỉnh link theo vị trí mới. Riêng
link đến `V8_ONE_WINDOW_PAPER.md` đã được thay bằng chú thích vì file đã bị
gỡ trước đợt dọn này. Không khôi phục các file người dùng đã xóa.

## Bằng chứng và phục hồi tài liệu

`validation-evidence/` không bị dọn, không sửa checksum hoặc receipt.
Không xóa tài liệu vĩnh viễn: muốn đưa một báo cáo về root có thể chuyển
file từ `docs/archive/` về và cập nhật lại các link tương đối.
Tài liệu và bằng chứng được đồng bộ bằng Git. Không thay model/runtime frozen
hoặc xóa raw data để cập nhật báo cáo; checkout vận hành đã đăng ký giữ riêng.
