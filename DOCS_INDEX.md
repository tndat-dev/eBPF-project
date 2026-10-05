# Mục lục tài liệu Sentinel Pulse

Cập nhật bố cục: 05/10/2026. Tài liệu ở thư mục gốc phục vụ phát triển hiện
tại; báo cáo của các lượt chạy đã kết thúc nằm trong `docs/archive/`.
Mục lục này phân loại tài liệu, không xác nhận trạng thái live của cụm.

## Tài liệu đang dùng

| Tài liệu | Đọc khi cần |
|---|---|
| [README.md](README.md) | Điểm vào repo, bố cục source và giới hạn claim |
| [sentinel-pulse.md](sentinel-pulse.md) | Khái niệm, kiến trúc đầy đủ, luồng online/offline |
| [SENTINEL_PULSE_LUONG_VA_MINH_CHUNG.md](SENTINEL_PULSE_LUONG_VA_MINH_CHUNG.md) | Toàn bộ luồng, sơ đồ và ví dụ log thật đã đối chiếu checksum; đầy đủ 249 giá trị của một window |
| [SENTINEL_PULSE_REPORT.md](SENTINEL_PULSE_REPORT.md) | Báo cáo nghiên cứu và trạng thái hiện hành |
| [TIEN_DO_SENTINEL_PULSE_TU_2026-09-18.md](TIEN_DO_SENTINEL_PULSE_TU_2026-09-18.md) | Tiến độ hiện hành; không nối thêm checkpoint lịch sử |
| [SENTINEL_PULSE_FEATURES_249.md](SENTINEL_PULSE_FEATURES_249.md) | Tên, thứ tự và ý nghĩa feature |
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
Thay đổi chưa được tự commit/push hay đồng bộ sang VM; không sửa code,
model, raw data hoặc tài nguyên Kubernetes trong đợt dọn tài liệu này.
