# Tài liệu lịch sử — không phải trạng thái runtime hiện tại

Các tài liệu sau được chuyển khỏi thư mục gốc ngày 04/10/2026 để giảm
nhầm lẫn giữa checkpoint cũ và hướng phát triển Sentinel Pulse hiện tại.
Giữ nguyên nội dung nghiên cứu, số liệu và verdict; chỉ sửa các link tương
đối theo vị trí mới và bỏ link tới file đã bị gỡ trước đó.

| Tài liệu | Phạm vi lịch sử |
|---|---|
| [PROJECT_STATUS_V8.md](PROJECT_STATUS_V8.md) | Kiến trúc, dữ liệu và đánh giá V8 |
| [V8_MODEL_RETIREMENT.md](V8_MODEL_RETIREMENT.md) | Gỡ bundle V8, phạm vi giữ lại và hướng dẫn khôi phục |
| [PROJECTED_COUNTER_CANARY.md](PROJECTED_COUNTER_CANARY.md) | Thiết kế projected counters và collector canary |
| [PROJECTED_ML_CANARY_20261003.md](PROJECTED_ML_CANARY_20261003.md) | ML canary với projected counters ngày 03/10 |
| [PROJECTED_OPERATIONAL_SOAK_20261003.md](PROJECTED_OPERATIONAL_SOAK_20261003.md) | Operational run/checkpoint projected counters ngày 03/10 |
| [PULSE_PRESSURE_C2_INCIDENT_20261004.md](PULSE_PRESSURE_C2_INCIDENT_20261004.md) | Alert Redis Sentinel, telemetry gap và giới hạn attribution |
| [Agent_Runtime_Sentinel_Build_Spec.md](Agent_Runtime_Sentinel_Build_Spec.md) | Đặc tả mở rộng Agent/MCP V1→V2, không phải Pulse deployment hiện tại |

Lịch “đang chạy”, cấu hình và số liệu trong báo cáo chỉ áp dụng cho
timestamp/run ID được ghi. Không dùng chúng làm xác nhận trạng thái live.
Incident và rejected runs vẫn được giữ, không xóa alert để làm đẹp kết quả.

Trở lại [mục lục hiện hành](../../DOCS_INDEX.md),
[báo cáo Pulse](../../SENTINEL_PULSE_REPORT.md) hoặc
[bằng chứng gốc](../../validation-evidence/).
