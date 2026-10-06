# Kiểm tra soak trực tiếp ngày 06/10/2026

`inspection.json` được lấy trực tiếp từ control plane `.234`, gồm trạng thái service,
registration, summary, các biên bản audit đã kết thúc và health/supervision của đợt đang chạy.
Thời điểm kiểm tra nằm trong `checked_at_unix`; giờ trình bày trong báo cáo là UTC+7.

Đây là snapshot kiểm tra, không phải terminal report hay formal PASS. Alert chưa có
ground truth vẫn cần adjudication; khoảng thiếu telemetry không tính normal/TN.
Các lỗi được mô tả trong [SOAK_INCIDENTS.md](../../SOAK_INCIDENTS.md).

`redis-alert-s0012.jsonl` là raw alert sao chép từ worker `.237`, đối chiếu
SHA-256 với receipt đã audit. `s0019-worker-terminal.json` là receipt exit 1
của worker `.237`. `s0024-corrected-audit.json` kiểm chứng lại ba raw streams
đã seal, giữ checksum marker/health và phiên bản auditor; không ghi đè journal gốc.
