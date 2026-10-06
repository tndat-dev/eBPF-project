# eBPF Runtime Sentinel — Sentinel Pulse

Hướng phát triển hiện tại là **Sentinel Pulse**: thu syscall bằng eBPF counters,
trích xuất feature và phát hiện bất thường theo workload/container bằng
ExtraTrees. Trạng thái hiện hành ở [SOAK_OBSERVATION_STATUS.md](SOAK_OBSERVATION_STATUS.md);
hướng dẫn code và triển khai ở [sentinel_pulse/README.md](sentinel_pulse/README.md).

Bắt đầu tra cứu tại [mục lục tài liệu](DOCS_INDEX.md). Thư mục gốc chỉ giữ
tài liệu đang dùng; báo cáo V8, canary đã kết thúc và đặc tả Agent đời đầu
được chuyển vào [docs/archive/](docs/archive/README.md).

## Tài liệu đang dùng

- [Campaign soak và tiến độ hiện hành](SOAK_OBSERVATION_STATUS.md).
- [Lỗi/alert và bằng chứng từ VM](SOAK_INCIDENTS.md).
- [Nguồn syscall, frequency, importance và ablation](syscall_analysis.md).
- [Định dạng telemetry](WORKLOAD_TELEMETRY_LOG_FORMAT.md)
  và [ví dụ/lệnh kiểm tra](example.md).
- [Operational soak runbook](OPERATIONAL_SOAK_RUNBOOK.md),
  [telemetry recovery](PULSE_TELEMETRY_RECOVERY.md) và
  [trạng thái tích hợp formal recovery ngày 04/10/2026](PULSE_RECOVERY_LIFECYCLE_STATUS_20261004.md).

Các tài liệu lưu trữ có checkpoint theo thời gian. Một dòng “active”, lịch kiểm
tra hoặc phiên bản trong checkpoint cũ không phải trạng thái live hiện tại.
Đối chiếu run ID, timestamp và terminal receipt trước khi dùng số liệu.
Mục tiêu latency 1–2 giây không đồng nghĩa đã đạt kernel-to-alert;
smoke diagnostic cũng không thay cho formal soak hoặc blind attack evaluation.

## Bố cục code và bằng chứng

- `sentinel_pulse/`: collector, features, ExtraTrees, detector, protocol,
  deployment và evaluation cho Pulse.
- `tests/test_sentinel_pulse*.py`: regression cho Pulse.
- `validation-evidence/`: receipts, checksum và kết quả đánh giá; giữ cả
  lượt bị reject để bảo toàn provenance.
- `ml-service/`, `sentinel/`: pipeline và benchmark các thế hệ trước;
  việc source còn trong repo không chứng minh model/service đang active.
- `agent_runtime/`, `Agent_Runtime_Sentinel_ALL_FILES/`: extension Agent/MCP;
  không mặc định coi là một phần đã triển khai của ML path Pulse.

## Tài liệu lịch sử

[V8 status](docs/archive/PROJECT_STATUS_V8.md) và
[retirement/khôi phục model V8](docs/archive/V8_MODEL_RETIREMENT.md)
được giữ để tra cứu lịch sử, không làm báo cáo runtime hiện hành.
Các số liệu và verdict canary/incident vẫn nằm trong
[thư mục lưu trữ](docs/archive/README.md). Dọn tài liệu không sửa model,
không xóa raw evidence và không khởi động hoặc dừng workload trên cụm.
