# eBPF Runtime Sentinel — Sentinel Pulse

Ba tiến trình phát triển chạy song song; mỗi tiến trình có **một báo cáo hiện hành**:

| Đầu việc | Báo cáo |
|---|---|
| Sentinel Pulse: exact telemetry, ML realtime, latency và confusion matrix | [SENTINEL_PULSE_STATUS.md](SENTINEL_PULSE_STATUS.md) |
| Thí nghiệm chọn feature/syscall: addition, ablation, holdout và blind comparison | [SYSCALL_FEATURE_EXPERIMENT_STATUS.md](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) |
| Dựng cây RCA từ tín hiệu Pulse: process/parent/connect/destination | [RCA_RUNTIME_STATUS.md](RCA_RUNTIME_STATUS.md) |

Mỗi báo cáo có thuật ngữ, luồng triển khai, trạng thái SSH có timestamp,
kết quả kèm nguồn, giới hạn, việc còn lại và lệnh kiểm tra. Cập nhật tại chỗ,
không sinh thêm báo cáo/checkpoint cho mỗi lần kiểm tra.

Giữ nguyên [SENTINEL_PULSE_VA_THI_NGHIEM_SYSCALL.md](SENTINEL_PULSE_VA_THI_NGHIEM_SYSCALL.md)
theo yêu cầu; không dùng số liệu cũ trong đó để thay cho trạng thái mới.
Các báo cáo phụ cũ đã gỡ, không tạo thư mục lưu trữ; lịch sử vẫn trong Git.
Một số liên kết lịch sử của bản tổng hợp giữ nguyên có thể trỏ file đã gỡ.

## Code và bằng chứng

- [sentinel_pulse/](sentinel_pulse/README.md): collector, features, ExtraTrees,
  support model, candidate preview, study và RCA.
- tests/: regression và kiểm chứng contract.
- validation-evidence/: raw receipts, checksum, kết quả và mẫu cây thật;
  không xóa hoặc sửa seal để dọn báo cáo.
- sentinel/, ml-service/, agent_runtime/: code khác/legacy; source còn
  tồn tại không chứng minh nó thuộc inference path Pulse hiện hành.

Pulse đang ở shadow/preview, không mặc nhiên là alert production hoặc
root cause đã được xác nhận. Development result, mục tiêu kỳ vọng và blind
validation là ba loại thông tin khác nhau.

Việc dọn báo cáo không đổi model/policy/source frozen, không xóa dataset,
không restart các job đang chạy. [Mục lục ngắn](DOCS_INDEX.md).
