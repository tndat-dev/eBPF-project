# Tài liệu đang dùng

Chỉ có **ba báo cáo tiến độ hiện hành**:

1. [Sentinel Pulse](SENTINEL_PULSE_STATUS.md): thuật ngữ eBPF/ML, 249 feature,
   996 chiều temporal context, candidate preview, soak/canary, matrix,
   latency và phần còn thiếu trước production.
2. [Thí nghiệm feature/syscall](SYSCALL_FEATURE_EXPERIMENT_STATUS.md): nguồn
   syscall, frequency, arm/seed, addition/ablation, split/calibration/blind,
   matched study và tiêu chí thống kê để kết luận giữ/bỏ/thêm kênh.
3. [RCA sau alert/preview](RCA_RUNTIME_STATUS.md): exec identity, parent/child,
   connect và đích K8s, context/case/checkpoint, coverage và giới hạn causal claim.

[SENTINEL_PULSE_VA_THI_NGHIEM_SYSCALL.md](SENTINEL_PULSE_VA_THI_NGHIEM_SYSCALL.md)
được giữ nguyên riêng theo yêu cầu. Không tiếp tục tạo báo cáo tổng hợp mới.
Các link lịch sử trong file giữ nguyên không nhất thiết còn là điểm vào hợp lệ.

Báo cáo cũ đã xóa, không archive Markdown. Có thể tra lịch sử bằng Git khi
cần nhưng không dùng trạng thái “đang chạy” trong commit cũ làm trạng thái live.
[README](README.md) và README trong module là hướng dẫn code, không phải
báo cáo tiến độ bổ sung.

Bằng chứng gốc trong validation-evidence/ và artifact trên VM/NFS giữ nguyên.
README hoặc report nằm trong thư mục evidence là một phần hồ sơ thí nghiệm,
không thuộc đợt xóa báo cáo này. Không đổi hash/seal để sửa đường dẫn lịch sử.
