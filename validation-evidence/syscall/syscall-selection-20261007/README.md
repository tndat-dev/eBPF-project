# Kiểm chứng nguồn và tổng hợp bằng chứng syscall

`selection-evidence.json` được tạo bằng `sentinel_pulse.verify_syscall_selection`.
Đây là tổng hợp lại số đo độc lập ngày 06/10, **không phải capture mới ngày 07/10**.
Tool tải bảng syscall Linux v6.8 từ URL nguồn chính thức và ghi checksum,
đối chiếu toàn bộ 29 tên/ID cùng thứ tự slot trong collector header.

Input là `../syscall-analysis-20261006/analysis-worker4.json` và `ablation.json`.
Tool kiểm tra hash liên kết, tổng count, tỷ lệ/rate, coverage và số context của
từng ablation. Không đọc lại raw seals, không fit/tune model và không có nhãn
attack; độ chính xác security và tập syscall tối ưu vẫn chưa được chứng minh.

```bash
python3 -m sentinel_pulse.verify_syscall_selection \
  --analysis validation-evidence/syscall-analysis-20261006/analysis-worker4.json \
  --ablation validation-evidence/syscall-analysis-20261006/ablation.json
```

Có thể dùng `--abi-table <bản tải bảng v6.8>` khi offline. Kết quả ghi checksum
bản được đọc; đối chiếu lại checksum nguồn nếu dùng bản do bên khác cung cấp.
Nguồn và diễn giải đầy đủ: [syscall_analysis.md](../../syscall_analysis.md).
