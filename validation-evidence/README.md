# validation-evidence — biên nhận và kết quả thí nghiệm

Chỉ giữ evidence của thế hệ thí nghiệm hiện hành. Dữ liệu thô lớn nằm trên NFS
của cụm (`/mnt/sentinel-pulse-archive`); ở đây là biên nhận, checksum, bảng kết quả
và mẫu nhỏ. Không sửa nội dung đã niêm phong; nếu cần sửa báo cáo, ghi file mới.

| Thư mục | Nội dung |
|---|---|
| `pulse/` | Soak normal A1 24 h, canary chấm theo lô B1/B2, ma trận attack/control R3/R5 (kèm audit fit R4), kiểm tra live 15/10 |
| `syscall/` | Đối chiếu ID/tên syscall, phân tích tần suất C3, sửa tiền xử lý C6 |
| `rca/` | Cây RCA thật + input chuẩn hóa, kiểm chứng runtime C3 trong production |
| `results-20261018/` | Kết quả thu ngày 18/10: terminal soak 48 h, holdout R4, nghiên cứu xác nhận/hiệu chỉnh lại |

Evidence của các thế hệ đã gỡ code (AIMS/v8, lifecycle R9/R10, projected
counter/pressure, recovery coordinator, soak inspection 06–07/10…) đã được gỡ
khỏi nhánh ngày 18/10; tra lại bằng tag `archive/pre-refactor-20261018`.
