# validation-evidence — biên nhận và kết quả thí nghiệm

Chỉ giữ evidence của thế hệ thí nghiệm hiện hành. Dữ liệu thô lớn nằm trên NFS
của cụm (`/mnt/sentinel-pulse-archive`); ở đây là biên nhận, checksum, bảng kết quả
và mẫu nhỏ. Không sửa nội dung đã niêm phong; nếu cần sửa báo cáo, ghi file mới.

| Thư mục | Nội dung |
|---|---|
| `pulse/` | Soak normal A1 24 h, canary chấm theo lô B1/B2, ma trận attack/control pulse-attack-dev/R5 (kèm audit fit syscall-arms), kiểm tra live 15/10 |
| `syscall/` | Đối chiếu ID/tên syscall, phân tích tần suất C3, sửa tiền xử lý C6 |
| `rca/` | Cây RCA thật + input chuẩn hóa, kiểm chứng runtime C3 trong production |
| `results-20261018/` | Kết quả thu ngày 18/10: terminal soak 48 h, holdout syscall-arms, nghiên cứu xác nhận/hiệu chỉnh lại |
| `results-20261019/` | 19–20/10: lượt live pulse-live-recalibrated (campaign chính + tiếp nối, replay chính sách), chọn candidate cho pulse-stable-candidate, nghiên cứu làm mới calibration, kiểm tương đương, RCA; syscall: so ngân sách, bootstrap, k2of2, nhóm feature |
| `results-20261021/` | 21/10: lượt pulse-stable-candidate (campaign, RCA, luật v2, final: novelty có xét exec, kiểm chấm nhanh, Pareto), lượt pulse-stable-refreshed (giai đoạn campaign), baseline G1 (iforest/AE/freq_profile/tree_ae, theo tốc độ attack) |

Evidence của các thế hệ đã gỡ code (AIMS/v8, lifecycle R9/R10, projected
counter/pressure, recovery coordinator, soak inspection 06–07/10…) đã được gỡ
khỏi nhánh ngày 18/10; tra lại bằng tag `archive/pre-refactor-20261018`.
