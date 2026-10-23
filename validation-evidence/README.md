# validation-evidence — biên nhận và kết quả thí nghiệm

Chỉ giữ evidence của thế hệ thí nghiệm hiện hành. Dữ liệu thô lớn nằm trên NFS
của cụm (`/mnt/sentinel-pulse-archive`); ở đây là biên nhận, checksum, bảng kết quả
và mẫu nhỏ. Không sửa nội dung đã niêm phong; nếu cần sửa báo cáo, ghi file mới.

| Thư mục | Nội dung |
|---|---|
| `pulse/` | Soak normal A1 24 h, canary chấm theo lô B1/B2, ma trận attack/control pulse-attack-dev/R5 (kèm audit fit syscall-arms), kiểm tra live 15/10 |
| `syscall/` | Đối chiếu ID/tên syscall, phân tích tần suất C3, sửa tiền xử lý C6 |
| `rca/` | Cây RCA thật + input chuẩn hóa 15/10, kiểm chứng runtime C3; ví dụ mới nhất ở `rca/examples-20261023/` |
| `results-20261018/` | Kết quả thu ngày 18/10: terminal soak 48 h, holdout syscall-arms, nghiên cứu xác nhận/hiệu chỉnh lại |
| `results-20261019/` | 19–20/10: lượt live pulse-live-recalibrated (campaign chính + tiếp nối, replay chính sách), chọn candidate cho pulse-stable-candidate, nghiên cứu làm mới calibration, kiểm tương đương, RCA; syscall: so ngân sách, bootstrap, k2of2, nhóm feature |
| `results-20261021/` | 21/10: lượt pulse-stable-candidate (campaign, RCA, luật v2, final: novelty có xét exec, kiểm chấm nhanh, Pareto), lượt pulse-stable-refreshed (giai đoạn campaign), baseline G1 (iforest/AE/freq_profile/tree_ae, theo tốc độ attack) |
| `results-20261022/` | 22–23/10: chọn ML stable (5.19), giảm gánh cảnh báo (5.22), 5.7d; syscall 5C (CUSUM `keep`/`cap`), nhóm feature trên holdout chính và hai biến thể p-value (5B.3); seed baseline binary RCA (5.12). README trong thư mục ghi script và bản gốc trên cụm của từng file |
| `results-20261023/` | Lượt xác nhận `pulse-stable-confirm` (Pulse 5.25, RCA 5.14, 5.15): giai đoạn campaign, độ trễ kernel → người nhận, biên nhận bridge cảnh báo; giai đoạn final thêm sau. README trong thư mục ghi script và bản gốc của từng file |
| `rca/examples-20261023/` | Hai cây RCA thật, chép nguyên (attack ptrace có nghi phạm hạng 1 đúng; cảnh báo normal do exec probe), kèm hình SVG và hướng dẫn đọc |

Evidence của các thế hệ đã gỡ code (AIMS/v8, lifecycle R9/R10, projected
counter/pressure, recovery coordinator, soak inspection 06–07/10…) đã được gỡ
khỏi nhánh ngày 18/10; tra lại bằng tag `archive/pre-refactor-20261018`. Dữ liệu thô của các
thế hệ đó (pulse500, projected, canary 08–10/2026; 642 file, 1,3 GB, chưa từng nằm trong git) chỉ còn trên NFS:
`/mnt/sentinel-pulse-archive/host-evidence-pre-refactor-20261023/`, kèm `SHA256SUMS` (chuyển và kiểm 24/10).
