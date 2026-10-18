# Danh mục tài liệu

## Đang dùng

1. [docs/STATUS.md](docs/STATUS.md) — báo cáo trạng thái duy nhất được cập nhật:
   kiến trúc, thuật ngữ, trạng thái cụm, kết quả, vấn đề chính, cách kiểm tra.
2. [TODO.md](TODO.md) — danh sách việc theo mức ưu tiên.
3. README trong từng thư mục (`sentinel_pulse/`, `testbed/`) — hướng dẫn code,
   không phải báo cáo tiến độ.

## Báo cáo chi tiết cũ (snapshot 15–16/10/2026)

Các file ở thư mục gốc dưới đây là ảnh chụp trạng thái trước khi soak 48 giờ và
holdout R4 kết thúc. Chúng giữ chi tiết kỹ thuật đầy đủ nhưng số liệu "đang chạy"
trong đó đã cũ; dùng docs/STATUS.md cho trạng thái hiện tại. Link tới evidence
trong các file này dùng đường dẫn trước ngày 18/10 (nay nằm dưới
`validation-evidence/{pulse,syscall,rca}/` hoặc trong tag `archive/pre-refactor-20261018`).

- `SENTINEL_PULSE_STATUS.md` — nhánh phát hiện ML.
- `SYSCALL_FEATURE_EXPERIMENT_STATUS.md` — thí nghiệm chọn syscall.
- `RCA_RUNTIME_STATUS.md` — nhánh dựng đồ thị điều tra.
- `SENTINEL_PULSE_VA_THI_NGHIEM_SYSCALL.md` — bản tổng hợp dài (giữ theo yêu cầu).

## Bằng chứng

`validation-evidence/` chứa biên nhận, checksum và kết quả từng lượt chạy. Không
sửa file đã niêm phong để chỉnh báo cáo; dữ liệu thô lớn nằm trên NFS của cụm.
