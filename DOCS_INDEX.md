# Danh mục tài liệu

## Báo cáo hiện hành (cập nhật liên tục, mỗi file có nhật ký làm việc riêng)

1. [SENTINEL_PULSE_STATUS.md](SENTINEL_PULSE_STATUS.md) — Pulse (phát hiện ML): tóm tắt, trạng thái cụm và job,
   thuật ngữ, kết quả các lượt (soak 48 giờ, pulse-attack-dev, hiệu chỉnh lại, live pulse-live-recalibrated,
   pulse-stable-candidate, pulse-stable-refreshed), luật chọn chính sách v2, biên Pareto, baseline (5.15),
   tripwire A1 (5.16), hạ tầng chung, nhật ký.
2. [SYSCALL_FEATURE_EXPERIMENT_STATUS.md](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) — thí nghiệm chọn syscall:
   thiết kế syscall-arms, holdout, replay attack, so sánh ở cùng ngân sách cảnh báo, luật chọn, nhật ký.
3. [RCA_RUNTIME_STATUS.md](RCA_RUNTIME_STATUS.md) — RCA: subscriber, policy Tetragon, xếp hạng nghi phạm,
   độ phủ trong campaign, sự cố đã xử lý, nhật ký.
4. [TODO.md](TODO.md) — danh sách việc theo mức ưu tiên.
5. [RESEARCH_IDEAS.md](RESEARCH_IDEAS.md) — đánh giá tổng thể (điểm mạnh, khoảng cách G1–G9, đề xuất, % tiến độ),
   ý tưởng từ tài liệu (R1–R8, A1–D1), công trình liên quan và nguồn.
6. README trong từng thư mục (`sentinel_pulse/`, `testbed/`) — hướng dẫn code, không phải báo cáo tiến độ.

## Bằng chứng

`validation-evidence/` chứa biên nhận, checksum và kết quả nhỏ của từng lượt chạy
(`pulse/`, `syscall/`, `rca/`, `results-20261018/`, `results-20261019/`, `results-20261021/`). Không sửa file đã niêm phong để chỉnh báo cáo;
dữ liệu lớn nằm trên NFS của cụm (`/mnt/sentinel-pulse-archive`).
