# TODO hiện hành: syscall và Sentinel Pulse

Cập nhật **14/10/2026**. Hai nhánh chạy song song; chỉ điều phối attack tránh
làm bẩn capture đã đăng ký normal. Không zero-alert gate, không xóa miss/unknown.

## Nhánh syscall

- [x] C2 fit và lưu đủ 608 model, 19 workload × 32 biến thể.
- [x] Sidecar manifest sửa path có provenance; xác minh 608 hash/size.
- [x] Load/replay 608/608 đúng venv C2; score/p-value/decision khớp.
- [x] C3 thu đủ selection và holdout qua năm regime trên ba worker.
- [x] Giữ 16 attempt recovery lỗi, sửa HPA/identity settle bằng amendment;
  attempt 17 pass, không bỏ integrity validation hoặc sửa model.
- [x] Audit 15 capture mỗi split; 333.877 context selection và 334.655 holdout.
- [x] Thống kê selection mới: 185.303.624 entry, 135 ID, tập 29 chiếm 35,7347%.
- [x] Triển khai C4 independent holdout scoring bằng systemd, checkpoint/reboot resume.
- [ ] C4 chấm hết 608/608; xác minh prediction seals và coverage theo workload/regime.
- [ ] Adjudicate normal/health, chia interval 30 s và báo unknown riêng.
- [ ] Khóa fresh blind binary/cases/target UID/container/revision, seed/rate và lịch.
- [ ] Chạy blind trials cùng đầu vào cho mọi biến thể; giữ miss và infrastructure evidence.
- [ ] Confusion matrix cùng đơn vị; precision/recall/FPR/coverage, model-only và policy riêng.
- [ ] Paired block-bootstrap CI 95%, McNemar/Holm; báo trade-off và kết luận giữ/bỏ có giới hạn.
- [ ] Live kernel/injection-to-decision timestamp binding; không thay bằng offline inference time.
- [ ] Cross-distro/kernel/ABI theo VM plan nếu có máy, không suy rộng từ Ubuntu.

## Nhánh Pulse

- [x] Bundle idle-aware 21 workload, freeze model/policy và kiểm tra trên ba worker.
- [x] Normal capture A1 đủ 86.400 giây/node; không dừng vì alert/ordinary recovery.
- [x] Review toàn bộ 33.148.914 decisions; 11.388.831 scored, 30.412 preview pending.
- [ ] Giải thích 565 dòng chênh capture/decision; xác minh alignment/coverage.
- [ ] Adjudicate previews, health và normal intervals; không gọi preview mặc định là FP.
- [x] Batch runtime giữ history/identity/policy; 21/21 model có scalar/batch score sai lệch 0.
- [x] B1 live 5 phút: feature-end-to-score p95/p99 0,424/0,474 s; không gọi kernel-to-alert.
- [x] Triển khai B2 live 30 phút trên cả ba worker, riêng với soak đã đóng.
- [ ] Chốt B2 lag/backlog/CPU/RAM/issues theo node, không chỉ pooled latency.
- [ ] Adapter blind phù hợp idle-aware contract; fresh attack/control và kernel timestamp.
- [ ] Confusion/recall/live latency, overhead A/B lặp và CI trước claim stable/paper.

## Job đang chạy và khi nào xem tiếp

- Syscall: `.234`, `pulse-syscall-normal-evaluation-c4.service`, NFS
  `/mnt/sentinel-pulse-archive/syscall-variant-normal-c4`; resume sau reboot.
- Pulse: `.237/.238/.239`, `pulse-idle-batch-canary-b2.service`,
  `/var/lib/pulse-idle-batch-canary-b2-20261014`; bounded 30 phút, không nối SSH.
- B2 dự kiến kết thúc khoảng 15:06; **kiểm tra khoảng 15:10 ngày 14/10 UTC+7**.
  C4 có thời lượng khác; xem completed_models/608, không suy thành quality %.

Chi tiết: [trạng thái syscall](SYSCALL_FEATURE_EXPERIMENT_STATUS.md),
[batch timing Pulse](PULSE_BATCH_TIMING.md), [hai nhánh](PULSE_PARALLEL_EXECUTION.md),
[phân tích syscall](syscall_analysis.md). Bằng chứng nằm trong validation-evidence
và các output VM/NFS đã bind; không chỉnh frozen test theo kết quả vừa xem.
