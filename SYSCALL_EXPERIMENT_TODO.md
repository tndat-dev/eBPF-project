# TODO hiện hành: syscall và Sentinel Pulse

Cập nhật **15/10/2026**. Hai nhánh chạy song song; chỉ điều phối attack tránh
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
- [x] C4 chấm hết 608/608; hậu kiểm toàn bộ context/prediction seals, số đếm và nguồn.
- [x] Giữ 145.820/334.655 raw flags C4 nhưng đánh dấu không hợp lệ cho quality:
  training rolling-10 khác sidecar rolling-5, không dùng tỷ lệ này làm FPR.
- [x] Khởi động C5 read-only audit training/reference so với selection, không dùng holdout để tune.
- [x] C5 hoàn tất; xác minh profile qua hash-bound training capture manifests.
- [x] Triển khai C6 replay nguyên bản rồi derive đúng rolling-10, tự chấm lại model.
- [x] C6 sửa đủ 30 capture/781.239 rows, xác minh nonrolling invariant và chấm đủ 608 model.
  Full 11.989/334.655 raw positives (3,5825%), chưa adjudicate nên không phải FPR.
- [x] Thiết kế và test nhánh thêm syscall ngoài tập 29: base29, +top8/+top16/+top32/+all training-observed.
- [x] Hoàn thành exploratory fit/evaluate A2: 105/105 model, 0 unknown trên C3 histogram 1s.
- [ ] Chạy addition study trên observable Pulse 500 ms; A2 không phải blind/quality result.
- [x] Capture full-ID matched 500 ms và index đủ 21/21 model key trong R3.
- [x] R3 fit 627/693 biến thể; giữ 66 thiếu calibration của hai Kafka operator.
- [x] Triển khai R4 chờ sealed coverage đến cuối selection, giữ nguyên R3 và chạy lại study.
- [ ] Blind attack/control paired cho các arms thêm syscall, không kết luận tối ưu từ normal flags.
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
- [x] Chốt B2 timing theo node: p99 feature-end-to-score 0,502/0,556/0,213 s;
  .238 có 9 cadence gaps; không gọi đây là kernel-to-alert. Overhead A/B vẫn thiếu.
- [x] Chạy tiếp B3 bounded 30 phút trên ba worker, cùng frozen model/policy, song song nhánh thêm syscall.
- [x] Adapter attack/control 500 ms gắn candidate preview với CRI identity và kernel timestamp.
- [x] R3 hoàn tất 315 cặp development; replay có TP=284/FN=2/FP kỳ vọng=72/TN kỳ vọng=237, unknown=35.
- [x] Triển khai R5 follow-up 15 cặp RabbitMQ sau sửa staging; kết quả ở output riêng.
- [x] R5 chạy hết: TP=13/FN=0/FP kỳ vọng=1/TN kỳ vọng=14, unknown=2; giữ thiếu coverage và kernel receipt.
- [ ] Fresh blind attack/control, review nhãn và confusion matrix confirmed.
- [ ] Confusion/recall/live latency, overhead A/B lặp và CI trước claim stable/paper.

## Trạng thái hiện hành

- Capture/preview 500 ms còn chạy, đã tích lũy trên 9 giờ/node trong đăng ký 48 giờ.
- Study R4 active, enabled, checkpoint trên VM/NFS; R5 đã chạy hết 15 cặp, Result=success.
- R3 replay: precision kỳ vọng 79,78%, recall observable 99,30%, lower bound 90,16%;
  kernel→preview p95 1,609 s và p99 4,751 s. Control-positive 23,30% cần cải thiện.
- Chờ R4 đủ 693 fit; cần independent normal holdout/fresh paired blind và CI để chọn syscall.
- C4/C5/C6, A2 và B3 đã kết thúc; giữ kết quả theo đúng candidate/observable.

Tổng hợp kết quả và giải thích đầy đủ:
[SENTINEL_PULSE_VA_THI_NGHIEM_SYSCALL.md](SENTINEL_PULSE_VA_THI_NGHIEM_SYSCALL.md).

Chi tiết: [trạng thái syscall](SYSCALL_FEATURE_EXPERIMENT_STATUS.md),
[batch timing Pulse](PULSE_BATCH_TIMING.md), [hai nhánh](PULSE_PARALLEL_EXECUTION.md),
[phân tích syscall](syscall_analysis.md). Bằng chứng nằm trong validation-evidence
và các output VM/NFS đã bind; không chỉnh frozen test theo kết quả vừa xem.
