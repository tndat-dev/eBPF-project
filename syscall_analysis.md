# Phân tích syscall và bằng chứng lựa chọn feature của Sentinel Pulse

## Nguồn định nghĩa và cơ sở lựa chọn

ID/tên syscall được đối chiếu với bảng ABI x86-64 chính thức của [Linux v6.8](https://raw.githubusercontent.com/torvalds/linux/v6.8/arch/x86/entry/syscalls/syscall_64.tbl). Các worker đang chạy kernel 6.8.0-138-generic. Bảng ABI chứng minh ánh xạ ID/tên, không chứng minh tập syscall được chọn là tối ưu để phát hiện attack.

`sentinel_pulse/features.py::TRACKED_SYSCALLS` định nghĩa **29** syscall tường minh:

| Nhóm giải thích kỹ thuật | Syscall (ID x86-64) |
|---|---|
| File/I/O | read(0), write(1), open(2), close(3), chmod(90), openat(257) |
| Bộ nhớ | mmap(9), mprotect(10) |
| Socket | socket(41), connect(42), accept(43), sendto(44), recvfrom(45), accept4(288), recvmmsg(299), sendmmsg(307) |
| Process | clone(56), execve(59), execveat(322), clone3(435) |
| Quyền, namespace, sandbox | ptrace(101), setuid(105), setgid(106), capset(126), pivot_root(155), mount(165), unshare(272), setns(308), seccomp(317) |

Các nhóm trên giải thích giả thuyết thiết kế: quan sát I/O thông dụng và các hoạt động có thể liên quan security. Chưa có bằng chứng rằng 29 syscall này là tập tối ưu. `SENSITIVE_IDS` cũng là lựa chọn engineering; syscall nhạy cảm có thể hoàn toàn hợp lệ. Đếm `sys_enter` ghi nhận lần gọi, không tự chứng minh syscall thành công hoặc là attack.

Syscall ngoài danh sách được gom thành `other`, 64 syscall hash bins và 64 transition bins. Do collision, không thể suy ra tần suất riêng của futex/epoll/... từ bins. Muốn so sánh tập 29 syscall với một tập khác, cần capture thêm histogram theo syscall ID trong thí nghiệm riêng rồi train các biến thể; dữ liệu hiện tại không đủ để khẳng định tập thay thế tốt hơn. Ánh xạ trên không áp dụng trực tiếp cho ARM hay process dùng ABI compat.

## Dữ liệu đánh giá tách biệt

Bundle đang kiểm tra là R10C1, alpha 0,001, window 500 ms, 21 workload/container. Manifest, dataset manifest, training contract và artifact checksum được kiểm tra trước khi phân tích. Capture đánh giá cần khác hash các nguồn training/calibration và nằm sau ngày đóng băng training contract.

Capture sau train của run `pulse-recovery-formal-c1-20261005` được dùng cho phân tích normal độc lập, có seal raw riêng. Run đã kết thúc sớm vì gap; chỉ các snapshot/feature recovery hợp lệ và revision được model chấp nhận mới vào phân tích. Không dùng capture này train/tune candidate đang đo. Vì sự cố đã được xem xét, kết quả này là phân tích exploratory; cần một evaluation mới đã đăng ký để xác nhận kết luận paper.

## Các phép đo đã triển khai trong code

`sentinel_pulse/syscall_analysis.py` thực hiện:

- Tần suất exact: tổng count, tỷ lệ trên tổng syscall và count/container-second, tách từng workload/container và regime. `other` được giữ nguyên, không suy diễn syscall bên trong. Mẫu số container-second khác union workload-hour dùng trong soak.
- Đọc impurity importance từ ExtraTrees, cộng qua bốn vị trí temporal cho mỗi feature. Đây là thống kê về split của mô hình học normal/corruption; không phải tác động nhân quả hoặc recall attack.
- Trên tối đa 1.024 context temporal độc lập mỗi workload, đo độ thay đổi score khi hoán vị theo block 16 context, ba lần lặp; đồng thời đo độ nhạy khi mask một nhóm feature bằng median. Các nhóm gồm count, ratio, syscall bins, transition bins, rolling mean, rolling std, security và volume.
- Xuất context archive có checksum cho ablation retrain riêng. Mẫu context là phần đầu hợp lệ có giới hạn của capture; kết quả không đại diện mặc định cho toàn bộ regime hay cả ngày.

Hoán vị trên tập normal không có nhãn attack chỉ đo **độ nhạy score**. Theo [tài liệu scikit-learn về permutation importance](https://scikit-learn.org/stable/modules/permutation_importance.html), đánh giá importance theo hiệu năng cần scoring phù hợp trên tập đánh giá; feature tương quan còn có thể che vai trò của nhau. Không gọi kết quả normal-only này là predictive permutation importance.

`sentinel_pulse/syscall_ablation.py` train lại baseline full và các biến thể bỏ nhóm feature, dùng đúng dataset normal đã khóa và temporal train/calibration split. Threshold được calibration riêng trên phần calibration; holdout không tham gia fit. Sau đó đo raw-model FP/TN có điều kiện benign trên context holdout. Đây là ablation model; policy semantic đang deploy vẫn giữ nguyên, nên chưa cung cấp hiệu quả end-to-end khi bỏ semantic gate.

## Đánh giá confusion matrix và phần còn cần bổ sung

Normal soak ghi mọi alert nhưng chưa thể kết luận tất cả là FP. Cần adjudication bằng traffic/incident evidence, giữ nhãn uncertain riêng. Đơn vị benchmark đã đăng ký là scenario interval, khác raw-model window và khác alert incident. Không trộn các đơn vị trong một confusion matrix.

Precision = TP/(TP+FP), recall = TP/(TP+FN), FPR = FP/(FP+TN). Chỉ normal data thì thiếu TP/FN; precision/recall để `null`. Mask/permutation làm score thay đổi cũng không chứng minh feature giúp phát hiện attack.

Để chứng minh lợi ích security của tập syscall, còn cần blind attack evaluation tách biệt cho từng ablation, cùng scenario/rate/seed, latency và confidence interval. Trial thiếu telemetry tính là miss trong recall end-to-end, đồng thời báo recall có điều kiện telemetry hợp lệ. Khoảng normal thiếu dữ liệu là unknown, không tính TN. Bootstrap nên theo block thời gian hoặc trial/workload để tránh coi các window liên tiếp là mẫu độc lập.

## Kết quả thực nghiệm hiện hành

Công cụ đã được viết; kết quả JSON tần suất/importance và ablation sẽ được ghi vào phần này sau khi chạy, kiểm tra seal và lấy kết quả từ VM. Không dùng số kỳ vọng thay cho số đo.
