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

Đã chạy trực tiếp trên VM, lấy kết quả và kiểm tra liên kết checksum giữa analysis và ablation. Bằng chứng lưu trong [analysis-worker4.json](validation-evidence/syscall-analysis-20261006/analysis-worker4.json) và [ablation.json](validation-evidence/syscall-analysis-20261006/ablation.json). Analysis SHA-256: `4a7c62b3a854c5150d928aaea6cbc7da843f4bdd0002434de51e4ec17e908f49`; capture SHA-256: `37c7662a49fd14976d51a3c7e420522de57907eb1178dc35e45b6f0c9bc620c2`. Hai hash này được ghi lại trong ablation; không dùng số kỳ vọng thay cho số đo.

Capture nằm trên worker `.238`, có **143.447 feature rows hợp lệ và 45.028.993 syscall**, phủ 19 workload/container trong bundle 21 workload. 253 rows bị loại theo eligibility/revision. Đây không phải coverage toàn cụm. Regime trong capture này là `unlabelled`; chưa có bằng chứng riêng cho từng chế độ peak/burst/recovery. Context đánh giá lấy tối đa 1.024 lịch sử liên tiếp hợp lệ mỗi workload, tổng 19.456 context; mỗi context gồm bốn vector 249 chiều.

### Ví dụ tần suất RabbitMQ

`production/aims-rabbitmq-server:rabbitmq`: 6.367 rows, tổng 1.445.750 syscall.

| Counter | Tổng lần gọi | Tỷ lệ tổng syscall |
|---|---:|---:|
| other | 1.061.410 | 73,42% |
| read | 186.796 | 12,92% |
| write | 92.493 | 6,40% |
| recvfrom | 66.161 | 4,58% |
| openat | 15.923 | 1,10% |
| close | 13.397 | 0,93% |

Các số này chứng minh read/write/recvfrom có mặt đáng kể trong capture này, không chứng minh đó là feature tối ưu. Tỷ lệ `other` giữa các workload từ 55,13% đến 97,45%: tập syscall tường minh chưa giải thích đầy đủ hành vi. Hash bins giữ tín hiệu tổng hợp nhưng không thay thế histogram syscall ID để diễn giải từng syscall.

### Feature quan trọng theo mô hình đã đóng băng

Importance cộng qua bốn vị trí temporal, tính bằng impurity importance của các cây. Với RabbitMQ, feature đầu bảng là `log_count:recvfrom` (0,04249) và `rolling_mean:recvfrom` (0,04173). Với search-recommendation, đầu bảng là `rolling_std:openat` (0,03511) và `rolling_std:setuid` (0,03122). Không có một feature đứng đầu chung cho mọi workload.

Đây là importance đối với **bài toán normal/corruption tự giám sát**, không phải bằng chứng `setuid` gây attack. Feature của một syscall ít xuất hiện vẫn có thể được model sử dụng khi phân biệt dữ liệu bị corrupt. Muốn diễn giải một alert cụ thể cần thêm attribution trên đúng context đó và kiểm tra counts/policy.

### Ablation train lại: kết quả normal holdout

Đã hoàn thành **19 workload × 9 biến thể = 171 fit**: full và bỏ tám nhóm feature. Fit dùng dataset normal gốc; threshold calibration lại trên calibration split, không trên holdout. Cột bên dưới là số context được raw model gọi anomalous trong 1.024 context normal của mỗi workload. Chúng **không phải số alert sau semantic/temporal policy**, và không dùng để sửa model đang soak.

| Workload/container | Full | Bỏ count | Bỏ ratio | Bỏ rolling mean | Bỏ rolling std | Bỏ security | Bỏ syscall bins | Bỏ transition bins | Bỏ volume |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| search-recommendation/app | 157 | 225 | 146 | 153 | 165 | 186 | 189 | 115 | 173 |
| Kafka user-operator | 44 | 13 | 11 | 22 | 7 | 38 | 14 | 22 | 0 |
| Redis Sentinel | 33 | 51 | 56 | 43 | 22 | 41 | 113 | 2 | 55 |
| Kafka broker | 7 | 10 | 3 | 5 | 6 | 8 | 4 | 3 | 4 |
| RabbitMQ | 1 | 0 | 1 | 1 | 0 | 1 | 1 | 1 | 1 |

Full raw-model anomaly rate của search-recommendation là **157/1.024 = 15,33%**, Redis Sentinel **3,22%**, RabbitMQ **0,098%**. Đây là dấu hiệu cần phân tích drift và hiệu quả gate; chưa thể nói hệ thống end-to-end có FPR tương ứng. Bỏ nhóm feature đôi khi giảm anomalous rate, nhưng cũng có thể làm giảm khả năng phát hiện attack. Không lựa chọn biến thể chỉ vì nó cho ít anomaly trên normal holdout.

**Chưa đo:** blind attack recall của từng biến thể, precision end-to-end đã adjudication, latency kernel-to-alert và confidence interval của so sánh attack. Kết quả hiện tại cung cấp bằng chứng tần suất và độ nhạy, chưa đủ chứng minh 29 syscall là tập tối ưu cho paper.
