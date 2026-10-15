# Sentinel Pulse và thí nghiệm syscall: trạng thái hiện hành

Kiểm tra SSH ngày **15/10/2026, khoảng 10:20 UTC+7**. Cả ba worker đang chạy
capture **500 ms**, xuất full syscall-ID delta và 249 feature từ cùng snapshot,
đồng thời chấm frozen candidate preview. Các service capture chưa restart.
Sáu node Kubernetes v1.34.10 đều Ready; không thấy pod production ở trạng thái
khác Running/Completed trong lần kiểm tra này.

| Nhánh | Trạng thái | Service / output |
|---|---|---|
| Capture và Pulse preview | Chạy trên `.237/.238/.239`, đã tích lũy trên 9 giờ/node; đăng ký 48 giờ | `pulse-matched-worker-parallel-20261015.service`; NFS `matched-parallel-20261015/workers/<node>` |
| Matched syscall study R4 | Đã fit 81/693 model, chưa có coverage gap trong phần đã xử lý | `.234`: `pulse-matched-study-parallel-r4-20261015.service`; NFS `matched-parallel-r4-20261015/syscall-matched-study` |
| Pulse follow-up R5 | Hoàn tất 15/15 cặp RabbitMQ, Result=success; đã kết thúc | `.234`: `pulse-matched-campaign-parallel-r5-rabbit-20261015.service`; NFS `matched-parallel-r5-rabbit-20261015/pulse-development-matrix` |

Capture tiếp tục sau cadence gap và recovery, giữ issue và reset history khi
cần. Attack/control intervals được lưu riêng trong campaign journal. Những
khoảng attack không được mặc nhiên xem là normal vì capture vẫn đang chạy.

## Kết quả candidate Pulse đã hoàn tất

R3 đã chạy đủ **315 cặp = 630 interval**, trên 21 workload/container key,
5 scenario development, 3 rate và 1 seed. Các scenario đã được sử dụng trong
phát triển; đây chưa phải fresh blind validation.

Replay có binding sau sửa evaluator cho `warming` cho kết quả:

| Ground truth dùng để chấm | Preview dương | Preview âm | Chưa kết luận |
|---|---:|---:|---:|
| Attack theo lịch inject | TP = 284 | FN = 2 | 29 |
| Control expected-normal | FP kỳ vọng = 72 | TN kỳ vọng = 237 | 6 |

- Precision theo nhãn control kỳ vọng: **79,78%**.
- Recall trên attack đánh giá được: **99,30% = 284/286**.
- Lower bound theo toàn bộ attack đăng ký: **90,16% = 284/315**.
- Control-positive rate: **23,30% = 72/309**.
- Kernel → preview trên 284 trial phát hiện được: p50 **1,067 s**,
  p95 **1,609 s**, p99 **4,751 s**.

Chỉ số còn phụ thuộc nhãn expected-normal chưa review; `confirmed_precision`
và `confirmed_FPR` vẫn null. `alert=false`, `policy_applied=false`;
`kernel_to_alert` còn null. Kết quả p95 đạt kỳ vọng 2 giây ở tập development,
nhưng p99 chưa đạt và tỷ lệ control dương vượt kỳ vọng 5%.
Precision trên thiết kế attack/control gần 1:1 này không suy ra precision khi
attack hiếm trong production. Kỳ vọng 5% ở đây thuộc development interval;
protocol chọn syscall còn đăng ký metric episode/workload-hour riêng.

Terminal R3 gốc giữ TP=284/FN=2/FP kỳ vọng=72/TN kỳ vọng=236, unknown=36.
Replay chỉ chuyển một control từ unknown sang TN; các khoảng warming còn lại
vẫn bị giới hạn bởi scored coverage. Cả terminal gốc, replay và danh sách thay
đổi đều có trong [evidence đã sao chép](validation-evidence/pulse-matched-r3-r4-20261015/README.md).

## Syscall study R3 và bản sửa R4

Study R3 index đủ **21/21 key**, gồm notification/payment. Nó hoàn tất
**627/693 model = 19/21 key × 11 arm × 3 seed**. Hai container
`topic-operator` và `user-operator` chỉ có 678 calibration context, chưa đạt
1.200, nên 66 model được ghi thiếu coverage.

Coordinator cũ bắt đầu khi selection đã hết nhưng segment cuối vẫn đang mở;
nó chỉ đọc segment đã đóng, làm mất phần cuối calibration. R4 dùng lại đúng
khoảng selection đã đăng ký **00:58:40–02:28:40 ngày 15/10, UTC+7**, đợi mỗi
worker có segment đã seal phủ hết biên cuối, xác minh SHA-256 trước indexing.
Giữ nguyên artifact và kết quả R3. Chưa dùng R4 để thay candidate Pulse.
Kiểm tra trực tiếp input R4 cho thấy mỗi Kafka operator có **5.734 train** và
**2.741 calibration context**, đủ điều kiện tối thiểu 1.200 calibration.

11 arm gồm base29, +top8/+top16/+top32, +security, +all-observed,
+all-defined-native, và bỏ nhóm accept/accept4, open/openat,
execve/execveat, clone/clone3. Xếp hạng syscall chỉ dùng training prefix;
3 seed dùng cùng data/context, temporal embargo và reset history.

Đây là phép đo utility của các kênh tường minh: hash/transition bins và
sensitive aggregate vẫn giữ thông tin. Hoàn tất fit chưa đủ kết luận giữ/bỏ
syscall; còn cần independent normal holdout, fresh paired blind attack trên
từng arm, cùng đơn vị interval, CI theo block và phép so sánh paired.

## RabbitMQ follow-up

15 attack RabbitMQ của R3 bị unknown vì `/tmp` thuộc root filesystem chỉ đọc.
Fixture được chuyển sang `/operator/sentinel-runtime-attack-blind`, trong
emptyDir `rabbitmq-plugins`. Runner xác minh CRI container identity và checksum,
stage bằng create-exclusive và cleanup đúng file. Tetragon provenance policy
đã thêm đường dẫn cố định này. Không đổi securityContext hoặc dùng PVC để stage.

R5 ghi 15 cặp mới ở output riêng; kết quả không thay thế 15 unknown của R3.
Các ca FN và control dương trong R3 vẫn được giữ để phân tích.
R5 hoàn tất trên cả ba replica: **TP=13, FN=0, FP kỳ vọng=1, TN kỳ vọng=14,
unknown=2**. Trial 7 `child_ptrace_handshake` chỉ có 4,433/15 giây được score;
trial 15 có đủ scored exposure nhưng không lấy được kernel exec receipt.
Campaign ghi cả hai và chạy đến hết; không loại hoặc thay chúng bằng TN/FN.

Precision kỳ vọng R5 **92,86%**, recall observable **100% = 13/13**, lower
bound **86,67% = 13/15**, control-positive **6,67% = 1/15**. Trên 13 trial phát
hiện được, kernel→preview p50/p95/p99 **0,951/1,288/1,332 s**. Tập này nhỏ và
chỉ gồm RabbitMQ; không dùng để thay matrix R3 hoặc suy ra stable toàn cụm.
Bằng chứng: [R5 terminal](validation-evidence/pulse-matched-r3-r4-20261015/r5-TERMINAL.json).

## Điểm cần cải thiện trước phép so sánh cuối

- Control R3 là hoạt động nền, không chạy một fixture benign cùng cách stage,
  exec và nhịp sleep. Vì vậy chưa tách được tín hiệu của thao tác inject/exec
  khỏi tín hiệu riêng của scenario. Cần thêm matched benign-exec control.
- Timestamp kernel hiện lấy từ execve của fixture qua Tetragon; chưa phải
  timestamp syscall bảo mật đầu tiên trong scenario. Phải ghi rõ khi báo latency.
- Chưa có fresh blind set cho từng arm, independent normal holdout hoàn chỉnh,
  adjudication và paired CI. Những phần này còn cần chạy sau khi model arm freeze.
- Các checkout frozen có contract khác nhau; không thay chỉ vì cùng 249 chiều.
  Resume study cần tiếp tục kiểm tra input/index/model binding và coverage.

## Kiểm tra và bước kế tiếp

Hai bản sửa đã qua 34 tests trong VM ML venv; thay đổi scope follow-up đã qua
16 tests liên quan. Source R4 cố định tại
`/mnt/sentinel-pulse-archive/runtime-control-981aef3/source`; source R5 tại
`/mnt/sentinel-pulse-archive/runtime-control-24912d6/source`.

R5 đã hoàn tất. Study R4 dự kiến cần tổng **2–4 giờ**, tùy NFS/CPU và số context.
Đây là dự kiến, không bảo đảm mọi trial đều đủ coverage. Service được enable
khi boot, restart khi process lỗi; checkpoint và bằng chứng nằm trên VM/NFS.

Lượt kiểm tra tiếp theo sau khoảng **2–3 giờ**: xác minh R4 đủ
693/693 model, phân tích unknown/provenance R5, rồi khóa independent normal holdout và bộ blind mới cho so sánh
arm. Dùng paired metrics để chọn feature; chưa tune candidate theo R3 rồi gọi
R3 là blind test.

```bash
systemctl show pulse-matched-study-parallel-r4-20261015.service -p ActiveState -p SubState -p NRestarts
systemctl show pulse-matched-campaign-parallel-r5-rabbit-20261015.service -p ActiveState -p SubState -p NRestarts
python3 -m json.tool /mnt/sentinel-pulse-archive/matched-parallel-r5-rabbit-20261015/pulse-development-matrix/STATUS.json
```

Checkout cũ `/home/dat/eBPF-project` còn các thay đổi chưa commit từ trước và
không trùng host hiện tại. Checkout đồng bộ mới dùng `/home/dat/eBPF-project-current`;
release thực thi R4/R5 được ghim riêng ở NFS. Các thay đổi cũ vẫn cần review,
chưa được coi là đã hợp nhất vào phiên bản hiện hành.
