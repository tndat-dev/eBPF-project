# Đánh giá attack của candidate đã soak

## Luồng hiện hành

Entry point mới: `sentinel_pulse.observation_attack`. Luồng này nhận
`START.json` và `TERMINAL.json` của observation soak đã hoàn thành, kiểm tra
model/policy và exposure của từng workload. **Không yêu cầu alert = 0**;
vượt ngân sách alert cũng không chặn phép đo attack. Không tạo `NORMAL_PASS`
giả để đi qua protocol formal cũ.

Candidate giữ manifest `6ddf7cf9b03cb783b82c23272f7046bafa7ab1412b0545b60a2821d1f441cc21`
và policy `602165bd48d81f549d3bfb65e5bdb319a11252678cbf484d739afcf2e5bc8143`.
Trước attack, launcher đối chiếu byte của capture/features/encoding/model/detect,
decision policy, telemetry recovery, freshness và attribution với checkout đã
soak. Chỉ orchestration và registration được bổ sung, không train/tune lại ML.

Matrix R10 đã khóa trước training: **19 controller × 5 scenario × 5 seed/rate
= 475 interval**, không phải 475 loại attack độc lập. Bundle có 21 model;
matrix chọn container chính của từng controller, chưa kiểm tra attack riêng
cho cả hai container phụ MinIO/Kafka operator.

Ba controller api-gateway, PostgreSQL và Kafka chạy trước với seed 53051/rate
12, đủ 15 interval pilot. Sau đó tiếp tục 460 interval còn lại theo schedule
đã đăng ký, không lặp pilot và không chỉnh model theo kết quả pilot.

## Thu và recovery

Collector projected 500 ms, recovery profile và live freshness như candidate
đã soak. Mỗi leg tối đa 30 phút, raw dữ liệu được giữ/seal trên worker; master
đăng ký leg kế tiếp khi hết leg hoặc cần phục hồi. Model/policy không đổi.
Rollout/Longhorn degraded/health toàn cụm được ghi làm context, không tự chặn
mọi trial hay gán thành normal. Target pod/node, sensor provenance và telemetry
phải sẵn sàng; MemoryPressure/PIDPressure trên node target chặn generator để
tránh tăng áp lực. Lỗi runtime làm đợi phục hồi có journal. Campaign có hạn 24 giờ để xuất cả kết quả thiếu coverage
thay vì chờ vô hạn. Không xóa Longhorn hoặc sửa AIMS để qua gate.

Service system-level `sentinel-pulse-observation-attack.service` được thiết kế
enabled khi boot, restart khi controller lỗi và đọc checkpoint. Worker leg
chạy bằng systemd, không gắn với SSH. Worker reboot làm mất BPF maps: controller
giữ kết quả cũ, ghi khoảng thiếu chứng cứ, khởi tạo leg mới; không giả vờ
telemetry liên tục. Chưa thực nghiệm reboot để tránh gián đoạn production.

`INTENTS.jsonl` được fsync trước dispatch. Nếu crash sau intent nhưng chưa có
receipt, interval giữ là `infrastructure_unknown`, không tự tiêm lại seed đó.
Detection miss và alert trong normal không bị xóa. Binary chỉ tác động cây
process của generator; không external network, persistent write, mount hay
privilege change thành công. File binary tạm không được ghi đè file đã tồn tại.

## Cách đọc kết quả

`TRIALS.jsonl`: mọi receipt, gồm observed miss và infrastructure unknown.
`STATUS.json`: tiến độ, số phát hiện, miss, unknown và percentile latency.
`TERMINAL.json`: xuất khi xong matrix hoặc hết hạn, kể cả kết quả chất lượng thấp.
`INFRASTRUCTURE.jsonl`: lỗi/recovery; `trials/`: stdout/stderr generator, raw
Tetragon, attributed alerts và decision tail. Raw capture/decisions/alerts nằm
trên worker trong `/var/lib/sentinel-pulse-500ms/runs/<leg>/`.

Chỉ `status=alert` đúng pod UID/cgroup/model/policy mới được tính là phát hiện.
Attribution horizon của detector giữ **15 giây**, không đổi để tăng recall.
Interval cần ít nhất 90% số window dự kiến được score để vào mẫu observed;
thiếu chứng cứ là unknown, không giả là normal hay detection miss thuần ML.

Hai mẫu số được công bố riêng: recall trên interval observed, và tỷ lệ phát
hiện end-to-end trên interval đã thử, tính unknown là không phát hiện. Không
trộn TN theo hàng triệu normal window với TP theo attack interval. Precision,
FPR và FP/TN để `null` khi chưa có normal interval được adjudication cùng đơn vị.
Một alert Redis trong soak vẫn `uncertain`, không tự biến thành FP hoặc TP.

Latency lấy **Tetragon kernel exec-entry → alert** trên cùng node, không lấy
timestamp chạy lệnh hoặc window-end để gọi là kernel-to-alert. Percentile chỉ
trên trial đã phát hiện; luôn công bố sample count và miss cùng với latency.
Đây là latency đến khởi chạy binary thử nghiệm, không chứng minh thời điểm
syscall độc hại đầu tiên hay hiệu quả trên mọi attack thực tế.

## Trạng thái triển khai

Đang kiểm thử và chuẩn bị service trên VM. Chưa có kết quả attack live mới
để công bố recall/latency của campaign này. Thí nghiệm chọn syscall chạy độc
lập; không đợi nó hoàn thành và không lấy subset mới thay vào candidate hiện tại.
