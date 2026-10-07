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

Binary thực thi phải có SHA-256 `d77c7237d302cae9e0ca56afd0bafcb8b328ef0779ce559cc300b3122ec1a927`.
Tái biên dịch có thể khác hash dù cùng tên/version GCC vì static link phụ thuộc
libc/linker. Launcher nhận bản binary gốc đã đóng băng và xác minh hash trước
registration; không sửa contract để chấp nhận binary mới. Binding sai dừng
dispatch với `BLOCKED.json`/exit 65, không mắc kẹt restart vô hạn.

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

Kiểm tra SSH lúc **08/10/2026 02:23:50 ICT**. Campaign hiện hành
`pulse-observation-attack-c2-20261007` trên control plane `.234`, thư mục
`/home/dat/sentinel-pulse-observation-attacks/pulse-observation-attack-c2-20261007`.
Service PID **2122534**, `NRestarts=0`, đang chạy. Với `Type=oneshot`, trạng thái
`activating/start` trong lúc chạy là bình thường, không phải startup bị treo.
Source triển khai frozen: `/home/dat/eBPF-project-observation-attack-r2-20261007`,
commit **ee2528be497507797fa98e6e37bd0dbd41587a89**. Thí nghiệm syscall giữ
source/service riêng, không thay candidate này.

Đã xử lý **447/475 interval: 94,11%**, chưa terminal. Đây là số receipt đã
xử lý, không có nghĩa 447 attack đều đã được tiêm thành công. Bằng chứng:
[STATUS.json](validation-evidence/attack-inspection-20261008/STATUS.json),
[đối chiếu độc lập](validation-evidence/attack-inspection-20261008/inspection.json).

### Kết quả tạm thời, không phải kỳ vọng

| Nhóm đánh giá | Có alert hợp lệ | Không có alert trong horizon | Thiếu chứng cứ |
|---|---:|---:|---:|
| Attack interval đã xử lý | 131 | 240 | 76 |
| Normal interval cùng đơn vị, đã adjudication | Chưa có FP | Chưa có TN | Chưa đánh giá |

**Recall có điều kiện = 131/(131+240) = 35,31%**, trên 371 interval observed.
Đây là phát hiện theo attribution horizon 15 giây của detector hiện hành,
không phải recall trên mọi attack thực tế hoặc mọi alert trong suốt 45 giây.
**Tỷ lệ phát hiện end-to-end = 131/447 = 29,31%**; 76 unknown không bị xóa
khỏi mẫu số này. Unknown không được gán thành FN thuần ML trong bảng có điều kiện.

**Precision, FPR và confusion matrix 2×2 đầy đủ chưa đo được**: FP/TN vẫn
`null`, không phải 0. Không lấy hàng triệu normal window làm TN để ghép với
TP theo attack interval. Alert Redis trong soak chưa adjudication; không tự
gán FP=1 hoặc FP=0, không công bố precision=100% trên tập chỉ có attack.

| Scenario | Có phát hiện | Miss observed | Unknown |
|---|---:|---:|---:|
| anonymous_mprotect_churn | 0 | 76 | 15 |
| child_ptrace_handshake | 65 | 8 | 17 |
| execveat_resolution_probe | 66 | 7 | 18 |
| invalid_setns_burst | 0 | 75 | 12 |
| seccomp_api_probe | 0 | 74 | 14 |

Ba scenario chưa có phát hiện trong các interval observed. Không thể gọi
candidate đạt recall cao hoặc production stable dựa trên kết quả này.
Chưa chỉnh model/policy theo matrix; giữ miss để phân tích sau khi chạy hết.

Latency trên **131 trial đã phát hiện**: p50 **0,651 s**, p95 **1,882 s**,
p99 **4,544 s**. Đã kiểm tra provenance loader trên 386 kernel records có mặt
lúc inspection; không hit nào thiếu kernel record. Đây không phải audit lại
mọi raw seal. **124/371 = 33,42%** interval observed được phát hiện trong 2 giây;
latency đẹp trên riêng hit không bù được những miss. Chưa đạt mục tiêu đồng
thời recall cao và tail latency 1–2 giây.

### Lỗi giữ nguyên và bước tiếp theo

76 unknown gồm 41 `CalledProcessError`, 7 copy timeout, 14 interval thiếu
scored coverage và 14 lần không tìm thấy container target. Ví dụ có raw stderr
RabbitMQ: `cannot create /tmp/sentinel-runtime-attack-blind: Read-only file system`.
Không coi đó là false negative thuần ML; không vô hiệu hóa hardening của AIMS
hay đổi model giữa matrix để qua lỗi. Cần phân tích target selection theo
prefix và đường staging writable trong phiên đánh giá hạ tầng tiếp theo.

Giữ campaign chạy ngầm đến hết; còn 28 receipt, kỳ vọng khoảng **45–60 phút**
tính từ lần kiểm tra trên nếu không phát sinh chờ hạ tầng. Không cần giữ SSH
hoặc laptop bật. Sau terminal: xuất kết quả baseline nguyên vẹn; thực hiện
normal control interval cùng đơn vị với nhãn/adjudication để hoàn thiện FP/TN
và precision; phân tích model-only so với policy trên replay riêng. Chỉ sửa
candidate trên tập phát triển độc lập, không tune theo các miss của matrix
này rồi gọi lại chính matrix đó là blind test mới.

Regression trên host: **754 test + 20 subtest** đã qua (34,44 giây), gồm
admission nonzero-alert, checkpoint intent, hit/miss, thiếu kernel provenance,
thiếu scored coverage và cleanup failure. Không thay thế số đo live.
