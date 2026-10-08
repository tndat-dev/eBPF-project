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

Kiểm tra SSH lúc **08/10/2026 09:07 ICT**. Campaign đã hoàn thành
`pulse-observation-attack-c2-20261007` trên control plane `.234`, thư mục
`/home/dat/sentinel-pulse-observation-attacks/pulse-observation-attack-c2-20261007`.
Service `active/exited`, MainPID **0**, `ExecMainStatus=0`, `NRestarts=0`.
Không còn đợi matrix chạy ngầm; đây là hoàn thành thu, không phải đạt quality gate.
Source triển khai frozen: `/home/dat/eBPF-project-observation-attack-r2-20261007`,
commit **ee2528be497507797fa98e6e37bd0dbd41587a89**. Thí nghiệm syscall giữ
source/service riêng, không thay candidate này.

Đã xử lý **475/475 interval: 100%**, đã terminal và controller seal. Đây là
số receipt, không có nghĩa mọi generator đều đã tiêm thành công. Bằng chứng:
[paired-final-inspection.json](validation-evidence/pulse-improvement-20261008/paired-final-inspection.json).

### Kết quả cuối của baseline, không phải kỳ vọng

| Nhóm đánh giá | Có alert hợp lệ | Không có alert trong horizon | Thiếu chứng cứ |
|---|---:|---:|---:|
| Attack interval đã xử lý | 140 | 257 | 78 |
| Normal interval theo giả định protocol, chưa adjudication | 0 | 431 | 44 |

**Recall có điều kiện = 140/(140+257) = 35,26%**, trên 397 interval observed.
Đây là phát hiện theo attribution horizon 15 giây của detector hiện hành,
không phải recall trên mọi attack thực tế hoặc mọi alert trong suốt 45 giây.
**Tỷ lệ phát hiện end-to-end = 140/475 = 29,47%**; 78 unknown không bị xóa
khỏi mẫu số này. Unknown không được gán thành FN thuần ML trong bảng có điều kiện.

**Confusion matrix protocol tạm tính đã có**: TP=140, FN=257, FP=0, TN=431;
precision protocol 100%, FPR protocol 0%. Normal label là giả định protocol,
chưa review độc lập, vì vậy adjudicated matrix/precision vẫn `null`. Không
lấy hàng triệu normal window làm TN, không gọi precision này là precision
production. Alert Redis trong soak chưa adjudication, không tự gán FP=1/0.

| Scenario | Có phát hiện | Miss observed | Unknown |
|---|---:|---:|---:|
| anonymous_mprotect_churn | 0 | 80 | 15 |
| child_ptrace_handshake | 70 | 8 | 17 |
| execveat_resolution_probe | 70 | 7 | 18 |
| invalid_setns_burst | 0 | 82 | 13 |
| seccomp_api_probe | 0 | 80 | 15 |

Ba scenario chưa có phát hiện trong các interval observed. Không thể gọi
candidate đạt recall cao hoặc production stable dựa trên kết quả này.
Model/policy baseline không đổi; giữ toàn bộ miss và unknown.

Latency trên **140 trial đã phát hiện**: p50 **0,650 s**, p95 **1,538 s**,
p99 **4,511 s**. Audit raw Tetragon/attributed alerts/controller seals đã xuất
report cuối. Latency trên riêng hit không bù được miss; chưa đạt đồng thời
recall cao và tail latency 1–2 giây. Không giữ tỷ lệ detection-within-2s của
prefix cũ làm tỷ lệ cuối; cần đọc đủ raw receipt để tính theo mẫu số cuối.

### Lỗi giữ nguyên và bước tiếp theo

78 unknown được giữ trong report cuối. Ví dụ có raw stderr
RabbitMQ: `cannot create /tmp/sentinel-runtime-attack-blind: Read-only file system`.
Không coi đó là false negative thuần ML; không vô hiệu hóa hardening của AIMS
hay đổi model giữa matrix để qua lỗi. Cần phân tích target selection theo
prefix và đường staging writable trong phiên đánh giá hạ tầng tiếp theo.

Campaign và paired normal-control đều đã hoàn thành, không cần đợi thêm.
Đã phân tích gate trên prefix riêng, kiểm chứng điểm mù seccomp và fit support
ensemble normal-only: [trạng thái cải thiện](PULSE_IMPROVEMENT_STATUS.md).
Sửa exact target selection ở source mới, không sửa checkout frozen/unknown
cũ. Candidate sửa đổi cần bộ normal/attack mới; không tune theo miss rồi gọi
lại matrix này là blind test mới.

Regression đã bao phủ admission nonzero-alert, checkpoint intent,
hit/miss, thiếu kernel provenance,
thiếu scored coverage và cleanup failure. Không thay thế số đo live.

## Normal-control và báo cáo cuối

`sentinel-pulse-normal-control.service` trên `.234` **enabled**, MainPID **0**,
`NRestarts=0`, `active/exited`, `ExecMainStatus=0`; đủ 25 epoch/475 receipt.
Controller riêng `/home/dat/eBPF-project-paired-evaluation-r2-20261008`, commit
**2036357776b92445f9a5d4cfe921da87be8bd84e**. Worker vẫn dùng source frozen
**ee2528b**, không đổi model/policy/pipeline đã soak.

Report cuối checksum `7fe79acbc5e791f22b82e4d5513a03ff7837fecd6b1982eb80d4bf19200c720a`.
Service chạy lại sau terminal/reboot không sửa QUEUE đã seal, chỉ tái tạo
report riêng. Không restart attack để thu lại các trial miss.

Luồng tự động: attack terminal → đóng/seal leg → kiểm tra controller seal và
đối chiếu raw provenance/alert → đăng ký normal-control → thu interval → audit
lại decision tail → xuất `RESULTS.json` riêng. Không ghi report vào thư mục
attack đã seal. Khóa fleet ngăn collector control chạy đồng thời với attack.

Plan có **19 workload/container chính × 25 interval = 475**; quan sát song song
19 workload mỗi đợt. Interval 45 giây, prediction horizon 15 giây giống attack,
tối thiểu 81 scored windows/interval. Pha này đã xong, không phải soak 24 giờ
hoặc retrain. Chọn target bằng workload/container đúng metadata
cgroup, không chỉ prefix pod name để tránh nhầm Redis/Sentinel. Không tiêm
binary trong pha này; loadgens vẫn chạy.

Mọi alert trong 45 giây được giữ; alert ngoài horizon không bị xóa nhưng không
tính vào prediction 15 giây. Thiếu coverage, mất target hoặc ngắt controller
sau epoch intent giữ unknown, không tự replay và không tính TN. Health degraded
trước/sau interval giữ `uncertain`. Phục hồi bằng leg mới, không reset campaign.
Vượt ngân sách FP không chặn thu. Thời hạn thu tối đa 6 giờ để xuất cả thiếu
coverage thay vì chờ vô hạn.

Report tách **provisional protocol confusion matrix/precision/FPR** khỏi
**adjudicated metrics**. Protocol-assumed normal là nhãn pha thí nghiệm với
health context phù hợp, không chứng minh không có compromise. Adjudicated
precision vẫn `null` khi chưa review độc lập. Alert Redis ở soak không tự
chuyển thành FP. Expectation 95% precision/recall và 5% FPR là mục tiêu, không
phải số đo hay zero-gate. Interval chung epoch có phụ thuộc thống kê; không coi
475 negative interval là 475 mẫu độc lập hoặc suy precision production từ
prevalence của benchmark.

Raw worker seals được giữ. Finalizer rehash controller evidence và reconstruct
receipt từ raw stream/tail trên master; chưa rehash từ xa mọi worker artifact.
Giới hạn này được ghi trong report, không gọi là audit phân tán toàn bộ capture.

Trên `.234`:

```bash
systemctl status sentinel-pulse-normal-control.service --no-pager
journalctl -u sentinel-pulse-normal-control.service -n 30 --no-pager
python3 -m json.tool /home/dat/sentinel-pulse-normal-controls/pulse-normal-control-c1-20261008/QUEUE.json
# STATUS/TERMINAL xuất khi pha control bắt đầu/kết thúc:
python3 -m json.tool /home/dat/sentinel-pulse-normal-controls/pulse-normal-control-c1-20261008/STATUS.json
# Report cuối đã xuất sau terminal và audit:
python3 -m json.tool /home/dat/sentinel-pulse-paired-results/pulse-paired-c1-20261008/RESULTS.json
```

Mã: `sentinel_pulse/normal_control.py`, `paired_evaluation.py`, installer và
systemd unit. Service restart/checkpoint, enabled khi VM boot; chưa chủ động
reboot production để test. Gồm 20 test mới cho FP, sparse coverage, exact target,
checkpoint, seal drift và raw attack audit. Test code không thay thế số đo live.
