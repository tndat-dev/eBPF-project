# Sentinel Pulse: formal operational soak theo exposure

## Trạng thái hiện hành

Từ 06/10/2026, dùng **campaign quan sát có phục hồi** trong
[`observation_campaign.py`](sentinel_pulse/observation_campaign.py).
Đăng ký tối thiểu 24 giờ wall time, mục tiêu 24 giờ exposure hợp lệ cho mỗi
workload, tối đa 48 giờ để bù thiếu telemetry. Alert hoặc không đạt ngân sách
chất lượng không chấm dứt campaign. Giữ và audit các đoạn tốt trước sự cố,
chờ phục hồi rồi thu tiếp; health/telemetry không quan sát được là unknown,
không tính normal/TN. Khởi động lại coordinator tiếp tục cùng registration.

Protocol và trạng thái live được ghi tại
[SOAK_OBSERVATION_STATUS.md](SOAK_OBSERVATION_STATUS.md);
phân tích lựa chọn syscall tại [syscall_analysis.md](syscall_analysis.md).
Các mô tả formal/zero-alert/guard phía dưới là **protocol legacy**, không
phải cách điều khiển campaign quan sát hiện hành.

## Protocol formal legacy

Formal recovery lifecycle đã tích hợp bằng adapter riêng
[`recovery_coordinator.py`](sentinel_pulse/recovery_coordinator.py): marker trước
capture, worker attestation, freshness gate, bounded supervision, worker seals,
node reports và union scored exposure. Bản `1c03987` bổ sung khóa một writer/run
và kiểm tra identity khi resume; không thay model/policy hoặc verdict cũ.
Trạng thái run thực tế và thời điểm kiểm tra nằm tại
[status hiện hành](PULSE_RECOVERY_LIFECYCLE_STATUS_20261004.md).

CLI mới là `python -m sentinel_pulse.recovery_coordinator --config CONFIG
--password-file PRIVATE_FILE --output-root ROOT --run-id NEW_ID
--duration-seconds 89880`. Thêm `--diagnostic-only` chỉ cho run 180–1800 giây.
Resume phải dùng cùng tham số đã đăng ký và thêm `--resume`; terminal run
không được hồi sinh. Source phải là worktree Git sạch, thực thi đúng executable
đã bind; credentials ở file private, không lưu vào config/marker.

Phần operational v1 bên dưới mô tả protocol legacy. Các starter/finalizer legacy
vẫn chủ động từ chối recovery; dùng coordinator riêng, không thêm profile mới
vào run cũ để đổi verdict. Formal recovery PASS cũng không thay NORMAL_PASS
hoặc chứng minh recall/kernel-to-alert. Không tự mở blind/promotion.

### Guard dung lượng ngoài coordinator frozen

[`recovery_capacity_guard.py`](sentinel_pulse/recovery_capacity_guard.py) là
wrapper riêng trên master, không sửa checkout runtime `1c03987`. Chạy file
trực tiếp với `PYTHONPATH` trỏ checkout frozen; coordinator con dùng đúng
source đó. Wrapper đăng ký contract/source SHA/config SHA trước khi launch,
rồi bind checksum marker thật của coordinator.

- Đọc hai filesystem chứa capture và detector log trên ba worker mỗi30 s,
  parallel SSH timeout12 s. Percent tính `used / (used + available)` như `df`,
  đã loại reserved blocks khỏi mẫu số. Kiểm tra device không bị đổi.
- Budget riêng cho **lượt mới**: available>0, used<90%; không yêu cầu dự trữ
  cố định64 GiB. 90% là ngưỡng dừng bảo vệ vận hành, không phải target cần dùng
  hết disk; không áp ngược vào marker legacy max85%.
- Mất quan sát giữ trạng thái unknown; quá60 s thì reject/dừng coordinator con.
  Vi phạm dung lượng cũng chỉ SIGTERM đúng child `Popen` đang sở hữu, cho55 s
  để coordinator cleanup worker riêng. Không kill process theo tên, không dừng
  control collector hoặc pod; không xóa dataset/model.
- Evidence riêng: `/home/dat/sentinel-pulse-capacity-guards/<run_id>` có
  START, COORDINATOR_BINDING, OBSERVATIONS, TERMINAL và SHA256. Guard không cấp
  formal PASS: verdict vẫn từ REPORT/TERMINAL của coordinator frozen.

Lệnh wrapper trên master, thay `NEW_RUN` bằng ID mới; không resume run terminal:

```bash
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=/home/dat/eBPF-project-recovery-coordinator-r3-20261005 \
/home/dat/ml-venv/bin/python -u /home/dat/pulse-capacity-guard-20261005.py \
  --config /home/dat/pulse-recovery-coordinator-r3-config-20261005.json \
  --password-file /home/dat/.pulse-recovery-credential-20261005 \
  --output-root /home/dat/sentinel-pulse-recovery-coordinator-runs \
  --guard-root /home/dat/sentinel-pulse-capacity-guards \
  --run-id NEW_RUN --duration-seconds 89880
```

Đọc [status hiện hành](PULSE_RECOVERY_LIFECYCLE_STATUS_20261004.md) để biết run
thật đã start hay chưa. `89880 s` là thời lượng đăng ký, không chứng minh mọi
key đã có24h scored exposure hợp lệ. Không tự mở blind/promote sau lượt này.

**Recovery candidate, 03/10 khoảng23:40 ICT:** core opt-in đã test
(release `936d3df`, host/VM435 test +20 subtest), nhưng chưa nối vào
starter/installer/monitor/finalizer/evaluator formal. Operational v1 bên dưới
vẫn giữ gap10 s; đừng hiểu rằng soak hiện tại đã tự phục hồi gap14 s.
Model/policy và verdict cũ giữ nguyên. Diagnostic C1 đã reject và observer
C1 failed126; lượt observer C2 đã có sample thật, ML C2 START23:37:48,
duration7200 s, strict contract cũ. Kiểm tra khoảng02:10 ICT04/10.
Thiết kế, ngân sách, CLI thử riêng và interlock:
[PULSE_TELEMETRY_RECOVERY.md](PULSE_TELEMETRY_RECOVERY.md).

**Terminal projected operational run, 03/10:** START 12:05:14, failure
20:13:34 vì gap **14,030071 s >10 s** trên worker3. Archive hoàn tất 20:28:04,
START 5/5 và RAW 52/52 checksum kiểm tra lại đạt. Đây là cadence rejection,
không phải counter consistency/projection failure; run không được resume hoặc
dùng train/tune. Source `4c2948f` và model/policy giữ nguyên. Trước khi mở soak
mới, chạy diagnostic canary với service cgroup PSI/reclaim/CPU/io.stat và clock
observer. Không sửa gap budget để làm run cũ thành PASS. Chi tiết:
[PROJECTED_OPERATIONAL_SOAK_20261003.md](docs/archive/PROJECTED_OPERATIONAL_SOAK_20261003.md).

**03/10/2026, sau canary terminal:** projected ML canary đã đạt aggregate
normal-only (114.984 decision, 21/21 key, 0 alert/restart). Đang chuẩn bị
operational run mới; không resume R10-C3 và không sửa model/policy frozen.
Starter opt-in `COLLECTOR_VARIANT=projected` +
`PROJECTED_CANARY_PLAN_SOURCE` sẽ bind plan SHA, verified per-node loader/object
và unit SHA trong `SOAK_START.json`. Selector kiểm tra lại safety capture và
live revision trước khi cài. Resume đổi variant/plan bị từ chối; monitor kiểm
tra checksum START, worker marker, env/path/binary/unit mỗi poll. Finalizer
dùng `remote_source_root` đã đăng ký, không repo cũ hardcode.

Capacity đăng ký **mới** dự kiến: min-free-byte **0**, max-root-used **85%**.
Worker3 đang khoảng 81%, còn 119 GB; tốc độ JSONL ở canary 900 s dự báo khoảng
**17 GB/node/25 giờ** cho feature + decision, chỉ là ngoại suy, không là
đảm bảo storage usage. Giữ percentage/pressure guards và dừng nếu vượt.
Không sửa ngưỡng capacity marker C3 hoặc yêu cầu dự trữ cố định 64 GiB.
Thời điểm START và lịch finalize chỉ ghi sau khi preflight thật đạt.

Ngày triển khai code: 02/10/2026. Đây là protocol đánh giá mới, không phải model
mới. Candidate ExtraTrees và semantic/temporal policy R10-C1 giữ nguyên bytes.
Không đổi nhãn hoặc tiêu chuẩn của các run cũ đã fail.

**Trạng thái mới:** R10-C3 đã infrastructure-reject lúc **11:37:15 ICT 02/10**
vì snapshot consistency retry exhausted trên worker1. Archive hoàn tất 11:38:33;
control collectors được phục hồi. Lịch finalize 12:03 ngày 03/10 bên dưới chỉ
là lịch đã đăng ký trước failure, **không còn là lịch một run đang chạy**.
Thử projected-counter collect-only canary riêng sau failure không resume R10-C3.

## 1. Điều chỉnh gì và không điều chỉnh gì?

| Hạng mục | Legacy strict soak | Operational soak v1 |
|---|---|---|
| Alert đầu tiên | Dừng ngay | Ghi đầy đủ, đánh giá ngân sách ở cuối run |
| Volume Longhorn không liên quan | Có thể dừng cả run | Warning, không loại exposure |
| Dependency degraded còn attached | Dừng ngay | Cho phục hồi tối đa 300 giây/incident |
| Tổng đoạn degraded + recovery padding | Không có cách phân đoạn này | Tối đa 900 giây, vượt thì fail |
| Telemetry availability | ≥0,999 | Giữ nguyên ≥0,999 |
| Max single telemetry gap | ≤10 giây | Giữ nguyên ≤10 giây |
| Counter integrity, finite vector, identity/revision | Fail closed | Giữ nguyên fail closed |
| Bằng chứng terminal | `NORMAL_PASS` | `OPERATIONAL_PASS`, không thay thế `NORMAL_PASS` |
| Blind/promotion tự động | Có interlock riêng, không promote | Không tự mở blind và không promote |

Profile opt-in: [`operational-soak-v1.json`](sentinel_pulse/protocol/operational-soak-v1.json).
Không cung cấp profile thì starter/monitor/finalizer vẫn dùng strict protocol cũ.
Các run R10-C1/R10-C2 đã terminal không được resume bằng profile mới.

## 2. Ngân sách alert

Tiêu chí vận hành ban đầu, đăng ký trước run:

- Toàn bộ: `all_alerts / valid_workload_hours ≤ 0,01`.
- Mỗi workload/container: `all_alerts_of_key / valid_hours_of_key ≤ 0,05`.
- Mọi key trong manifest phải có ít nhất **24 giờ scored exposure hợp lệ**.
- Collector đăng ký tối đa 25 giờ; không kéo dài tùy tiện khi thấy kết quả.

Ví dụ nếu đủ 21 key × 24 giờ = 504 workload-hour, ngân sách toàn bộ cho phép
tối đa 5 alert; từng key 24 giờ cho phép tối đa 1 alert. Một workload quá nhiễu
không thể bị che bởi tổng exposure của các workload khác.

Các ngưỡng này là engineering acceptance budget ban đầu, **không phải mức FPR
đã đo hoặc tối ưu theo holdout fail**. Thay chúng cần profile/run mới. Hash của
file profile được lưu trong marker; resume với profile khác bị từ chối.

Alert trong đoạn degraded vẫn nằm trong tử số ngân sách. `alerts_during_degraded`
được báo riêng, không bị xóa hoặc chuyển thành suppressed. Báo cáo không tự
gán ground-truth false positive cho từng alert; cần adjudication khi công bố FPR.

## 3. Dependency scope và các lỗi vẫn phải dừng

Binder lấy 21 workload/container từ frozen manifest, chuẩn hóa thành controller,
bổ sung ba AIMS loadgen cần thiết cho exposure. Từ pod đang Ready, binder lấy
PVC rồi ánh xạ qua Bound PV tới `spec.csi.volumeHandle` của Longhorn. Không dùng
substring namespace để tự đoán volume liên quan. CNPG cluster được lấy từ pod
label `cnpg.io/cluster`. Scope được khóa trong `SOAK_START.json` trước start.

Stateless controller cần ít nhất một Ready pod để không đánh dấu HPA 4→3 là
lỗi; số replica lúc đăng ký vẫn được lưu và thay đổi được ghi warning.
StatefulSet/StrimziPodSet/CNPG giữ số Ready lúc đăng ký làm ngưỡng tối thiểu.
Capacity/SLO của website không được chứng minh chỉ bằng gate này.

Những điều kiện vẫn fatal:

- Worker collector NotReady, missing hoặc có pressure condition/taint nguy hiểm.
- Dependency volume missing/faulted/detached hoặc trạng thái không xác định.
- Storage topology vi phạm guard của protocol; telemetry hard integrity lỗi.
- Identity/source/revision thay đổi; detector restart/inactive; mất collector.
- Không đọc/parse được health API, hoặc health observation gap >180 giây.
- Dependency không phục hồi trong 300 giây, tổng exclusion >900 giây.

Degraded-but-attached, dependency pod unready và CNPG degraded có thể tiếp tục
trong ngân sách. Topology guard global vẫn kiểm tra cả cụm; không dùng việc
scope volume để bỏ qua duplicate disk UUID hay replica placement sai.

## 4. Đo valid exposure, không lấy thời gian đồng hồ để thay thế

[`operational_soak.py`](sentinel_pulse/operational_soak.py) ghi health JSONL trong
suốt run. Khi quan sát degraded, exclusion bắt đầu từ lần kiểm tra trước đó
(conservative bound), kết thúc ở lần xác nhận hồi phục cộng 30 giây padding.
Monitor mặc định polling 60 giây, không bảo đảm nhìn thấy mọi lỗi ngắn đã tự
phục hồi giữa hai poll. Raw telemetry/cadence và journal vẫn cần được đối chiếu.

[`evaluate_operational_soak.py`](sentinel_pulse/evaluate_operational_soak.py):

1. Kiểm tra marker/model/policy/run/node identity và replay exclusion policy.
2. Giữ toàn bộ alert; tách số alert trong degraded.
3. Không tính warming, window >0,8 giây hoặc window giao với exclusion vào valid
   scored exposure. Window trong tập hợp hợp lệ phải có start/end hữu hạn.
4. Lấy hợp các interval theo workload/container qua nhiều pod/node; không cộng
   đôi exposure khi hai replica cùng hoạt động.
5. Yêu cầu ≥24 giờ valid scored exposure/key và đánh giá hai ngân sách alert.
6. Yêu cầu aggregate telemetry vẫn pass ≥0,999/gap≤10/zero hard integrity.

Vì vậy không thể chỉ bỏ đoạn xấu rồi claim 24 giờ nếu exposure hợp lệ thiếu.
Không tính đoạn không quan sát được là normal, không dùng filler/zero vector.
Gián đoạn telemetry vẫn sử dụng history-reset/warming đã có trong detector;
không sửa runtime ML đang freeze. Health-only incident được đánh dấu và loại
exposure cộng padding, không âm thầm thay score hoặc state của detector.

Profile không chứng minh kernel-to-alert 1–2 giây. Số đo ấy vẫn cần timestamp
kernel/attack và evaluation riêng trên workload-hour/incident hợp lệ.

## 5. Confidence interval và giới hạn thống kê

Báo cáo có equal-tail Poisson rate interval 95%, tính từ count và exposure bằng
chi-square quantile. Đây là interval **có điều kiện trên giả thiết Poisson**,
không phải acceptance gate và không bảo đảm coverage khi alert theo burst.
Paper cần phân tích block-bootstrap/temporal dependence và adjudication độc lập.
Code sử dụng `chi2.ppf`; API quantile được mô tả trong
[tài liệu SciPy](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.chi2.html).

`legacy_zero_alert_normal_gate` được giữ để so sánh. Operational pass không làm
kết quả strict fail biến thành strict pass. Thiếu exposure là evidence rejection;
vượt ngân sách alert sau khi đủ identity/health/telemetry/exposure là normal-gate
rejection, không được đổi thành infrastructure failure để rerun thuận tiện.

## 6. Chạy profile mới

Chỉ chạy từ source worktree sạch, với model/policy đã freeze bên trong worktree.
Không trỏ vào evidence directory của run cũ.

```bash
# LOCAL_ROOT/PYTHON/MODEL_SOURCE/POLICY_SOURCE/SSHPASS đã được cấu hình;
# không ghi credential vào Git hoặc lệnh được lưu trong báo cáo.
export OPERATIONAL_CONTRACT_SOURCE="$LOCAL_ROOT/sentinel_pulse/protocol/operational-soak-v1.json"
export NORMAL_RUN_ID="pulse-operational-normal-<UTC_TIMESTAMP>"
export STOP_AFTER_NORMAL=true
bash "$LOCAL_ROOT/sentinel_pulse/run_500ms_candidate_lifecycle.sh"
```

Lifecycle ép duration 90.000 giây và stop-after-normal khi profile được cung cấp.
Eligible finalize ở phút thứ 24h50, monitor tiếp tục qua margin mặc định 300
giây; freeze dự kiến khoảng 24h55, trước collector bound 25h. Kết quả pass còn
phụ thuộc đủ exposure/coverage/integrity, không được suy ra từ lịch dự kiến.
Không dùng finalization margin tùy ý lớn hơn headroom của collector.

Đăng ký capacity riêng cho run C3 đã terminal: tối thiểu 64 GiB trống, trần sử dụng root
85%. Worker3 lúc chuẩn bị có 123.142.631.424 byte trống (~114,69 GiB), `df`
hiển thị 80%; capture C2 dài khoảng 2h43 chiếm 771 MiB trên node này. Trần 80%
không đủ headroom cho capture 25 giờ. Đây là thay đổi engineering capacity
đăng ký trước start, không nới telemetry hay sửa evidence cũ. Nếu vượt 85% hoặc
còn dưới 64 GiB, run vẫn phải fail; dự báo dung lượng không bảo đảm tăng trưởng
Longhorn/workload trong tương lai.

Source main cho **run mới** nay mặc định `MINIMUM_ROOT_AVAILABLE_BYTES=0`, tức
không bắt buộc chừa một sàn 64 GiB. Percentage guard vẫn giữ (starter mặc định
80%; override phải đăng ký trước start), cùng node pressure/integrity guards.
`capacity_contract.py` đọc hai giá trị capacity từ marker khi resume, không lấy
default mới áp vào run cũ; explicit override khác marker bị từ chối trước monitor.
Thay đổi không được áp ngược vào worktree frozen hoặc marker R10-C3.

Giữ runtime/environment/source hash trong marker và chạy supervisor như strict
lifecycle. Sau finalize kiểm tra `OPERATIONAL_REPORT.json`, `OPERATIONAL_PASS`,
`OPERATIONAL_SHA256SUMS`, `FINAL_SHA256SUMS` và control-collector restoration.
Nếu fail vẫn archive đầy đủ; không restart cùng run ID để thử lại.

## 7. Trạng thái triển khai

Code và shell integration được triển khai trong ngày 02/10. Các test mới kiểm
tra cả nhánh operational và legacy: alert đầu không abort operational, legacy
vẫn abort; integrity/fatal health vẫn dừng, exclusion tamper bị reject, exposure
không cộng đôi và alert trong degraded không bị giấu.

Observer hạ tầng 6 giờ từ 10:24 đến khoảng 16:24 ICT là run riêng. Chưa có
formal operational soak pass; không lấy kết quả từ observer thay normal gate.
Receipt start nằm trong `validation-evidence/operational-soak-v1-20261002/`.
Source runtime riêng trên VM: `/home/dat/eBPF-project-operational-soak-20261002`,
commit `464bb99c3dc69611d4bb05f8b16434e7a9c0b4ab`, 337 test + 12 subtest
pass trong 33,29 giây. Tracked worktree sạch trước start, bundle verify pass;
model SHA `6ddf7cf9...`, policy SHA `602165bd...` không đổi.

Run `sentinel-pulse-operational-r10-c3-20261002T040300Z` từng ACTIVE trên ba
worker, marker start thực tế **11:08:00 ICT 02/10**. Tên run ID ghi thời điểm
đăng ký, không được dùng thay timestamp start thực. Lifecycle và supervisor
chạy bằng systemd độc lập phiên chat. Checkpoint 11:10: cả ba detector/collector
active, 0 restart, first monitor snapshots 2.891/1.885/638 decision, 0 alert;
health không fatal/transient/exclusion. Đây không phải kết quả terminal.

Lịch đăng ký cũ là eligible finalize 11:58 ICT ngày 03/10 cộng margin 300 giây,
nhưng **đã hủy theo failure 11:37:15 ICT ngày 02/10**. Archive hoàn tất
11:38:33 ICT; checksum kiểm tra lại 17:18 ICT đạt. Candidate đã dừng, control
collectors phục hồi. Source worker
ở `/home/dat/sentinel-pulse-operational-runtime-20261002`; raw đầy đủ giữ trên
worker và evidence root `/home/dat/sentinel-pulse-evidence/operational/` trên VM.

Canary projected counters bắt đầu 17:19:02 ICT ngày 02/10 trên worker1,
collect-only 900 s, không thay source C3 hoặc model/policy. Regression source
main mới đạt 355 test + 20 subtest; không gán kết quả này cho frozen commit
C3. Chi tiết ở [PROJECTED_COUNTER_CANARY.md](docs/archive/PROJECTED_COUNTER_CANARY.md).

**Amendment 03/10, 09:51 ICT:** worker1 projected canary đã terminal và full
collector safety review đạt (38.505 row, 16/16 node key, measured span 899,007 s,
source/capture SHA khớp). Hai canary collect-only worker3/4 đang chạy từ 09:44
ICT, duration 900 s, chưa terminal tại checkpoint. Main source đã bổ sung
duration/coverage/checksum evaluator và đạt **370 test + 20 subtest** trên host
và VM. Candidate ML vẫn dừng; không restart C3, không mở blind và không dùng
canary collector thay operational normal gate.

Timer full safety review đã đăng ký cho hai worker lúc khoảng 10:01 ICT;
kiểm tra kết quả 10:03 ICT. Source reviewer riêng readonly và expectation được
hash, không sửa source C3 hoặc auto-deploy ML khi collector review đạt.

**Terminal amendment 03/10, 10:02 ICT:** cả hai timer review đã hoàn tất exit
0, source/duration/coverage đạt 15/15 và 19/19 node keys. 3/3 collector review
đạt, union 21 key và 117.412 feature row. Không còn canary/review chạy ngầm;
ML candidate vẫn dừng. Tiếp theo phải mở ML canary mới với bundle frozen,
không được coi collector canary là operational normal/latency-attack evidence.

**Amendment 03/10, 10:15 ICT:** ML canary projected mới đã active 3/3 worker,
run `pulse-projected-ml-c1-20261003T031200Z`, model/policy frozen, audit-only,
900 s/node. Chưa mở operational soak successor; run C3 vẫn rejected bất biến.
Chi tiết và lịch kiểm tra 10:35 ở
[PROJECTED_ML_CANARY_20261003.md](docs/archive/PROJECTED_ML_CANARY_20261003.md).
