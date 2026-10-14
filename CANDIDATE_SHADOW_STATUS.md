# Candidate Shadow Runtime — trạng thái hiện hành

## Mục đích và giới hạn

`sentinel_pulse.candidate_shadow` là bộ chấm điểm **shadow-only** cho candidate
idle-aware đã đóng băng. Nó đọc feature record schema
`sentinel-pulse-extended-feature-v2`, contract
`pulse-entered-plus-seccomp-skip-idle-v2`, xác minh vector 249 chiều và giữ
history riêng theo workload, pod UID, container, revision và cgroup.

Candidate chỉ được chấm sau khi có đủ **4 feature window liên tiếp** (3 window
lịch sử + window hiện tại). Cadence 500 ms phải nằm trong khoảng 350–800 ms;
gap/reset không được nối qua. Collector có `task_state_update_fail` hoặc
`snapshot_projection_fail` thì record thành `degraded_telemetry` và history bị
xóa. Đổi UID/revision/cgroup tự tạo một history mới.

Đầu vào hỗ trợ cả một JSONL file lẫn các file capture luân phiên theo
`segments/sNNNN/features.jsonl`; sau reboot, follower bắt đầu ở cuối segment
mới nhất để không chấm lại backlog cũ, rồi đọc các segment kế tiếp. Đầu ra
JSONL là raw score/preview, trạng thái warming/degraded và thời gian inference.
Invariant cố định: `alert=false`, `policy_applied=false`,
`serving_compatible=false`. Đây **không phải detector serving**, không phát
alert, không thực hiện enforcement, không tạo confusion matrix và không được
dùng để tuyên bố precision/recall.

## Policy preview và đóng gói artifact

Policy preview riêng được đăng ký tại
`sentinel_pulse/protocol/idle-aware-candidate-preview-policy-c1.json`, bind với
SHA-256 manifest model-only. Quy tắc chỉ đọc `joint_p <= alpha` đã hiệu chuẩn
trong model theo workload. Không thêm semantic gate hoặc temporal confirmation
để tránh âm thầm làm giảm recall. Kết quả chỉ là cờ `candidate_alert_preview`;
invariant `alert=false`, `policy_applied=false`, `serving_compatible=false` vẫn
giữ nguyên. Mức 5%/30 windows là ngân sách thiết kế để theo dõi, **không phải
bảo đảm FPR** vì cửa sổ chồng lấn và nhãn normal chưa adjudicate.

Bundle benchmark ở `/home/dat/pulse-idle-reference-benchmark-c1-20261012` chỉ
có manifest/kết quả; artifacts ở reference root
`/home/dat/pulse-idle-reference-c1-20261012`. SSH ngày 12/10/2026 xác nhận
21/21 model artifacts có mặt và SHA-256 khớp manifest. Đã thêm
`sentinel_pulse.bundle_candidate`: giữ nguyên manifest, xác minh hash trước và
sau khi copy; từ chối ghi đè output đã có. Bundle đã được dựng riêng trên NFS
và được xác nhận tải đủ 21 model trên cả ba worker.

## Kiểm chứng code

Ngày 13/10/2026, toàn bộ repo đạt **1.131 passed, 7 skipped, 20 subtests**.
Thay đổi mới giữ record của workload không có model ở trạng thái
`candidate-model-unavailable` nhưng bỏ decode vector không cần thiết; output
flush theo lô mỗi giây và `fsync` tối đa mỗi 5 giây. Decision/preview vẫn ghi
từng dòng; không thay candidate, policy hay ngưỡng. Collector khi chạm ngưỡng
byte đăng ký sẽ mở rộng ngân sách đúng bằng phần dung lượng hiện có sau khi trừ
reserve, ghi journal; khi chạm reserve thì pause và tiếp tục sau phục hồi thay
vì terminal sớm. Installer yêu cầu đủ free-space cho capture 70 GiB, shadow
headroom 8 GiB và reserve 12 GiB. Các thay đổi đã unit-test local và source
đang được chạy trong soak A1.

## Trạng thái cluster

Kiểm tra SSH ngày 12/10/2026 trên ba worker cho thấy disk trống khoảng **160.9
GiB (worker1), 118.1 GiB (worker4), 303.0 GiB (worker3)**. Smoke capture mới
trên worker1 đạt **60.44 giây boundary exposure**, tạo 9,758 feature rows,
8,938 rows đủ điều kiện review và 0 lỗi; raw/features/observations khoảng
22.7 MB. Đây chỉ là kiểm tra kỹ thuật một node, không phải normal soak, không
phải dữ liệu độc lập đã adjudicate và không dùng để train/tune.

Smoke shadow đầu tiên **không hợp lệ để kết luận scoring**: scorer được khởi
động sau khi smoke capture ngắn đã đóng segment, nên không có decision rows;
systemd kết thúc nó theo giới hạn 180 giây riêng của smoke. Không tính lần đó
là canary thành công. Đã xác nhận `ProtectSystem=full` vẫn cho phép ghi vào
`/var/lib` qua `ReadWritePaths`.

Integrated smoke B2 trên worker1 chạy capture đủ **300.209 giây**: 48,462
feature rows, 47,642 eligible, 0 lỗi, capture 112,411,154 byte. Shadow ghi
48,455 decision rows, 31,908 model-unavailable, 16,463 scored, 84 warming,
không có `record_rejected`, và 133 preview dương chưa adjudicate. Shadow
event-age p95 là **27.3 giây** lúc capture kết thúc; sau khi đọc gần hết backlog,
event-age của row cuối khoảng **31.8 giây**. Candidate shadow vì vậy chưa đạt
mục tiêu latency thấp; đây không phải kernel-to-alert production latency.
Ngoại suy từ smoke: capture khoảng **32.3 GB/24 giờ/node**, shadow khoảng
**10.6 GB/24 giờ/node**. Đây là ước tính từ 5 phút, không phải số đo 24 giờ.

Ngày 13/10, SSH tương tác xác nhận **6/6 node Ready, v1.34.10**. NFS
`10.1.16.233:/sentinel-pulse` được mount trên cả ba worker; legacy collector
và resolver active. Các pod workload AIMS chính đang Running; một số pod
`Completed` là job/pod kết thúc, không tính như replica Ready. Free space trước
run: worker1 **163.0 GB**, worker3 **302.6 GB**, worker4 **117.2 GB**.

Run normal-observation **`normal-a1-20261013` đã hoàn tất capture trên cả ba worker** với
source commit `2c1a72d`, model manifest SHA
`747c4eed2a9a74321d0ac3b716c201c449f946665252baa1ca314b1f18278a08`, policy SHA
`fd0be94a4ca7f2cd64b97bf5c7dc074763405f821ab346e8e19bb5975d10f401`, và 86,400
giây boundary exposure/node. Kiểm tra SSH **09:06 ngày 14/10 (UTC+7)** xác nhận
terminal `completed_observation`, không còn writer capture; errors=0 và
capacity_pause_count=0 trên cả ba node:

| Worker | Boundary exposure | Feature rows |
|---|---:|---:|
| worker1 `.237` | 86.400,249 s | 13.928.602 |
| worker4 `.238` | 86.400,297 s | 15.096.447 |
| worker3 `.239` | 86.400,390 s | 4.124.430 |

Shadow vẫn active, `NRestarts=0`, model/policy không thay đổi. Row cuối của ba
worker đã tới cuối capture: worker1 window_end=1791916967,012;
worker4=1791917016,301; worker3=1791916992,378. Worker1 row cuối mang trạng thái
`candidate-model-unavailable`; worker4 row cuối scored có event age
**18.816,45 s (~314 phút)** lúc xử lý; worker3 row cuối **0,01164 s**. Chưa audit
mọi decision row để xác nhận coverage hoàn chỉnh. Các con số là mẫu row cuối,
**không phải p95 hay kernel-to-alert**. Chưa chốt confusion matrix.

Evidence: `/home/dat/pulse-syscall-capture-c3/inspection-20261014-0906.json`.
Capture đủ 24 giờ không đồng nghĩa candidate đạt realtime, stable hoặc chất
lượng phát hiện. C3 đã bắt đầu thu dữ liệu mới trong thư mục riêng sau khi cả
ba capture đóng; nó không sửa hoặc thêm record vào capture soak đã hoàn tất.

Ngưỡng **70 GiB** là mức ngân sách đăng ký ban đầu, không còn là điều kiện
terminal: khi chạm, collector mở rộng theo free space hiện có sau reserve và
ghi `expanded_byte_budget_from_current_free_space`. Khi free space chạm reserve
12 GiB, collector đóng segment, ghi event pause (không tính normal exposure),
chờ phục hồi rồi tiếp tục từ checkpoint. Việc này tránh fail sớm chỉ vì chạm
ngưỡng kế hoạch, nhưng không thể bảo đảm trước hỏng đĩa, mất NFS/hệ điều hành
hoặc hết sạch dung lượng; nếu tài nguyên chưa hồi phục, run sẽ ở trạng thái
waiting thay vì giả vờ đã hoàn tất.

Tiếp theo: audit decision coverage, journal/gaps và nhãn preview/normal để
tổng hợp đánh giá. C3 recovery bị lặp vì HPA/cgroup; đã sửa bước đợi identity
ổn định. ETA capture C3 mới khoảng **12:00–12:30 ngày 14/10**, phụ thuộc identity
ổn định; đây chưa phải ETA của toàn bộ blind evaluation.

Candidate vẫn model-only; preview không phải alert production. Không tune
candidate trong independent normal soak; giữ mọi preview và khoảng degraded để
adjudicate sau thu thập. V7 và campaign khác không bị thay đổi.

## Chạy thủ công trên feature stream riêng

Sau khi candidate và source đã được cài ở vị trí riêng, có thể chạy:

```bash
python3 -m sentinel_pulse.candidate_shadow \
  --features /path/to/new-idle-aware/features.jsonl \
  --candidate-dir /path/to/frozen-candidate \
  --manifest-sha256 <sha256-da-duoc-dang-ky> \
  --output /path/to/new-run/shadow-scores.jsonl \
  --run-id <unique-shadow-run-id> \
  --policy /path/to/idle-aware-candidate-preview-policy-c1.json
```

Với collector chia segment, dùng `--features-root /path/to/capture-root` thay
cho `--features`; không truyền đồng thời cả hai.

Mặc định reader theo dõi phần dữ liệu mới được append và theo file qua rotation.
Thêm `--from-start` chỉ khi chủ ý replay một file đã đóng; kết quả replay không
được coi là live latency. `feature_event_age_seconds` chỉ là thời gian từ cuối
feature window tới lúc chấm, **không phải kernel-to-alert**. Đồng hồ lệch được
giữ nguyên dấu để lộ vấn đề thay vì clamp thành số 0.

## Khởi chạy soak quan sát bền vững

Sau khi commit/push và tạo checkout đúng commit trên NFS, chạy installer bằng
runtime venv trên từng worker (dùng cùng run ID):

```bash
sudo /opt/sentinel-pulse/runtime-venv/bin/python -m sentinel_pulse.install_normal_observation \
  --run-id normal-a1-20261012 \
  --source /mnt/sentinel-pulse-archive/runtime-<commit>/source \
  --build /home/dat/pulse-extended-telemetry-c1/build \
  --proof /home/dat/pulse-extended-telemetry-c1/proof-r2 \
  --candidate-dir /mnt/sentinel-pulse-archive/runtime-<commit>/model-bundle \
  --manifest-sha256 747c4eed2a9a74321d0ac3b716c201c449f946665252baa1ca314b1f18278a08 \
  --policy /mnt/sentinel-pulse-archive/runtime-<commit>/source/sentinel_pulse/protocol/idle-aware-candidate-preview-policy-c1.json
```

Mặc định collector cần **86,400 giây boundary exposure trên mỗi node**. Gap,
pause và thiếu free space không được cộng vào exposure. Capture checkpoint/fsync
mỗi 5 giây; systemd bật lúc boot và restart process khi lỗi. Shadow chạy song
song, ghi `decisions.jsonl`; sau restart history warm-up lại. Theo dõi hai unit,
`STATUS.json`, capacity journal và số decision rows trên từng worker. Chỉ xác
nhận hoàn tất khi cả ba capture có `TERMINAL.json` với
`state=completed_observation`, `boundary_observation_seconds >= 86400`, audit
replay thành công và mọi pause/gap được giữ nguyên. Không train/tune hoặc chạy
blind attack trong normal soak.

## Gate trước khi đo accuracy

1. Đồng bộ code đã review và tạo bundle mới từ 21 artifacts đã xác minh; kiểm
   tra model load trên runtime Python của worker.
2. Chạy unit/integration test và đo inference latency trên worker với giới hạn
   CPU/RAM; xác minh shadow không ghi alert.
3. Triển khai collector + scorer shadow bằng run ID/thư mục output mới; không
   thay detector V7 hay dữ liệu candidate đã đóng băng.
4. Mở canary normal mới và ghi mọi candidate preview, kể cả lúc
   workload rollout/telemetry degraded; phân loại degraded riêng, không gọi là
   normal.
5. Thu đủ normal độc lập theo workload/regime, adjudicate trước khi ước lượng
   FPR/precision.
6. Đăng ký blind attack binary/scenario/seed/checksum mới trước khi inject;
   chỉ sau đó tính TP/FN/FP/TN, coverage và kernel-to-alert với unknown công bố
   riêng.
