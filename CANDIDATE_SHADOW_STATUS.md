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

Run normal-observation **`normal-a1-20261013` đang chạy trên cả ba worker** với
source commit `2c1a72d`, model manifest SHA
`747c4eed2a9a74321d0ac3b716c201c449f946665252baa1ca314b1f18278a08`, policy SHA
`fd0be94a4ca7f2cd64b97bf5c7dc074763405f821ab346e8e19bb5975d10f401`, và 86,400
giây boundary exposure/node. Capture/shadow units đều `enabled`; checkpoint
được xác minh gần nhất lúc **06:45 ngày 13/10 (UTC+7)**: cả ba capture còn
`collecting`, cả ba shadow `active`; không có capture error, capacity pause,
systemd restart hoặc warning trong journal capture. Boundary exposure: worker1
**18,089 s (20.94%)** với 2,915,756 feature rows; worker3 **18,063 s (20.91%)**
với 859,158 rows; worker4 **18,042 s (20.88%)** với 3,151,312 rows. Dung lượng
trống: worker1 **152.2 GB**, worker3 **299.4 GB**, worker4 **99.0 GB**; thư mục
run trên worker4 đang chiếm khoảng **9.1 GB**. Tiến độ chỉ là lượng telemetry đã
thu, không phải kết quả chất lượng hay confusion matrix. Units tự khởi động lại
khi node reboot; capture checkpoint/fsync mỗi 5 giây và resume từ checkpoint.

Shadow vẫn chạy nhưng chưa realtime: một decision mới nhất quan sát được có
`feature_event_age_seconds` khoảng **52 phút** trên worker4 và khoảng **23 phút**
trên worker1 (worker3 có mẫu mới nhất khoảng 0.17 giây). Đây là độ tuổi của các
row được lấy mẫu, **không phải p95 hay kernel-to-alert latency**. Shadow worker4
đang dùng xấp xỉ một CPU core và 782 MB RAM (peak 806 MB, giới hạn 1 GiB); số
dòng decision bằng khoảng 82.7% feature rows hiện có tại snapshot, nên backlog
có thể còn tăng. Có row preview dương; chúng vẫn là ứng viên chưa adjudicate,
không được gọi là false positive lúc này. Backlog shadow không làm mất exposure
capture, nhưng hiện chưa đạt yêu cầu latency thấp.

Ngưỡng **70 GiB** là mức ngân sách đăng ký ban đầu, không còn là điều kiện
terminal: khi chạm, collector mở rộng theo free space hiện có sau reserve và
ghi `expanded_byte_budget_from_current_free_space`. Khi free space chạm reserve
12 GiB, collector đóng segment, ghi event pause (không tính normal exposure),
chờ phục hồi rồi tiếp tục từ checkpoint. Việc này tránh fail sớm chỉ vì chạm
ngưỡng kế hoạch, nhưng không thể bảo đảm trước hỏng đĩa, mất NFS/hệ điều hành
hoặc hết sạch dung lượng; nếu tài nguyên chưa hồi phục, run sẽ ở trạng thái
waiting thay vì giả vờ đã hoàn tất.

Run tiếp tục thu; không train/tune hoặc chạy blind attack trong independent
normal soak. Sau khi từng worker đạt 86,400 giây exposure, kiểm tra terminal,
journal, gaps, decision coverage và disk. Mọi pause/gap không cộng normal
exposure; nếu có pause, thời điểm kết thúc lùi tương ứng. Sau đó mới adjudicate
preview/normal và tính confusion matrix; cải thiện candidate trên split phát
triển riêng.

Ước tính hiện tại: còn khoảng **19 giờ exposure tối thiểu** nếu không có pause,
song song trên ba worker; mọi gap/pause sẽ đẩy hạn hoàn thành tương ứng. Capture
có thể đạt đủ khoảng **01:43 ngày 14/10 (UTC+7)**. Shadow đang hụt tốc độ; nếu
tỷ lệ xử lý quan sát được trên worker4 (~82.7% số feature rows) giữ nguyên, phần
drain sau capture có thể mất xấp xỉ **5 giờ**. Đây là ngoại suy từ snapshot, có
độ bất định cao; kiểm tra lại gần 01:45 ngày 14/10 rồi mới ước lượng chính xác
hơn. Không được coi đây là cam kết hoàn tất.

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
