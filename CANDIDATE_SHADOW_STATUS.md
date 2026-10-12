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

Lần test mới nhất: **1.128 passed, 7 skipped, 20 subtests passed** trong toàn
bộ repo; riêng ba module bundle, policy và shadow có **14 passed**. Đây là test
trong workspace, không phải bằng chứng runtime đã triển khai lên worker.

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

Tốc độ ghi smoke khoảng **22.7 MB/phút**, tương đương gần 33 GB/24 giờ nếu giữ
nguyên tốc độ. Runbook mới đặt hard cap **70 GiB/node** và dự trữ **12 GiB free**;
worker có ít dung lượng nhất vẫn đủ cho budget + reserve. Khi free space xuống
dưới reserve, collector đóng segment, ghi `capacity_events.jsonl`, pause (không
tính là normal exposure), rồi tự tiếp tục từ checkpoint sau khi dung lượng hồi
phục. Journal được hash-bind vào terminal receipt. Hard cap vẫn có thể kết thúc
run nếu bị chạm; capacity được đặt cao hơn gấp đôi mức ghi ngoại suy từ smoke,
nhưng cần theo dõi thực tế và không thể bảo đảm trước mất filesystem/phần cứng.

Installer và systemd pair boot-persistent vừa được thêm nhưng **chưa cài/chưa
mở run 24 giờ**. Cần hoàn tất integrated smoke 5 phút để xác nhận shadow nhận
feature rows khi capture còn chạy, rồi mới cài cùng run ID trên cả ba worker.
Candidate vẫn là model-only; `candidate_alert_preview` chỉ là cờ shadow, không
phải alert production. Giữ nguyên preview/alert và khoảng degraded để
adjudicate sau soak; không tune candidate trong lúc đo này. V7 và campaign
khác không bị thay đổi.

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
