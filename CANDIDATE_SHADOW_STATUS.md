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
sau khi copy; từ chối ghi đè output đã có. Chưa tạo bundle triển khai trên
cluster.

## Kiểm chứng code

Lần test mới nhất: **1.127 passed, 7 skipped, 20 subtests passed** trong toàn
bộ repo; riêng ba module bundle, policy và shadow có **14 passed**. Đây là test
trong workspace, không phải bằng chứng runtime đã triển khai lên worker.

## Trạng thái cluster

SSH kiểm tra master lúc **21:00 ICT, 12/10/2026** cho thấy 6/6 node `Ready`.
`sentinel-detector.service` active là detector legacy (`anomaly_detector2.py`,
10-second window), không phải candidate Pulse. Lần kiểm tra tiếp theo trên ba
worker lúc khoảng **22:10 ICT** thấy idle collection C1 đã chạy xong với exit
status 0 (03:18–05:18 UTC), nhưng mỗi output root chỉ có 4 KiB: không có
`START/STATUS/TERMINAL.json`, segment, hay feature JSONL. Journal chỉ ghi
`Starting`/`Finished`. Vì vậy lần chạy đó **không cung cấp dữ liệu soak hợp lệ**;
nguyên nhân output rỗng vẫn cần truy tiếp. Không có collector đang chạy liên tục.

Snapshot ba worker: available RAM lần lượt khoảng **24,4 / 37,1 / 27,4 GiB**
(worker1/worker3/worker4), disk trống khoảng **160,9 / 295,9 / 115,7 GiB**.
Worker4 đang dùng 81% filesystem nhưng còn hơn 100 GiB; đây là lý do vẫn cần
capacity guard cho capture, không phải bằng chứng DiskPressure.

Candidate hiện vẫn là manifest model-only (`decision_policy=null`,
`serving_compatible=false`). Policy mới chỉ đăng ký cách ghi nhận “would
preview”, không nâng candidate thành detector serving. **Chưa mở candidate
canary/soak mới hay blind attack mới.** Baseline đã xem trước đây không được
tái dùng làm blind confirmation. Source trong workspace chưa được cài lên
cluster; detector V7 và các campaign khác không bị sửa hay dừng.

Không thay thế hoặc nâng cấp `sentinel-pulse-detector-candidate.service` hiện
hữu bằng adapter này. Trước khi shadow canary cần một run ID và thư mục output
mới, candidate manifest/model artifacts được sao chép có kiểm tra SHA-256,
đồng thời feature stream trên worker phải đúng idle-aware v2. Shadow có thể
được dùng để xác minh input, continuity và chi phí inference; muốn đánh giá
confusion matrix cần đăng ký decision policy trước khi mở dữ liệu attack mới,
có normal label protocol và một blind set mới chưa nhìn thấy.

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
