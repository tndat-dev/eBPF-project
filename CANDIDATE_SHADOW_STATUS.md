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

Đầu ra JSONL là raw score, trạng thái warming/degraded và thời gian inference.
Invariant cố định: `alert=false`, `policy_applied=false`,
`serving_compatible=false`. Đây **không phải detector serving**, không phát
alert, không thực hiện enforcement, không tạo confusion matrix và không được
dùng để tuyên bố precision/recall.

## Kiểm chứng code

Test riêng cho shadow, extended capture và policy: **36 passed**. Toàn bộ repo:
**1.114 passed, 7 skipped, 20 subtests passed**. Đây là test trong workspace,
không phải bằng chứng runtime đã triển khai lên worker.

## Trạng thái cluster

Kiểm tra SSH chỉ đọc trên master `10.1.16.234` lúc **21:00 ICT, 12/10/2026**:
6/6 node đang `Ready`. `sentinel-pulse-detector-candidate.service` và
`sentinel-pulse-extended-collection.service` đang inactive; service
`sentinel-detector.service` active là detector legacy (`anomaly_detector2.py`,
10-second window), không phải candidate Pulse này. C2 đang chạy nền tại
**306/608 workload-variant fits**, không bị dừng hay chỉnh sửa.

Candidate hiện có manifest model-only (`decision_policy=null`,
`serving_compatible=false`). Vì thế **chưa mở candidate canary, soak mới hay
blind attack mới**. Những kết quả baseline đã xem trước đây không được tái dùng
làm blind confirmation. Thay đổi source trong workspace hiện cũng chưa được
đồng bộ/cài lên cluster; soak/C2 đang chạy không bị sửa hay dừng.

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
  --run-id <unique-shadow-run-id>
```

Mặc định reader theo dõi phần dữ liệu mới được append và theo file qua rotation.
Thêm `--from-start` chỉ khi chủ ý replay một file đã đóng; kết quả replay không
được coi là live latency. `feature_event_age_seconds` chỉ là thời gian từ cuối
feature window tới lúc chấm, **không phải kernel-to-alert**. Đồng hồ lệch được
giữ nguyên dấu để lộ vấn đề thay vì clamp thành số 0.

## Gate trước khi đo accuracy

1. Chốt/đăng ký decision policy riêng, bind checksum với candidate manifest;
   không sửa manifest model-only cũ.
2. Chạy unit/integration test và kiểm tra inference latency trên worker với
   giới hạn CPU/RAM; xác minh shadow không ghi alert.
3. Mở canary normal mới và ghi tất cả score/false-alert candidate, kể cả lúc
   workload rollout/telemetry degraded; phân loại degraded riêng, không gọi là
   normal.
4. Thu đủ normal độc lập theo workload/regime, adjudicate trước khi ước lượng
   FPR/precision.
5. Đăng ký blind attack binary/scenario/seed/checksum mới trước khi inject;
   chỉ sau đó tính TP/FN/FP/TN, coverage và kernel-to-alert với unknown công bố
   riêng.
