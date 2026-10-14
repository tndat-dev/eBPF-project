# C3 recovery: HPA làm thay đổi tập cgroup trong capture

## Kết luận từ kiểm tra trực tiếp

SSH ngày **14/10/2026** xác nhận recovery **attempt 17 đã pass** trên ba worker
sau amendment. C3 đã hoàn tất cả 10/10 phase, kể cả năm regime holdout.
**16 attempt recovery bị từ chối** được giữ nguyên. ETA ban đầu không đạt do
vòng retry bên dưới; không có model nào đang train hay attack được inject
trong vòng thu normal này.

Đây là lỗi giả định trong điều phối thí nghiệm, không phải chứng cứ model
phát hiện sai hay bằng chứng HPA hoạt động sai. `NRestarts=0` của coordinator
không chứng minh campaign có tiến triển: process vẫn sống trong vòng retry.

## Root cause và bằng chứng

1. Runner đổi traffic từ steady sang recovery, đăng ký danh sách cgroup ngay,
   chạy baseline 300 giây rồi attach probe trong 600 giây.
2. HPA `production/aims-waypoint` có min=2, max=4, target CPU=70%,
   `scaleDown.stabilizationWindowSeconds=300`. Tải recovery làm HPA scale
   từ 4 xuống 3 replica sau cửa sổ ổn định.
3. Một replica waypoint trên worker `.239` bị xóa sau thời điểm START: mất
   cgroup container `istio-proxy` và hai cgroup được resolver đánh dấu pod-slice.
   Capture metadata ghi nhận việc này; analyzer đối chiếu tập target cố định
   trong START nên báo mismatch.
4. Runner từ chối toàn phase ba worker rồi phục hồi traffic steady. HPA lại
   scale 3 → 4; retry recovery lặp đúng chuỗi scale-down trước đó.

Ví dụ attempt 1:

| Worker | Terminal worker | Analyzer |
|---|---|---|
| `.237` | completed, exit 0 | valid, problems={} |
| `.238` | completed, exit 0 | valid, problems={} |
| `.239` | completed, exit 0 | metadata_target_allowlist_mismatch=55; target_coverage_mismatch=543 |

Attempt 2 trên `.239` có 56 metadata mismatch và 553 coverage mismatch.
Metadata của các attempt 1, 2, 15 chỉ ra các pod waypoint UID khác nhau bị
xóa; không suy diễn từ tên error chung. Kubernetes events xác nhận scale-down
4 → 3 và scale-up 3 → 4. START/TERMINAL/metadata/histogram/seal của mọi attempt
được giữ nguyên dưới `syscall-capture-c3-r2/selection/` trên NFS.

## Thay đổi đã triển khai

- Coordinator mới: commit `49280a6b7c0c81c3a3b50c20e8383e2c8857eb75`, source
  `/home/dat/pulse-syscall-c3-settle-20261014/source` trên control plane/worker.
- Sau đổi regime, đợi identity cgroup trên ba worker không đổi **360 giây
  liên tục**. Nếu đổi UID/cgroup/revision, mất health hoặc gián đoạn poll quá
  60 giây, tính lại khoảng ổn định. Sau đó mới đăng ký worker và thu baseline.
- Không tắt/sửa HPA, không pin replica, không bỏ validation mismatch, không
  đổi model/threshold hoặc các thông số snapshot/feature/capture.
- Kiểm tra SHA-256 xác nhận capture, feature, model, analyzer và bốn binary
  loader/object trên worker không đổi. Chỉ coordinator được đổi source.
- Không ghi đè START gốc. Amendment
  `AMENDMENT-target-settle-20261014.json` bind original START và effective
  contract; SHA-256 `1b11286f109da381e27eed7bea04d2716e727ca833383dcbd658554b9b53b7e7`.
  Receipt của attempt mới bind amendment này. Policy cấm amendment thay
  semantics capture/model/analysis.
- Giữ checkpoint bốn phase đã hoàn tất. Coordinator cũ được dừng có chủ đích
  để cập nhật; worker attempt 16 không bị kill, được phép đóng/seal như cũ.
  Capture soak 24 giờ và shadow không bị restart hoặc thay source.
- Service systemd có drop-in mới, được enable và active từ 09:05 UTC+7;
  tiếp tục độc lập với SSH. 40 test liên quan pass.

## Phạm vi kết luận

Terminal và seal của recovery attempt 17 đã được audit hợp lệ. Nếu workload
tiếp tục autoscale, runner vẫn phải đợi ổn định; 360 giây không bảo đảm
workload không đổi trong tương lai.
Thí nghiệm hiện tại đánh giá những đoạn identity ổn định; chưa phải đánh giá
detector xuyên suốt autoscaling/rollout. Các đoạn churn bị loại khỏi cohort
phải được thống kê riêng, không gán normal/TN hoặc xóa evidence.

Năm regime holdout cũng đã hoàn tất. Bằng chứng mới nằm trong
`validation-evidence/pulse-parallel-completion-20261014/c3-TERMINAL.json` và
hai preflight-complete JSON cùng thư mục. Kết quả này xác nhận sửa điều phối
capture, không chứng minh model đã có recall/precision tốt hay hỗ trợ mọi rollout.
