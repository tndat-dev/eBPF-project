# Thực nghiệm syscall C3: nhiều chế độ tải và holdout riêng

## Mục tiêu và cách chạy

Hiện hành SSH **14/10/2026**: C3 **đã hoàn tất 10/10 phase, 30/30 capture worker**,
terminal `completed_frequency_collection`; service đã kết thúc bình thường.
Selection/holdout đều được audit đủ 15 capture. C4 đang chấm holdout riêng,
không tiếp tục attach probe C3. [Trạng thái hai nhánh](PULSE_PARALLEL_EXECUTION.md).

C3 tiếp nối 608 model C2 đã đóng băng. Coordinator chạy bằng systemd trên
`10.1.16.234`; ba worker `.237/.238/.239` thu dữ liệu. Coordinator đợi cả ba
capture `normal-a1-20261013` có terminal `completed_observation`, đủ 86.400
giây boundary exposure và không còn tiến trình `extended_collection` trước
khi đổi tải. Capture soak đã hoàn tất; nó không bị C3 sửa hoặc restart.

Service: `pulse-syscall-capture-c3.service`. Output chính trên NFS:
`/mnt/sentinel-pulse-archive/syscall-capture-c3-r2`.
Source triển khai: commit `b14f888c28e1d7d8752d19fd4d88457d38063a3a`, tại
`/home/dat/pulse-syscall-capture-c3/source` trên control plane và ba worker.

Coordinator hiện dùng commit `49280a6b7c0c81c3a3b50c20e8383e2c8857eb75` ở
`/home/dat/pulse-syscall-c3-settle-20261014/source`, qua amendment có hash
`1b11286f109da381e27eed7bea04d2716e727ca833383dcbd658554b9b53b7e7`.
Capture/model/analyzer và binary giữ nguyên hash; START và attempt gốc không
đổi. Sau đổi regime, đợi cgroup/UID/revision ổn định liên tục 360 giây rồi mới
đăng ký worker. Gap poll >60 giây hoặc thay identity/health sẽ tính lại thời
gian ổn định. HPA vẫn hoạt động. Chi tiết lỗi 16 recovery retry và sửa điều phối
ở [SYSCALL_C3_RECOVERY_INCIDENT.md](SYSCALL_C3_RECOVERY_INCIDENT.md).

Lượt đăng ký ban đầu trong thư mục `syscall-capture-c3` được giữ làm receipt
đã thay thế: chỉ ở trạng thái chờ, chưa đổi tải hoặc attach probe. Lượt `r2`
khóa đúng commit của archive và bổ sung kế hoạch phân tích trước khi thu dữ liệu.

## Dữ liệu cần thu

Hai phần chạy theo thứ tự, mỗi phần gồm năm regime:

1. **Selection/development**: steady, toolmix, peak, burst, recovery.
2. **Normal holdout riêng**: lặp lại năm regime trong những khoảng thời gian
   mới. Không dùng dữ liệu này để chọn top-K hoặc tune model/ngưỡng.

Mỗi regime có 300 giây baseline → 600 giây probe → 300 giây post trên ba
worker chạy song song. Tổng kế hoạch: **30 capture worker**, khoảng **3 giờ
20 phút thu/đối chiếu**, cộng tối thiểu **60 phút đợi identity ổn định** nếu chạy
từ đầu, rollout, chuyển artifact và recovery. Thời lượng
600 giây/regime là vòng thực nghiệm đầu; chưa đại diện mọi chu kỳ vận hành.

Hai probe trong cùng đợt thí nghiệm:

- Histogram full-ID `raw_tp/sys_enter`, snapshot 1 giây: số entry theo syscall
  ID và cgroup, drop counter, map occupancy và metadata workload/revision.
- Projected counter, snapshot 500 ms: raw cumulative snapshots và feature
  `sentinel-pulse-feature-v1`, 249 chiều, rolling history 5, bỏ window idle
  theo cách xây feature legacy. Đây là đầu vào để kiểm tra tương thích với C2.

Kênh feature này không bao gồm syscall bị seccomp bỏ qua trước `sys_enter`;
không tráo dữ liệu idle-aware/extended của soak vào C2 chỉ vì cùng 249 chiều.
Capture runtime hiện có NumPy 2.5.2; chấm model C2 phải dùng venv của C2
với NumPy 2.5.3 và scikit-learn 1.9.1, đồng thời xác minh schema/source.

## Lịch tải đã định nghĩa trong code

Nguồn điều khiển: `ml-service/set_aims_traffic_regime.sh`. Chỉ bốn Deployment
loadgen của Sentinel trong `production` được điều khiển. Cột đầu là số replica
**của từng Deployment** east-west và ingress, không phải tổng của hai loại.

| Regime | East-west / ingress, mỗi loại | Readmix | Dependency | Sleep vòng east-west/dependency |
|---|---:|---:|---:|---:|
| steady | 1 | 0 | 1 | 1 s |
| toolmix | 2 | 4 | 2 | 1 s |
| peak | 4 | 2 | 3 | 0,25 s |
| burst | 6 | 2 | 3 | 0 s |
| recovery | 1 | 0 | 1 | 2 s |

Đây là cấu hình tải, **chưa phải request/s đo được**. Các loadgen hiện có gồm
health/read requests, error-mix đã định nghĩa và handshake dependency; cần
báo phạm vi này khi diễn giải mức đại diện cho traffic thương mại điện tử.

Receipt từng worker bind lịch regime, SHA-256 START và snapshot cấu hình
Deployment sau rollout. Coordinator kiểm tra lại UID/spec loadgen khi thu;
nếu có thay đổi ngoài lịch, ghi `traffic-drift.jsonl`, giữ raw và thu bổ sung.
Snapshot health cụm được lưu mỗi khoảng 30 giây để phân tầng khoảng hạ tầng
không ổn định khi đánh giá; không tự gán các khoảng đó thành normal/TN.

## Phục hồi và giới hạn tài nguyên

- Coordinator dùng `flock`, checkpoint `STATUS.json`, `Restart=on-failure`,
  tự khởi động cùng VM. Đóng SSH/tắt laptop không dừng coordinator.
- Worker probe chạy trong unit systemd riêng, CPU tối đa 1 core, RAM 512 MiB,
  tối đa 1.500 giây/attempt. Nếu worker reboot, đợt đang dở được giữ lại;
  coordinator thu lại đợt thiếu, giữ nguyên các phase đã hoàn tất.
- Mỗi worker lưu riêng dưới `/var/lib/pulse-syscall-capture-c3`. Budget ban đầu
  4 GiB cho thư mục này và yêu cầu hơn 4 GiB trống trước lượt mới. Chạm budget
  cần xử lý dung lượng; runner giữ artifact, không tự xóa dữ liệu.
- Coordinator CPU tối đa 1 core, RAM 2 GiB. Sau mỗi phase, traffic trở lại
  steady. Không có điều kiện `alert == 0` trong vòng thu này.
- Dữ liệu được seal trước khi copy về NFS. Manifest và checksum được kiểm tra
  trước khi đưa capture vào cohort selection. Holdout được lưu riêng.

## Model và kế hoạch đánh giá

C2 có **19 workload × 32 variants = 608 model**. Notification/payment chưa
có model trong bộ C2; capture mới có thể thấy chúng nhưng không tự sinh model
hoặc tuyên bố phủ 21/21. Manifest model dẫn xuất được khóa bằng SHA-256:
`4c379dcabd8ea2c8ca0c19f9e13e186dfa9fe63f0df1ea1a2d4d591e946c4408`.

Replay bằng `sentinel_pulse/variant_replay.py` trên VM đã đối chiếu **608/608**
model với prediction C2 đã lưu: sai lệch score lớn nhất **0**, conformal p-value
và quyết định khớp hoàn toàn. Bằng chứng:
`/mnt/sentinel-pulse-archive/syscall-variant-replay-c3/TERMINAL.json`.
Đây là kiểm tra tái lập scoring trên dữ liệu đã xem; precision/recall vẫn null.

Kế hoạch đã đăng ký cho vòng đánh giá sau capture:

1. Thống kê tần suất/count/rate theo workload × revision × regime trên
   selection; syscall hiếm hoặc chưa thấy được báo riêng.
2. Kiểm tra seal, schema, thời gian/source không giao train/calibration và
   coverage holdout. Chấm cùng context cho mọi biến thể, mask tại cả bốn
   vị trí temporal; báo model-only và policy nếu policy đã được bind hợp lệ.
3. Đăng ký blind binary/cases mới, target identity, seed/rate và timestamp
   injection trước execution; chạy cùng trial cho các biến thể. Các miss
   phải được giữ. **C3 capture coordinator chưa tự inject blind attack.**
4. Unit dự kiến là interval workload 30 giây; nhãn normal có provenance,
   khoảng thiếu telemetry/health được báo unknown. Báo confusion matrix,
   precision/recall/FPR, coverage và miss trong mẫu số end-to-end.
5. So sánh paired với full; bootstrap theo block 10.000 lần, seed 73021,
   CI 95%, Holm cho nhiều so sánh. Bộ thống kê paired hiện có ở
   `ml-service/analyze_syscall_evaluation_matrix.py`; cần nối input C3 đã
   chấm và cùng trial identity trước khi công bố kết quả.
6. Kernel-to-alert phải đo live và gắn kernel timestamp với alert. Thời gian
   batch/replay không được dùng thay phép đo này. Chỉ kết luận giữ/bỏ syscall
   sau khi có cả kết quả normal và attack; tần suất đơn lẻ chưa đủ.

## Kiểm tra trạng thái

Preflight chỉ đọc `sentinel_pulse/variant_capture_audit.py` kiểm tra cả seal
feature, manifest schema, workload/revision, identity, exact counts, collector
integrity và bốn window liền kề. Không gộp history qua gap, không coi workload
thiếu model thành normal, không tính precision/recall. Audit chạy bằng source
riêng, không ghi đè source collector/coordinator đang hoạt động.

Kết quả đầy đủ: selection 390.195 rows / 333.877 context, holdout
391.044 rows / 334.655 context. Artifact:
`/mnt/sentinel-pulse-archive/syscall-capture-c3-r2/selection-preflight-complete-20261014.json`
và `holdout-preflight-complete-20261014.json`.
Chỉ số context chưa xác minh đầy đủ health/nhãn normal và không thay cho scoring.

Trên `.234`:

```bash
systemctl status pulse-syscall-capture-c3.service --no-pager
journalctl -u pulse-syscall-capture-c3.service -n 30 --no-pager
python3 -m json.tool /mnt/sentinel-pulse-archive/syscall-capture-c3-r2/STATUS.json
python3 -m json.tool /mnt/sentinel-pulse-archive/syscall-capture-c3-r2/TERMINAL.json
```

`waiting_for_existing_soak` nghĩa là chưa đổi traffic/attach probe. Sau đó là
`preparing_traffic`, `waiting_for_target_stability`, `launching`, `collecting`, `between_phases`; terminal
`completed_frequency_collection` chỉ xác nhận phần capture, chưa xác nhận
blind evaluation hay syscall nào nên bỏ. Các phase/attempt được liệt kê trong
`attempts.jsonl`. Xem tiến độ hiện hành tại
[SYSCALL_FEATURE_EXPERIMENT_STATUS.md](SYSCALL_FEATURE_EXPERIMENT_STATUS.md).
