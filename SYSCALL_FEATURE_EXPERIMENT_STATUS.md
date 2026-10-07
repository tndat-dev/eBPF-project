# Trạng thái thực nghiệm chọn kênh syscall

Cập nhật: 07/10/2026, 10:08:14 ICT. Trạng thái: **đang chạy ngầm trên host**, chưa hoàn thành. Đây là thực nghiệm exploratory normal-only, không phải xác nhận blind recall.

## Phạm vi đã triển khai

Module [syscall_feature_experiment.py](sentinel_pulse/syscall_feature_experiment.py) chạy từ checkout sạch, đóng băng commit `a17222adae6a570e5173dbaedff224eea4dbc719`. Kiểm tra hash model manifest, normal training dataset, training contract, analysis và context archive trước khi fit.

Mỗi workload có 32 biến thể: full, bỏ lần lượt bốn kênh tường minh của từng syscall trong 29 syscall, bỏ toàn bộ kênh tường minh, và giữ top-16 theo phần training cộng whitelist nhạy cảm. Mask áp dụng tại cả bốn vị trí temporal. Hash bins/aggregate vẫn giữ, nên đây không phải loại toàn bộ thông tin của syscall đó.

19 workload có holdout × 32 biến thể = **608 fit dự kiến**. Holdout thiếu notification/payment; không tuyên bố phủ 21/21. Top-16 dùng proxy `expm1(log_count)` từ float32 trên training prefix, không phải histogram full-ID exact mới. Calibration/holdout không tham gia chọn top-16.

Reference full cũng được train lại trên host: Python 3.12.3, scikit-learn 1.9.1, NumPy 2.5.3, joblib 1.6.0. Software khác môi trường train reference original; không gọi số đo host là tái lập bit-for-bit model production.

## Tiến độ đã đọc trực tiếp

`STATUS.json` lúc 10:08:14 ICT: **4/608 fit**, `errors=[]`, state `fitting`. Đã có kết quả full và các lần mask đầu tiên của frontend. Không suy chất lượng cả campaign từ vài fit đầu.

| Thành phần | Giá trị |
|---|---|
| Unit trên host | `pulse-syscall-feature-c1-20261007.service` |
| Thời điểm START | 07/10/2026 10:06:37 ICT |
| Giới hạn tài nguyên | CPU quota 150%, RAM tối đa 4 GiB, không swap, nice 15 |
| Input | `/home/tndat/.cache/sentinel-pulse-experiments/inputs-20261007.xBLUx8` |
| Checkout source frozen | `/home/tndat/.cache/sentinel-pulse-experiments/source-a17222a` |
| Output | `/home/tndat/.cache/sentinel-pulse-experiments/runs/explicit-c1-20261007` |
| START SHA-256 | `f52d89a16e6bc3ae400eb15ef9164f20aa616f371fa00379dccb2a8d74e285ae` |

Output gồm START, STATUS, RESULTS, prediction archives có checksum và TERMINAL khi kết thúc. Raw dataset/archive không đưa vào Git. Job chạy độc lập với phiên SSH/Codex; không restart unit khi output đã tồn tại. Thời lượng tổng chưa xác minh vì chưa chạy qua các workload lớn.

```bash
systemctl --user status pulse-syscall-feature-c1-20261007.service --no-pager
journalctl --user -u pulse-syscall-feature-c1-20261007.service -n 20 --no-pager
cat /home/tndat/.cache/sentinel-pulse-experiments/runs/explicit-c1-20261007/STATUS.json
```

## Giới hạn kết luận và bảo vệ soak

- Holdout normal độc lập với training nhưng đã được xem trong phân tích trước: kết quả **exploratory**, cần tập đánh giá mới để xác nhận lựa chọn.
- Raw model anomaly rate không phải policy alert FPR. TP/FP/TN/FN, precision, attack recall và kernel-to-alert giữ `null` khi chưa có ground truth/phép đo tương ứng. Inference timing trên host có quota không phải latency production.
- Không attach collector mới, inject attack, deploy subset hoặc tune model/policy đang soak. Campaign production được kiểm tra SSH vẫn `active/running`, PID `528252`, NRestarts `1`; START SHA giữ `10457f3f7f3823293258bf9fc8fcd1c14907cc29db68c232aca935f1a1be186f`.
- Vòng full-ID histogram/cross-OS chưa chạy; kế hoạch cấp VM trong [SYSCALL_EXPERIMENT_VM_PLAN.md](SYSCALL_EXPERIMENT_VM_PLAN.md). Giữ nguyên scope Linux native x86_64 hiện tại đến khi kiểm chứng nền tảng khác.
