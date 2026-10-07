# Snapshot soak hiện hành ngày 07/10/2026

`inspection.json` được lấy bằng SSH từ snapshot trên control plane `.234`,
`checked_at_unix=1791340883.7705333`, tương ứng khoảng 09:41 ICT ngày 07/10.
Run gốc `pulse-observation-c1-20261006` giữ nguyên START/model/policy và PID.
Đây chưa phải terminal/final report. Snapshot cũ ngày 06/10 vẫn giữ nguyên.

```bash
python3 -m sentinel_pulse.review_observation \
  --inspection validation-evidence/soak-inspection-20261007/inspection.json
```

Wall time đã qua 24 giờ, nhưng exposure hợp lệ thấp nhất mới 20,88 giờ.
Campaign còn chạy, không tự gán phần thời gian thiếu thành normal/TN.
Alert Redis vẫn giữ để adjudication. Retry audit s0048 đang chờ tại snapshot;
không gọi lỗi của một đợt con là campaign fail.
