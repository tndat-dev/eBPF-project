# Biên nhận 25/10: lượt `pulse-peer-discount-confirm` (chép về repo 25/10)

Lượt xác nhận chính sách `policy-k2of2-a5-peer30` (chiết khấu theo replica; protocol `peer-discount-confirmation-v1` + bổ sung 1), 24/10 10:55 → 25/10 11:06. Nguồn: NFS (`A=/mnt/sentinel-pulse-archive/pulse-peer-discount-confirm`). Code của giai đoạn campaign là snapshot `runtime-60093dd-20261024/source` (`scripts/after_stable_confirm.sh`, `RUN=$A`, `LIVE_RULE=le3s`).

| File | Kết quả cho | Script / lệnh | Bản gốc trên cụm |
|---|---|---|---|
| `pulse-peer-discount-confirm/confirm-campaign.json` | Pulse 5.27: kỳ vọng đăng ký trước, theo tốc độ và kịch bản. **Xác nhận** ở mức ≤ 3 s | `scripts/analysis/confirm_campaign.py --campaign $A/pulse-development-matrix` | `$A/analysis/` |
| `pulse-peer-discount-confirm/attack-vs-benign.json`, `campaign-RESULTS.json`, `campaign-trials.json` | Tỉ lệ dương theo kịch bản; kết quả từng trial; tốc độ và kịch bản của 524 trial | `attack_vs_benign.py`; coordinator; trích từ `trials/*/EVALUATION_INPUT.json` | `$A/analysis/`, `$A/pulse-development-matrix/` |
| `pulse-peer-discount-confirm/rca-*.json` | RCA 5.16: coverage, xếp hạng, độ trễ, flow, bộ đếm subscriber | như `results-20261023` | `$A/analysis/` |
| `pulse-peer-discount-confirm/delivery-latency-campaign.json` | RCA 5.14 / Pulse 5.27: kernel → người nhận theo đường cảnh báo (`--since` = lúc bridge khởi động) | `scripts/analysis/alert_delivery_latency.py` (`97412a2`, bỏ qua trial lỗi hạ tầng) | `$A/alert-bridge/` |
| `alert-bridge/episodes.jsonl.gz`, `deliveries.jsonl.gz`, `pushes.jsonl.gz`, `issues.jsonl`, `STATUS.json`, `START.json` | Đường cảnh báo vận hành của cả lượt | `python3 -m sentinel_pulse.ops.alert_bridge` (`60093dd`); gzip mtime 0; `START.json` bỏ đường dẫn credential | `$A/alert-bridge/` |

Giai đoạn final (bảng cửa sổ, gánh cảnh báo, test kiểm cài đặt, lý do nghi phạm, phân loại cảnh báo, khoảng hở nhịp chấm) đang chạy lại bằng code đã sửa (`0a173f8`, unit `final-peer-discount-confirm-rerun`); sẽ thêm khi xong.
