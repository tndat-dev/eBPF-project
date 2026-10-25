# Biên nhận 25/10: lượt `pulse-peer-discount-confirm` (chép về repo 25/10)

Lượt xác nhận chính sách `policy-k2of2-a5-peer30` (chiết khấu theo replica; protocol `peer-discount-confirmation-v1` + bổ sung 1), 24/10 10:55 → 25/10 11:06. Nguồn: NFS (`A=/mnt/sentinel-pulse-archive/pulse-peer-discount-confirm`). Code của giai đoạn campaign là snapshot `runtime-60093dd-20261024/source` (`scripts/after_stable_confirm.sh`, `RUN=$A`, `LIVE_RULE=le3s`).

| File | Kết quả cho | Script / lệnh | Bản gốc trên cụm |
|---|---|---|---|
| `pulse-peer-discount-confirm/confirm-campaign.json` | Pulse 5.27: kỳ vọng đăng ký trước, theo tốc độ và kịch bản. **Xác nhận** ở mức ≤ 3 s | `scripts/analysis/confirm_campaign.py --campaign $A/pulse-development-matrix` | `$A/analysis/` |
| `pulse-peer-discount-confirm/attack-vs-benign.json`, `campaign-RESULTS.json`, `campaign-trials.json` | Tỉ lệ dương theo kịch bản; kết quả từng trial; tốc độ và kịch bản của 524 trial | `attack_vs_benign.py`; coordinator; trích từ `trials/*/EVALUATION_INPUT.json` | `$A/analysis/`, `$A/pulse-development-matrix/` |
| `pulse-peer-discount-confirm/rca-*.json` | RCA 5.16: coverage, xếp hạng, độ trễ, flow, bộ đếm subscriber | như `results-20261023` | `$A/analysis/` |
| `pulse-peer-discount-confirm/delivery-latency-campaign.json` | RCA 5.14 / Pulse 5.27: kernel → người nhận theo đường cảnh báo (`--since` = lúc bridge khởi động) | `scripts/analysis/alert_delivery_latency.py` (`97412a2`, bỏ qua trial lỗi hạ tầng) | `$A/alert-bridge/` |
| `alert-bridge/episodes.jsonl.gz`, `deliveries.jsonl.gz`, `pushes.jsonl.gz`, `issues.jsonl`, `STATUS.json`, `START.json` | Đường cảnh báo vận hành của cả lượt | `python3 -m sentinel_pulse.ops.alert_bridge` (`60093dd`); gzip mtime 0; `START.json` bỏ đường dẫn credential | `$A/alert-bridge/` |

| `pulse-peer-discount-confirm/burden-blind-test.json` | Pulse 5.27: gánh cảnh báo live và của các luật tính lại trên cùng bảng cửa sổ, kiểm cài đặt (`--live-rule le3s`) | `scripts/pulse_stable_confirm_analysis.sh` `STAGE=final` chạy lại bằng `0a173f8` (unit `final-peer-discount-confirm-rerun`, 25/10 11:52–12:46): `window_table` rồi `burden_blind_test.py` | `$A/analysis/`; bảng cửa sổ `/var/tmp/burden-levers/table-pulse-peer-discount-confirm.npz` trên `.234` |
| `pulse-peer-discount-confirm/rca-suspect-reasons.json`, `alarm-taxonomy.json`, `cadence-gaps.json`, `rca-status-final.json` | RCA 5.16, Pulse 5.27 (cùng lần chạy lại) | như trên | `$A/analysis/` |
| `pulse-peer-discount-confirm/replicas-{aims-kafka-dual-role,aims-postgres-cnpg,inventory-service}.json` | Pulse 5.27: so sánh replica ngoài khoảng campaign | `scripts/analysis/replica_compare.py --exclude <attack_not_before − 60>,<trial cuối + 20>` | `$A/analysis/` |

Lần final đầu (snapshot `60093dd`) dùng nhầm bảng cửa sổ của lượt trước vì tên bảng gắn cứng (sửa ở `0a173f8`); các file trên là của lần chạy lại.

## So sánh không có / có rule (RULE_INTEGRATION_STATUS R6, 25/10)

Protocol `rule-integration-v1` + bổ sung 1, 2. Driver `scripts/rule_integration_r6.sh` chạy trên `.234` bằng root (case RCA thuộc root). Mã nguồn của mỗi lần chạy là `git archive <sha>` của commit ghi trong bảng (bản chụp tạm trên `.234` đã xóa 25/10 sau khi chạy xong).

| File | Kết quả cho | Script / lệnh | Bản gốc trên cụm |
|---|---|---|---|
| `rule-integration/falco-baseline.json` | Falco từng trial và event normal, từ hết khoảng selection tới hết capture | `scripts/analysis/falco_baseline.py` (`be481a5`, unit `rule-integration-r6`, 13:09) | `$A/analysis/rule-integration/`; log Falco ở `$A/falco-logs/` |
| `rule-integration/tripwire-a1.json.gz` | Tripwire A1: tham chiếu = khoảng selection, tập exec E, kết quả từng trial, cửa sổ cảnh báo trên normal (gzip mtime 0) | `scripts/analysis/novel_syscalls.py --normal-span` (`be481a5`, 13:10–13:30) | như trên |
| `rule-integration/rule-comparison.json` | 5 nhánh A, B1, B2, B3, B_all; từng rule đứng riêng; hiệu so với A có CI | `scripts/analysis/rule_comparison.py` (`ae9af77`, unit `rule-integration-r6b`, 15:57–16:02) | như trên; bảng cửa sổ `/var/tmp/burden-levers/table-pulse-peer-discount-confirm.npz` |
| `rule-integration-secondary/{falco-baseline,tripwire-a1}.json.gz`, `rule-comparison.json` | Dữ liệu phụ của bổ sung 2: `pulse-stable-confirm`, nhánh A = luật ≤ 3 s tính lại (chỉ báo cáo) | `RUN=/mnt/sentinel-pulse-archive/pulse-stable-confirm ML_RULE=le3s ML_RESULTS=…/pulse-stable-refreshed/analysis/burden-levers.json scripts/rule_integration_r6.sh` (`43cc1fc`, 16:06–17:02); gzip mtime 0 | `/mnt/sentinel-pulse-archive/pulse-stable-confirm/analysis/rule-integration/` |
