# Biên nhận 23/10: lượt xác nhận `pulse-stable-confirm`, giai đoạn campaign (chép về repo 23/10 13:30)

Campaign 525 cặp của lượt xác nhận kết thúc 23/10 12:29 (05:29 UTC). Các file dưới đây là output của giai đoạn campaign, chép nguyên từ NFS (`A=/mnt/sentinel-pulse-archive/pulse-stable-confirm`) hoặc đĩa local của `.234`. Capture của lượt chạy tới khoảng 24/10 01:20; output giai đoạn final (gánh cảnh báo, test blind 5.22, so sánh có/không rule) sẽ thêm vào đây sau lượt.

Code chạy giai đoạn campaign là snapshot `runtime-1e2ae7f-20261022/source` (`scripts/after_stable_confirm.sh` → `scripts/pulse_stable_confirm_analysis.sh`, `STAGE=campaign`). Các file ghi "sinh 13:05" chạy từ checkout `/home/dat/eBPF-project` ở commit ghi trong cột script.

| File (`pulse-stable-confirm/`) | Kết quả cho | Script / lệnh | Bản gốc trên cụm |
|---|---|---|---|
| `confirm-campaign.json` | Pulse 5.25: kỳ vọng đăng ký trước (`stable-confirmation-v1` + bổ sung 1), theo tốc độ và kịch bản. **Không đạt** | `scripts/analysis/confirm_campaign.py --campaign $A/pulse-development-matrix` | `$A/analysis/confirm-campaign.json` |
| `confirm-campaign-by-container.json` | Như trên, thêm control dương theo container (sinh 13:05); phần chung trùng từng số với `confirm-campaign.json` | `confirm_campaign.py` ở commit `67b6a9e` | `$A/analysis/` |
| `confirm-campaign-posthoc-without-cnpg2.json` | Pulse 5.25: độ nhạy **post-hoc**, bỏ container postgres worker1 (replica `cnpg-2` hỏng, 5.24); không thay kết luận | `confirm_campaign.py --exclude-container production/aims-postgres-cnpg:postgres@k8s-worker1.local` (`67b6a9e`) | `$A/analysis/` |
| `attack-vs-benign.json` | Tỉ lệ dương của attack, binary vô hại, control theo kịch bản | `scripts/analysis/attack_vs_benign.py` | `$A/analysis/` |
| `campaign-trials.json` | Tốc độ attack và kịch bản của 525 trial (để lọc tập chính không cần cụm, ví dụ trong `scripts/figures/thesis_figures.py`) | trích từ `trials/*/EVALUATION_INPUT.json` (`attack.rate_per_second`, `attack.scenario`), 13:40 | `$A/pulse-development-matrix/trials/` |
| `campaign-RESULTS.json` | Kết quả từng trial của coordinator (1.575 dòng: attack, control, binary vô hại) | coordinator campaign (`pulse-matched-campaign-pulse-stable-confirm`) | `$A/pulse-development-matrix/RESULTS.json` |
| `rca-coverage.json`, `rca-flow-coverage.json`, `rca-latency.json`, `rca-ranking-stored.json`, `rca-ranking-reranked.json`, `rca-status-after-campaign.json` | RCA 5.15: coverage, flow, độ trễ theo chặng, xếp hạng nghi phạm, bộ đếm của subscriber | `scripts/analysis/rca_coverage.py`, `rca_flow_coverage.py`, `rca_latency.py`, `python3 -m sentinel_pulse.rca.evaluate_ranking` | `$A/analysis/` (case ở `/var/lib/sentinel-pulse-rca/rca-pulse-stable-confirm/` trên `.234`) |
| `delivery-latency-campaign.json` | RCA 5.14: kernel → người nhận theo từng trial attack, theo đường push / pull (sinh 13:05) | `scripts/analysis/alert_delivery_latency.py --since 1792702402` | `/var/lib/sentinel-pulse-alert-bridge/pulse-stable-confirm/` trên `.234` |

SHA-256 của hai file chính, kiểm khi chép (khớp bản trên NFS):
- `confirm-campaign.json`: `7ff52b5ee76bd80c8db78bd7b3161b4645284d04dbe0709f71d2429e6cf3b617`
- `campaign-RESULTS.json`: `1fedebcec4805c85b4d4cd6c95848039c42c78710df82477bff7d9edf46df2d6`
