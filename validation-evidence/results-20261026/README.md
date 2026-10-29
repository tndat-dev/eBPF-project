# Biên nhận 26/10: lượt `pulse-final-system-confirm` (hệ thống cuối ML + tripwire, chép về repo 29/10)

Protocol `sentinel_pulse/protocol/final-system-confirmation-v1.json` (đăng ký 25/10 18:19, trước khi có dữ liệu). Lượt 25/10 22:05 → 26/10 khoảng 22:15, code `8251f56` (`runtime-8251f56-20261025/source`), ML ghim vào `runtime-60093dd-20261024/source`. Phân tích: `scripts/after_final_system.sh` → `scripts/final_system_analysis.sh` (code `4b18839`; bản chụp đã xóa, code lấy lại bằng `git archive 4b18839`), unit `after-final-system`. Bản gốc: `A=/mnt/sentinel-pulse-archive/pulse-final-system-confirm/analysis/`. File `.gz` nén với mtime 0; nội dung giống hệt bản gốc.

| File | Kết quả cho | Script |
|---|---|---|
| `pulse-final-system-confirm/final-system.json` | Pulse 5.29: nhánh A (ML) và B2 = S (ML + tripwire live), hiệu S − A có CI | `rule_comparison.py --tripwire live-tripwire.json` (không Falco, không triage) |
| `pulse-final-system-confirm/final-system-offline-tripwire.json` | Như trên, với tripwire tính lại offline (cùng kết quả) | `rule_comparison.py --tripwire tripwire-a1-offline.json` |
| `pulse-final-system-confirm/live-tripwire.json.gz` | Tripwire live từng trial và trên normal, độ khớp với offline, độ trễ frame theo worker | `live_tripwire.py --offline` |
| `pulse-final-system-confirm/tripwire-a1-offline.json.gz` | Tripwire A1 tính lại offline (tham chiếu = khoảng selection, tập exec E) | `novel_syscalls.py --normal-span` |
| `pulse-final-system-confirm/frame-lag-previous-run.json.gz` | Độ trễ frame của `pulse-peer-discount-confirm` để so | `live_tripwire.py` trên lượt trước |
| `pulse-final-system-confirm/confirm-campaign.json`, `attack-vs-benign.json`, `campaign-RESULTS.json.gz`, `campaign-trials.json` | ML theo định nghĩa của coordinator, theo tốc độ và kịch bản; kết quả từng trial; tốc độ và kịch bản của 525 trial (`campaign-trials.json` trích từ `trials/*/EVALUATION_INPUT.json` ngày 29/10) | `confirm_campaign.py`, `attack_vs_benign.py` |
| `pulse-final-system-confirm/burden-blind-test.json` | Gánh ML live từ đầu khoảng selection, kiểm cài đặt | `burden_blind_test.py --live-rule le3s` |
| `pulse-final-system-confirm/delivery-latency-campaign.json.gz`, `bridge-status-*.json` | Kernel → người nhận theo đường cảnh báo; bộ đếm bridge (push lỗi, thử lại) | `alert_delivery_latency.py` |
| `pulse-final-system-confirm/rca-*.json`, `alarm-taxonomy.json` | RCA 5.17 (trigger từ Alertmanager) | như các lượt trước |
| `pulse-final-system-confirm/rca-ranking-reranked-recency.json.gz` | RCA 5.19: xếp hạng lại cùng case với luật phá hoà theo thời điểm khởi chạy (development; top-1 100%, 469 case) | `evaluate_ranking.py --tie-break recency` (code `0a50f90`, 29/10) |
| `pulse-final-system-confirm/cadence-gaps.json`, `tetragon-zombies.json` | Khoảng hở nhịp theo worker; zombie sau lượt | `cadence_gaps.py`; đếm trong `final_system_analysis.sh` |

Trạng thái bridge của cả lượt nằm trên NFS `pulse-final-system-confirm/alert-bridge/` (bản local trên `.234` trùng từng byte, đã xóa 29/10).
