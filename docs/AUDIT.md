# Rà soát số liệu: báo cáo so với biên nhận và tài liệu (25/10/2026)

Mục đích: bảo đảm không có con số nào trong phần tóm tắt và kết quả chính là bịa đặt hay chép sai. Có hai loại số, kiểm bằng hai script trong `scripts/audit/`.

## 1. Số của đồ án: tính lại từ biên nhận

`scripts/audit/headline_numbers.py` tính lại từng số chủ chốt từ biên nhận đã commit trong `validation-evidence/`, rồi kiểm nguyên câu chứa số đó có trong báo cáo, ở đúng độ chính xác báo cáo in ra. Script chạy trong bộ test (`tests/test_headline_numbers.py`), nên mỗi lần sửa một số trong báo cáo mà không khớp biên nhận thì test hỏng. Một test khác cố tình sửa sai một số trong báo cáo và yêu cầu kiểm toán phải bắt được.

```bash
python3 scripts/audit/headline_numbers.py --markdown /tmp/AUDIT-table.md   # bảng như mục dưới
```

**Kết quả 25/10:** 31/31 câu khớp biên nhận. Hai số trước đây chỉ có trong báo cáo mà không có trong file biên nhận nào (push tới người nhận ở tập chính: 309/315 trial, p95 3,17 s) nay được tính lại trực tiếp từ log bridge và kết quả campaign trong repo; kết quả khớp.

| Mã | Báo cáo | Câu được kiểm (tính lại từ biên nhận) | Biên nhận | Khớp |
|---|---|---|---|---|
| `final-recall` | SENTINEL_PULSE_STATUS.md | ¦ Recall ¦ ≥ 95% ¦ **98,7%** (306/310) [96,7; 99,5] ¦ | `results-20261025/pulse-peer-discount-confirm/confirm-campaign.json` | có |
| `final-precision` | SENTINEL_PULSE_STATUS.md | ¦ Precision ¦ ≥ 95% ¦ **98,7%** (306/310) | `results-20261025/pulse-peer-discount-confirm/confirm-campaign.json` | có |
| `final-control` | SENTINEL_PULSE_STATUS.md | ¦ Control idle dương ¦ ≤ 5% ¦ **1,3%** (4/311) [0,5; 3,3] ¦ | `results-20261025/pulse-peer-discount-confirm/confirm-campaign.json` | có |
| `final-p95` | SENTINEL_PULSE_STATUS.md | **2,88 s** (mức chấp nhận) | `results-20261025/pulse-peer-discount-confirm/confirm-campaign.json` | có |
| `final-benign` | SENTINEL_PULSE_STATUS.md | ¦ Binary vô hại bị gắn cờ ¦ (báo kèm) ¦ 86,1% (266/309) ¦ | `results-20261025/pulse-peer-discount-confirm/confirm-campaign.json` | có |
| `final-slow` | SENTINEL_PULSE_STATUS.md | Recall 80,8% (84/104) ở 1/s và 95,2% (99/104) ở 3/s | `results-20261025/pulse-peer-discount-confirm/confirm-campaign.json` | có |
| `final-burden` | SENTINEL_PULSE_STATUS.md | **1,69 đợt/replica-giờ** [0,52; 3,85] | `results-20261025/pulse-peer-discount-confirm/burden-blind-test.json` | có |
| `final-burden-ratio` | SENTINEL_PULSE_STATUS.md | bằng 0,37 lần CUSUM `keep` và 0,28 lần stable trước | `results-20261025/pulse-peer-discount-confirm/burden-blind-test.json` | có |
| `final-agreement` | SENTINEL_PULSE_STATUS.md | 99,9999% cửa sổ (14 cửa sổ chỉ live có, 0 theo chiều ngược lại) | `results-20261025/pulse-peer-discount-confirm/burden-blind-test.json` | có |
| `final-push` | SENTINEL_PULSE_STATUS.md | tập chính 309/315 trial, p50 1,03 s, p95 3,17 s; mọi tốc độ 493/524, p95 3,91 s | `results-20261025/alert-bridge/*.jsonl.gz + campaign-RESULTS.json (join of alert_delivery_latency.py)` | có |
| `final-pull` | SENTINEL_PULSE_STATUS.md | pull nhanh p50 6,4 s; pull mặc định chỉ tới người nhận ở 130/524 trial (p50 61 s) | `results-20261025/pulse-peer-discount-confirm/delivery-latency-campaign.json` | có |
| `r6-b2-summary` | SENTINEL_PULSE_STATUS.md | tripwire thêm 2,1 điểm recall ở mọi tốc độ (94,5% → 96,6%), p95 nhanh hơn 0,47 s, gánh chỉ +0,066 đợt/replica-giờ | `results-20261025/rule-integration/rule-comparison.json` | có |
| `r6-row-A` | RULE_INTEGRATION_STATUS.md | ¦ A — ML ¦ 98,7% (94,5%) ¦ 1,3% (4) ¦ 85,7% ¦ 98,7% ¦ 0,86 s ¦ 2,91 s (3,72 s) ¦ 1,42 ¦ | `results-20261025/rule-integration/rule-comparison.json` | có |
| `r6-row-B1` | RULE_INTEGRATION_STATUS.md | ¦ B1 — ML + Falco ¦ 98,7% (95,2%) ¦ 2,9% (9) ¦ 86,0% ¦ 97,2% ¦ 0,71 s ¦ 2,48 s (3,20 s) ¦ 2,54 ¦ | `results-20261025/rule-integration/rule-comparison.json` | có |
| `r6-row-B2` | RULE_INTEGRATION_STATUS.md | ¦ B2 — ML + tripwire ¦ 98,7% (96,6%) ¦ 1,6% (5) ¦ 85,7% ¦ 98,4% ¦ 0,68 s ¦ 2,44 s (2,61 s) ¦ 1,48 ¦ | `results-20261025/rule-integration/rule-comparison.json` | có |
| `r6-row-B3` | RULE_INTEGRATION_STATUS.md | ¦ B3 — ML rồi triage probe ¦ 98,7% (94,5%) ¦ 1,3% (4) ¦ 85,7% ¦ 98,7% ¦ 3,23 s ¦ 5,90 s (6,52 s) ¦ 1,09 ¦ | `results-20261025/rule-integration/rule-comparison.json` | có |
| `r6-row-B_all` | RULE_INTEGRATION_STATUS.md | ¦ B_all ¦ 98,7% (96,6%) ¦ 3,2% (10) ¦ 86,0% ¦ 96,9% ¦ 0,54 s ¦ 4,82 s (4,88 s) ¦ 2,28 ¦ | `results-20261025/rule-integration/rule-comparison.json` | có |
| `r6-b2-burden-ci` | RULE_INTEGRATION_STATUS.md | **+0,066 [+0,020; +0,133]** | `results-20261025/rule-integration/rule-comparison.json` | có |
| `r6-tripwire-alone` | RULE_INTEGRATION_STATUS.md | ¦ Tripwire A1 ¦ 60,0% (59,9%) ¦ | `results-20261025/rule-integration/rule-comparison.json` | có |
| `r6-tripwire-burden` | RULE_INTEGRATION_STATUS.md | ¦ 0,3% ¦ 0,6% ¦ 99,5% ¦ **0,099** ¦ | `results-20261025/rule-integration/rule-comparison.json` | có |
| `r6-falco-rule` | RULE_INTEGRATION_STATUS.md | **Falco:** 839/845 đợt normal | `results-20261025/rule-integration/falco-baseline.json` | có |
| `r6-secondary-b2` | RULE_INTEGRATION_STATUS.md | **+0,045 [+0,004; +0,113]** | `results-20261025/rule-integration-secondary/rule-comparison.json` | có |
| `confirm-fail` | SENTINEL_PULSE_STATUS.md | **không đạt** (precision 94,6%, control 5,8%, 18/309) | `results-20261023/pulse-stable-confirm/confirm-campaign.json` | có |
| `blind-522` | TODO.md | gánh 1,74, control 2,9%, precision 97,2%, p95 2,68 s | `results-20261023/pulse-stable-confirm/burden-blind-test.json` | có |
| `benign-range` | SENTINEL_PULSE_STATUS.md | bị gắn cờ 80,7–95,1% qua 5 lượt live (86,1% ở lượt cuối) | `docs/figures/vi/live-runs-table.md (generated from the campaign receipts) + confirm-campaign.json` | có |
| `baselines-fresh` | SENTINEL_PULSE_STATUS.md | AE và `tree_ae` tăng recall 4,9 điểm nhưng tách binary vô hại kém khoảng 26 điểm (CI dưới 0) | `results-20261021/baselines/fresh/FRESH-ADOPTION.json` | có |
| `overhead` | SENTINEL_PULSE_STATUS.md | thêm khoảng 250–450 ns mỗi syscall khi container được theo dõi, 80–230 ns khi không | `results-20261021/overhead/OVERHEAD-AB.json (added ns per op / syscalls per op)` | có |
| `label-review` | SENTINEL_PULSE_STATUS.md | **Review nhãn (5.20):** 4.766 cảnh báo normal, không case nào có dấu hiệu độc hại | `results-20261021/pulse-stable-candidate/label-review.json` | có |
| `label-review-shares` | SENTINEL_PULSE_STATUS.md | ¦ benign_probe ¦ 2.573 ¦ 54,0% (52,6–55,4) | `results-20261021/pulse-stable-candidate/label-review.json` | có |
| `rca-final` | RCA_RUNTIME_STATUS.md | Attack có case riêng 459/524 (87,6%); top-1 99,8%, top-3 100%; preview → case p95 2,59 s (case attack); 575 case normal | `results-20261025/pulse-peer-discount-confirm/rca-coverage.json, rca-ranking-reranked.json, alarm-taxonomy.json` | có |
| `rca-confirm` | RCA_RUNTIME_STATUS.md | `pulse-stable-confirm` 86,9% / 99,8% / 2,50 s (5.15) | `results-20261023/pulse-stable-confirm/rca-coverage.json, rca-ranking-reranked.json` | có |

Ngoài 31 câu trên, đã đọc lại bằng tay trong lúc rà soát: review nhãn (cận dưới 99,92% = 1 − cận trên Wilson của 0/4.766), overhead tính trên mỗi syscall (mmap+munmap và open+close là 2 syscall mỗi phép đo), RCA (2,50 s là p95 của case attack, 2,65 s là của mọi case; hai định nghĩa đều ghi trong báo cáo).

## 2. Số của tài liệu: so với PDF của bài được trích

`scripts/audit/literature_numbers.py` lấy mọi dòng của `references/KNOWLEDGE_SYNTHESIS.md` chỉ nhắc một bài (bỏ dòng phân tích riêng `[ĐA]`), rồi tìm từng con số của dòng đó trong văn bản PDF của chính bài ấy. Cần PDF (ngoài git) và `pdftotext`.

**Kết quả 25/10:** 87 số được kiểm, 86 có trong PDF. Số không thấy là "10.000 lần" ở dòng Efron 1993: đó là số lần bootstrap của đồ án, không phải số của bài.

**Kiểm tay thêm các số ở bảng công trình liên quan (RESEARCH_IDEAS mục 3):**
- REPLICAWATCHER: precision 91,08%, recall 98,35% trên 13 kịch bản; CDL recall dưới 50% ở nhiều kịch bản; CHIDS trên 96% recall và 97% precision; 1.000 trace normal + 100 trace attack mỗi kịch bản, mỗi trace 30 s.
- CHIDS: 11.700 trace normal và 1.980 attack; dùng LID-DS và CB-DS.
- FedMon: precision 94%, recall 91%, F1 0,92.
- KubAnomaly: accuracy tới 96% (theo tóm tắt; bản PDF là bản dựng lại).
- eBPF-PATROL: overhead < 2,5%.
- BoSC: đăng ở STM 2015, LNCS 9331, tr. 123–135 (theo trang arXiv 1611.03056); file trong `references/` là bản arXiv 2016.

## 3. Giới hạn của rà soát

- Chỉ kiểm các số chủ chốt (tóm tắt, kết quả cuối, R6, baseline, overhead, review nhãn, RCA). Các bảng chi tiết trong mục 5.x của báo cáo do script sinh biên nhận in ra, chưa có kiểm toán tự động cho từng ô.
- 10 tài liệu chỉ có bản dựng lại (không phải PDF gốc), ví dụ Forrest 1996, KubAnomaly, CDL. Số lấy từ các bài này chỉ dựa trên tóm tắt; trước khi trích trong paper cần lấy bản gốc (danh sách trong `references/README.md`).
- Nhãn attack/normal là nhãn kỳ vọng của campaign; review nhãn (Pulse 5.20) do chính Claude làm, không độc lập.
