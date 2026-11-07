# Rà soát số liệu: báo cáo so với biên nhận và tài liệu (25/10/2026)

Mục đích: bảo đảm không có con số nào trong phần tóm tắt và kết quả chính là bịa đặt hay chép sai. Có hai loại số, kiểm bằng hai script trong `scripts/audit/`.

## 1. Số của đồ án: tính lại từ biên nhận

`scripts/audit/headline_numbers.py` tính lại từng số chủ chốt từ biên nhận đã commit trong `validation-evidence/`, rồi kiểm nguyên câu chứa số đó có trong báo cáo, ở đúng độ chính xác báo cáo in ra. Script chạy trong bộ test (`tests/test_headline_numbers.py`), nên mỗi lần sửa một số trong báo cáo mà không khớp biên nhận thì test hỏng. Một test khác cố tình sửa sai một số trong báo cáo và yêu cầu kiểm toán phải bắt được.

```bash
python3 scripts/audit/headline_numbers.py --markdown /tmp/AUDIT-table.md   # bảng như mục dưới
```

**Kết quả 29/10:** 54/54 câu khớp biên nhận (thêm G7, LID-DS 2021, luật phá hoà RCA, các dòng tương ứng trong luận văn). Lần thêm này bắt được một lỗi làm tròn hai lần ở bảng G7: Δ p95 của `/`, `/api/health/`, `/api/products/` là 5,845%, 3,145%, 8,145% nhưng báo cáo và luận văn ghi +5,9 / +3,2 / +8,2%; đã sửa thành +5,8 / +3,1 / +8,1% (kết luận không đổi). **Kết quả 25/10:** 31/31 câu khớp biên nhận. Hai số trước đây chỉ có trong báo cáo mà không có trong file biên nhận nào (push tới người nhận ở tập chính: 309/315 trial, p95 3,17 s) nay được tính lại trực tiếp từ log bridge và kết quả campaign trong repo; kết quả khớp.

**Cập nhật 07/11:** bốn file trạng thái (`SENTINEL_PULSE_STATUS.md`, `RULE_INTEGRATION_STATUS.md`, `RCA_RUNTIME_STATUS.md`, `SYSCALL_FEATURE_EXPERIMENT_STATUS.md`) đã xoá theo yêu cầu của chủ đồ án; các câu kiểm trong đó được bỏ (danh sách `RETIRED` trong script). Các câu của bản LaTeX và `TODO.md` vẫn được kiểm, cộng 5 câu mới cho bảng hệ thống cuối chạy live trong bản LaTeX. Bảng dưới là kết quả chạy lại.

| Mã | Báo cáo | Câu được kiểm (tính lại từ biên nhận) | Biên nhận | Khớp |
|---|---|---|---|---|
| `blind-522` | TODO.md | gánh 1,74, control 2,9%, precision 97,2%, p95 2,68 s | `results-20261023/pulse-stable-confirm/burden-blind-test.json` | có |
| `g7-thesis-/` | thesis/chapters/evaluation.tex |  & 11,5 / 12,1 & +5,8\% [−1,4; +14,5] & +0,5\% [−0,8; +3,2] & 0,04 \\ | `results-20261029/app-overhead/APP-OVERHEAD.json` | có |
| `g7-thesis-/api/health/` | thesis/chapters/evaluation.tex |  & 25,1 / 24,3 & +3,1\% [−8,1; +21,2] & +2,0\% [+0,2; +4,4] & 0,14 \\ | `results-20261029/app-overhead/APP-OVERHEAD.json` | có |
| `g7-thesis-/api/products/` | thesis/chapters/evaluation.tex |  & 306,4 / 318,2 & +8,1\% [+0,7; +18,3] & +3,0\% [+1,2; +4,3] & 5,9 \\ | `results-20261029/app-overhead/APP-OVERHEAD.json` | có |
| `g7-thesis-/api/products/?page=1` | thesis/chapters/evaluation.tex |  & 309,3 / 320,4 & +5,8\% [+1,4; +17,9] & +2,6\% [+0,4; +5,2] & 5,3 \\ | `results-20261029/app-overhead/APP-OVERHEAD.json` | có |
| `lidds-thesis-ml` | thesis/chapters/evaluation.tex | ML & 63,6\% (1154/1815) [61,3; 65,8] & 2,9\% (333/11341) [2,6; 3,3] & 2,46 & 1,33 / 4,13 \\ | `results-20261029/lidds/lidds-evaluation.json` | có |
| `lidds-thesis-tripwire` | thesis/chapters/evaluation.tex | Tripwire & 63,5\% (1153/1815) [61,3; 65,7] & 0,1\% (7/11341) [0,0; 0,1] & 0,05 & 0,79 / 2,94 \\ | `results-20261029/lidds/lidds-evaluation.json` | có |
| `lidds-thesis-system` | thesis/chapters/evaluation.tex | Hệ thống (ML hoặc tripwire) & 77,3\% (1403/1815) [75,3; 79,2] & 3,0\% (336/11341) [2,7; 3,3] & 2,48 & 0,77 / 2,71 \\ | `results-20261029/lidds/lidds-evaluation.json` | có |
| `lidds-macro-thesis` | thesis/chapters/evaluation.tex | Tính cùng cách (trung bình của 15 kịch bản), hệ thống của luận văn đạt 0,77. | `results-20261029/lidds/lidds-evaluation.json (mean over scenarios)` | có |
| `lidds-v2-thesis-system` | thesis/chapters/evaluation.tex | Hệ thống v1 (ML hoặc tripwire) & 77,4\% & 2,72\% \\ | `results-20261031/lidds-v2/lidds-evaluation-v2.json.gz` | có |
| `lidds-v2-thesis-path` | thesis/chapters/evaluation.tex | \texttt{path} & 69,9\% & 1,47\% \\ | `results-20261031/lidds-v2/lidds-evaluation-v2.json.gz` | có |
| `lidds-v2-thesis-errno` | thesis/chapters/evaluation.tex | \texttt{errno} & 68,8\% & 1,45\% \\ | `results-20261031/lidds-v2/lidds-evaluation-v2.json.gz` | có |
| `lidds-v2-thesis-bytes` | thesis/chapters/evaluation.tex | \texttt{bytes} & 80,0\% & 3,71\% \\ | `results-20261031/lidds-v2/lidds-evaluation-v2.json.gz` | có |
| `lidds-v2-thesis-ngram` | thesis/chapters/evaluation.tex | \texttt{ngram} & 87,5\% & 1,04\% \\ | `results-20261031/lidds-v2/lidds-evaluation-v2.json.gz` | có |
| `lidds-v2-thesis-step3` | thesis/chapters/evaluation.tex | OR mọi nhánh (hệ thống v2) & 97,8\% & 9,70\% \\ | `results-20261031/lidds-v2/lidds-evaluation-v2.json.gz` | có |
| `cbds-thesis-system` | thesis/chapters/evaluation.tex | \textbf{Hệ thống v1 (ML hoặc tripwire)} & \textbf{100\%} (891/891) & \textbf{1,5\%} (21) \\ | `results-20261029/cbds/cbds-confirmation.json` | có |
| `cbds-thesis-tripwire` | thesis/chapters/evaluation.tex | Tripwire & 100\% (891/891) & 0\% (0) \\ | `results-20261029/cbds/cbds-confirmation.json` | có |
| `cbds-thesis-ml` | thesis/chapters/evaluation.tex | ML & 99,0\% (882/891) & 1,5\% (21) \\ | `results-20261029/cbds/cbds-confirmation.json` | có |
| `cbds-thesis-step3` | thesis/chapters/evaluation.tex | OR mọi nhánh (v2) & 100\% (891/891) & 5,5\% (77) \\ | `results-20261029/cbds/cbds-confirmation.json` | có |
| `ml-v2-thesis-baseline` | thesis/chapters/evaluation.tex | ML ban đầu & 63,89\% (812) & 2,71\% (215) & 79,1\% & 5,29 s \\ | `results-20261102/lidds-ml-v1/lidds-ml-v1.json.gz` | có |
| `ml-v2-thesis-v1` | thesis/chapters/evaluation.tex | \texttt{lidds-\allowbreak{}ml-\allowbreak{}v1} & 65,22\% (829) & 2,05\% (163) & 83,6\% & 4,04 s \\ | `results-20261102/lidds-ml-v1/lidds-ml-v1.json.gz` | có |
| `ml-v2-thesis-v2` | thesis/chapters/evaluation.tex | \texttt{lidds-\allowbreak{}ml-\allowbreak{}v2} & 95,99\% (1.220) & 0,57\% (45) & 96,4\% & 2,32 s \\ | `results-20261105/lidds-ml-v2/lidds-ml-v2.json` | có |
| `ml-v3-thesis-v3` | thesis/chapters/evaluation.tex | \textbf{\texttt{lidds-\allowbreak{}ml-\allowbreak{}v3}} & \textbf{97,32\% (1.237)} & \textbf{0,44\% (35)} & \textbf{97,2\%} & \textbf{2,09 s} \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v2-thesis-token` | thesis/chapters/evaluation.tex | Chỉ token, bảng chữ v2 (chỉ báo) & 97,01\% (1.233) & 0,52\% (41) & 96,8\% & 1,47 s \\ | `results-20261105/lidds-ml-v2/lidds-ml-v2.json` | có |
| `ml-v3-thesis-token` | thesis/chapters/evaluation.tex | Chỉ token, bảng chữ v3 (chỉ báo) & 97,40\% (1.238) & 0,63\% (50) & 96,1\% & 1,41 s \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v2-thesis-trees` | thesis/chapters/evaluation.tex | Chỉ cây và support (chỉ báo) & 52,08\% (662) & 0,40\% (32) & 95,4\% & 13,15 s \\ | `results-20261105/lidds-ml-v2/lidds-ml-v2.json` | có |
| `ml-v3-thesis-Bruteforce_CWE-307` | thesis/chapters/evaluation.tex | \texttt{Bruteforce\_CWE-\allowbreak{}307} & 97/97 & 100,0\% & 0/538 & 0,00\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-CVE-2012-2122` | thesis/chapters/evaluation.tex | \texttt{CVE-\allowbreak{}2012-\allowbreak{}2122} & 84/84 & 100,0\% & 2/533 & 0,38\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-CVE-2014-0160` | thesis/chapters/evaluation.tex | \texttt{CVE-\allowbreak{}2014-\allowbreak{}0160} & 84/84 & 100,0\% & 1/531 & 0,19\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-CVE-2017-12635_6` | thesis/chapters/evaluation.tex | \texttt{CVE-\allowbreak{}2017-\allowbreak{}12635\_6} & 83/83 & 100,0\% & 1/527 & 0,19\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-CVE-2017-7529` | thesis/chapters/evaluation.tex | \texttt{CVE-\allowbreak{}2017-\allowbreak{}7529} & 83/83 & 100,0\% & 4/510 & 0,78\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-CVE-2018-3760` | thesis/chapters/evaluation.tex | \texttt{CVE-\allowbreak{}2018-\allowbreak{}3760} & 85/85 & 100,0\% & 0/516 & 0,00\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-CVE-2019-5418` | thesis/chapters/evaluation.tex | \texttt{CVE-\allowbreak{}2019-\allowbreak{}5418} & 83/84 & 98,8\% & 8/532 & 1,50\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-CVE-2020-13942` | thesis/chapters/evaluation.tex | \texttt{CVE-\allowbreak{}2020-\allowbreak{}13942} & 83/83 & 100,0\% & 3/529 & 0,57\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-CVE-2020-23839` | thesis/chapters/evaluation.tex | \texttt{CVE-\allowbreak{}2020-\allowbreak{}23839} & 84/84 & 100,0\% & 4/532 & 0,75\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-CVE-2020-9484` | thesis/chapters/evaluation.tex | \texttt{CVE-\allowbreak{}2020-\allowbreak{}9484} & 84/84 & 100,0\% & 3/531 & 0,56\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-CWE-89-SQL-injection` | thesis/chapters/evaluation.tex | \texttt{CWE-\allowbreak{}89-\allowbreak{}SQL-\allowbreak{}injection} & 84/84 & 100,0\% & 0/532 & 0,00\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-EPS_CWE-434` | thesis/chapters/evaluation.tex | \texttt{EPS\_CWE-\allowbreak{}434} & 85/85 & 100,0\% & 1/531 & 0,19\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-Juice-Shop` | thesis/chapters/evaluation.tex | \texttt{Juice-\allowbreak{}Shop} & 52/85 & 61,2\% & 4/532 & 0,75\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-PHP_CWE-434` | thesis/chapters/evaluation.tex | \texttt{PHP\_CWE-\allowbreak{}434} & 83/83 & 100,0\% & 2/532 & 0,38\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `ml-v3-thesis-ZipSlip` | thesis/chapters/evaluation.tex | \texttt{ZipSlip} & 83/83 & 100,0\% & 2/532 & 0,38\% \\ | `results-20261107/lidds-ml-v3/lidds-ml-v3.json` | có |
| `lidds-v3-thesis` | thesis/chapters/evaluation.tex | \textbf{Ít nhất 2 trong 5 nhánh (chọn trên development)} & \textbf{97,5\%} [96,5; 98,2] & \textbf{1,47\%} [1,23; 1,76] & \textbf{91,4\%} \\ | `results-20261031/lidds-v3-with-cbds.json` | có |
| `lidds-v3-cbds-thesis` | thesis/chapters/evaluation.tex | recall 100\% (891/891), báo nhầm 0,50\% (7/1.410), precision 99,2\% | `results-20261031/lidds-v3-with-cbds.json` | có |
| `final-thesis-recall` | thesis/chapters/evaluation.tex | Recall & ≥ 95\% & 99,4\% (313/315) {[}97,7; 99,8{]} & 99,4\% \\ | `results-20261026/pulse-final-system-confirm/final-system.json` | có |
| `final-thesis-precision` | thesis/chapters/evaluation.tex | Precision & ≥ 95\% & 99,4\% {[}97,7; 99,8{]} & 99,4\% \\ | `results-20261026/pulse-final-system-confirm/final-system.json` | có |
| `final-thesis-control` | thesis/chapters/evaluation.tex | Control dương & ≤ 5\% & 0,6\% (2/314) {[}0,2; 2,3{]} & 0,6\% \\ | `results-20261026/pulse-final-system-confirm/final-system.json` | có |
| `final-thesis-p95` | thesis/chapters/evaluation.tex | & 1,97 s & 2,25 s \\ | `results-20261026/pulse-final-system-confirm/final-system.json` | có |
| `final-thesis-benign` | thesis/chapters/evaluation.tex | Binary vô hại bị gắn cờ & báo kèm & 89,5\% (282/315) & 89,5\% \\ | `results-20261026/pulse-final-system-confirm/final-system.json` | có |

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
