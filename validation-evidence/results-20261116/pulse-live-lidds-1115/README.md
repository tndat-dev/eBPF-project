# pulse-live-lidds-1115: 15 CVE thật của LID-DS 2021 trên cụm, model v5 (16/11/2026)

Protocol `sentinel_pulse/protocol/pulse-live-lidds-v1.json` + amendment 1 (generator normal) + **amendment 2**
(thời lượng capture 8 h + live 4 h cho lượt này — đăng ký trước khi chạy). Đóng điểm yếu **W2** (`notes/PAPER_PLAN.md`):
dịch vụ dễ bị khai thác thật, client normal và exploit của chính kịch bản, exploit chạy trong cây process của victim,
chấm bằng đúng model/alphabet/ngưỡng/quyết định của `lidds-ml-v5`. Lineage tag (amendment 2) được ghi.

Lượt này **chạy lại** sau khi phát hiện 5–7 exploit của long-1114 không thực sự chạy (recall 0.68 là artifact công cụ,
không phải giới hạn detector — xem `results-20261115/exploit-verification/`). 15 exploit đã viết lại bằng HTTP trực tiếp
(`scripts/lidds_live/exploits_http/`), verify 15/15 landing trước khi chạy. Cluster-resident: unit `lidds-1115-master`
(.234) + `lidds-1115-worker` (k8s-worker1), phối hợp qua marker NFS. Capture 10:52→18:54 UTC, live →22:56, SCORED 22:58
(15/11). 48 chu kỳ exploit, 47 chu kỳ normal, tokens 2,96 GB.

## Kết quả per-scenario (`lidds-live-score.json`)

| Kịch bản (CVE) | Phát hiện | Báo nhầm | p95 (s) | lineage session | block ngưỡng |
|---|---|---|---|---|---|
| Bruteforce_CWE-307 | 3/3 | 0/3 | 1,28 | 0,00 | 41 |
| CVE-2012-2122 (MySQL bypass) | 3/3 | 0/4 | 1,46 | 0,00 | 44 |
| **CVE-2014-0160 (Heartbleed)** | **0/5** | 0/1 | — | — | 42 |
| CVE-2017-12635_6 (CouchDB) | 1/1 | 1/6 | 4,40 | 0,00 | 44 |
| CVE-2017-7529 (nginx) | 2/2 | 1/5 | 1,35 | 0,00 | 46 |
| CVE-2018-3760 (Rails) | 3/3 | 0/4 | 1,29 | 0,00 | 46 |
| CVE-2019-5418 (Rails) | 5/5 | 0/2 | 1,28 | 0,00 | 44 |
| CVE-2020-13942 (Unomi) | 4/4 | 0/2 | 1,30 | 0,00 | 45 |
| CVE-2020-23839 (GetSimple XSS→RCE) | 3/3 | 0/3 | 1,35 | 0,00 | 46 |
| CVE-2020-9484 (Tomcat) | 3/3 | 2/3 | 1,92 | 0,00 | 47 |
| CWE-89-SQL-injection (DVWA) | 2/2 | 2/4 | 1,44 | 0,00 | 45 |
| EPS_CWE-434 | 5/5 | 0/1 | 1,23 | 0,00 | 42 |
| Juice-Shop | 4/4 | 2/2 | 1,27 | 0,00 | 41 |
| PHP_CWE-434 (upload→RCE) | 3/3 | 2/3 | 1,20 | 0,00 | 42 |
| ZipSlip | 2/2 | 0/4 | 1,36 | 0,00 | 42 |
| **Pooled** | **43/48 = 0,896** | **10/47 = 21,3%** | 1,87 (p50 1,23) | 0,00 | — |

## Đối chiếu kỳ vọng đã đăng ký — đạt và TRƯỢT (trung thực)

- **Recall ≥ 95% pooled (trên các kịch bản v5 bắt 100% trên LID-DS official, Juice-Shop không gộp): KHÔNG đạt.**
  Pooled 39/44 = **0,886**. **Thiếu hụt toàn bộ do một kịch bản: Heartbleed 0/5.** 14/15 kịch bản còn lại (kể cả
  Juice-Shop) recall **1,00**.
- **False-alarm cycles ≤ 5% pooled: KHÔNG đạt.** 10/47 = **21,3%**, dồn ở victim web: Tomcat 2/3, CWE-89 2/4, Juice 2/2,
  PHP 2/3 (+ CouchDB 1/6, nginx 1/5). Mẫu số nhỏ (1–6 chu kỳ normal/kịch bản ở live 4 h) nên ước lượng nhiễu; nhưng
  xu hướng rõ: normal HTTP của các app web sinh cửa sổ vượt ngưỡng.
- **Latency p95 ≤ 3 s: ĐẠT** (1,87 s; p50 1,23 s). Một ngoại lệ p95 cục bộ: CouchDB 4,40 s (1 chu kỳ).
- **Lineage (H2 của amendment 2): xác nhận.** `alarm_session_share = 0,00` ở mọi kịch bản bắt được → cảnh báo nổ trên
  **dòng syscall gốc của victim**, không phải phiên inject. Victim không có runtime exec, đúng như thiết kế.

## Đọc

- **Khẳng định detector trên CVE thật, và bác con số 0,68 của long-1114.** 5 kịch bản trước đây 0 (vì exploit hỏng) nay
  bắt **100%**: MySQL 3/3, CWE-89 2/2, Juice 4/4, PHP 3/3, Bruteforce 3/3 (và 23839 3/3). Đây đúng là điều lượt chạy lại
  cần làm: phân biệt *trượt vì tàng hình thật* khỏi *trượt vì công cụ hỏng*.
- **Chỉ Heartbleed là trượt thật.** Nó là đọc lố bộ nhớ trong OpenSSL qua một heartbeat dị dạng, không sinh chuỗi
  syscall mới ở victim → mô hình token không thấy gì lạ. Đáng chú ý: trên LID-DS dataset v5 bắt Heartbleed 84/84, nhưng
  live 0/5 — exploit HTTP ở đây là đọc-lố thuần, còn bản ghi dataset có thể kèm hành vi khác. Giới hạn tàng hình này
  **lộ rõ hơn khi live** và là một kết quả trung thực đáng ghi, không phải lỗi dựng.
- **Điểm yếu mở: báo nhầm trên normal HTTP của app web** (21% pooled) — cần capture dài hơn hoặc normal đại diện hơn để
  đặt ngưỡng; mẫu số nhỏ của live 4 h làm số này nhiễu. Capture 8 h cho 41–47 block ngưỡng/kịch bản (ổn hơn long-1114's
  30–36), nhưng live 4 h chỉ cho ~3 chu kỳ normal/kịch bản.

## Dữ liệu

`lidds-live-score.json` (schema `lidds-live-score-v1`, `scripts/analysis/lidds_live_score.py`): per-scenario
workload / capture_windows / threshold / capture_blocks / exploit_cycles / detected / recall / normal_cycles /
false_alarm_cycles / latency_p50,p95 / alarm_session_share, và khối `pooled`. Run gốc trên NFS
`/mnt/sentinel-pulse-archive/pulse-live-lidds-1115` (tokens 2,96 GB, meta, schedule-{capture,live}.jsonl).
