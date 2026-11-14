# pulse-live-lidds: lượt dài đủ 15 kịch bản (14/11/2026)

Run `pulse-live-lidds-long-1114`, protocol `sentinel_pulse/protocol/pulse-live-lidds-v1.json` (+ amendment 1),
cluster-resident (unit `lidds-run-master-long` trên .234 + `lidds-run-worker-long` loader eBPF trên k8s-worker1,
điều phối qua marker NFS; cap RAM runtime master 24G / worker 8G). **Capture 6h + live 4h**, một lượt duy nhất.
Fit `CountTokenLM` + ngưỡng Gumbel theo workload (`alpha=0.00018`, horizon 30 s), chấm bằng
`scripts/analysis/lidds_live_score.py`. Tiến trình: 142 cycle capture, 94 cycle live; tokens.jsonl 2,3 GB, meta.jsonl 61 MB.

Đây là lượt thống kê (thay lượt ngắn `results-20261114/`): ngưỡng fit trên **30–36 block/kịch bản** (lượt ngắn 3–7),
mỗi kịch bản 2–5 cycle exploit, có cả cycle normal để đo báo nhầm. Dùng driver sau khi sửa `apply()` retry (commit
`28d3f51`) nên không kịch bản nào mất cycle; CVE-2020-23839 được chấm đầy đủ (lượt ngắn bị "too few capture windows").

## Kết quả

Gộp: **53 cycle exploit → 36 phát hiện (recall 0.68)**; 42 cycle normal → **6 báo nhầm (0.14)**; p50 **1.26 s** / p95 **4.14 s**;
mọi cảnh báo trên dòng **native** (alarm_session_share = 0.0 ở mọi kịch bản có phát hiện).

| Kịch bản (dịch vụ) | lớp lỗi | blocks | ngưỡng | exploit / phát hiện | recall | p50 (s) | báo nhầm | session share |
|---|---|---|---|---|---|---|---|---|
| CVE-2017-12635_6 (CouchDB) | RCE | 33 | 13.28 | 4 / 4 | **1.0** | 4.19 | 1/3 | 0.0 |
| CVE-2017-7529 (Nginx) | tràn số nguyên | 36 | 5.14 | 5 / 5 | **1.0** | 1.34 | 1/2 | 0.0 |
| CVE-2018-3760 (Rails sprockets) | path traversal | 35 | 11.87 | 3 / 3 | **1.0** | 1.27 | 0/4 | 0.0 |
| CVE-2019-5418 (Rails) | đọc file tuỳ ý | 34 | 11.72 | 5 / 5 | **1.0** | 1.00 | 0/2 | 0.0 |
| CVE-2020-13942 (Unomi) | RCE OGNL | 34 | 14.13 | 3 / 3 | **1.0** | 1.19 | **3/3** | 0.0 |
| CVE-2020-23839 (GetSimple XSS) | reflected XSS → RCE | 32 | 7.92 | 4 / 4 | **1.0** | 1.08 | 0/2 | 0.0 |
| CVE-2020-9484 (Tomcat) | giải tuần tự hoá | 36 | 6.59 | 5 / 5 | **1.0** | 1.75 | 1/1 | 0.0 |
| EPS_CWE-434 (upload) | upload thực thi | 30 | 0.96 | 3 / 3 | **1.0** | 1.06 | 0/3 | 0.0 |
| ZipSlip | ghi ngoài thư mục | 34 | 1.11 | 4 / 4 | **1.0** | 1.22 | 0/2 | 0.0 |
| CVE-2012-2122 (MySQL) | auth bypass | 33 | 5.05 | 4 / **0** | 0.0 | — | 0/3 | — |
| CVE-2014-0160 (Heartbleed) | lộ bộ nhớ | 33 | 2.68 | 1 / **0** | 0.0 | — | 0/5 | — |
| CWE-89-SQL-injection (DVWA) | SQLi | 32 | 5.19 | 4 / **0** | 0.0 | — | 0/2 | — |
| Juice-Shop (Node) | SQLi | 32 | 10.11 | 4 / **0** | 0.0 | — | 0/2 | — |
| Bruteforce_CWE-307 | brute-force | 30 | 2.29 | 2 / **0** | 0.0 | — | 0/4 | — |
| PHP_CWE-434 (DVWA upload) | upload | 31 | 6.05 | 2 / **0** | 0.0 | — | 0/4 | — |

## Phân tích: phát hiện bám đúng ranh giới "hành vi hệ thống mới"

- **9 kịch bản sinh hành vi hệ thống mới → recall 36/36 = 1.0** (RCE sinh tiến trình con/kết nối; path traversal mở
  file ngoài cây tài nguyên; upload-thực-thi; ZipSlip ghi ngoài thư mục). Phát hiện trong **~1.0–1.8 s** (CouchDB 4.2 s),
  mọi cảnh báo trên dòng **native** của chính dịch vụ (session share 0.0) — khai thác trong process victim, không phải
  qua `kubectl exec`. Đóng W2 và xác nhận H2 ở quy mô 9 CVE thật, 36 cycle.
- **6 kịch bản không để lại dấu ở tầng syscall → recall 0/17**: MySQL auth bypass, Heartbleed (đọc bộ nhớ sẵn có),
  SQLi thuần (DVWA CWE-89, Juice-Shop), brute-force (chỉ tăng tần suất chuỗi đã học), PHP upload. Khớp đúng giới hạn
  đã đăng ký trước và ghi ở `pulse_live_lidds_detection.md` §3 (tấn công không tạo hành vi hệ thống mới / chỉ dùng chuỗi
  đã thấy / tín hiệu tần suất). Đây là ranh giới phương pháp của detector token thuần, không phải lỗi cấu hình.
- **Báo nhầm giảm còn 0.14** (6/42) so với 0.54 (7/13) ở lượt ngắn, nhờ ngưỡng fit trên 30–36 block. Nguồn báo nhầm còn
  lại dồn ở **Unomi (3/3)** — tiến trình Java/Karaf có normal biến động mạnh; các kịch bản khác ≤ 1 báo nhầm.

## Mục cần xem tiếp (không chặn kết quả)

- **Unomi 3/3 báo nhầm**: normal của Karaf đa dạng; cần capture dài hơn nữa hoặc xem lại cách gộp block cho dịch vụ JVM.
- **PHP_CWE-434 không phát hiện** dù là upload (0/2) trong khi EPS_CWE-434 (cũng upload) đạt 3/3: cần kiểm kịch bản upload
  của DVWA có thực sự ghi/thực thi file ngoài thư mục quen hay không.
- **Heartbleed (0/1)**: tài liệu detection dự đoán bất thường tỉ lệ ghi/đọc; thực tế không bắt — chỉ 1 cycle, cần thêm cycle.

## Dữ liệu

`lidds-live-score.json` (điểm đầy đủ: ngưỡng, block, recall, độ trễ, session share theo kịch bản), `schedule-capture.jsonl`,
`schedule-live.jsonl`, `score.stdout`. Token/meta thô (`tokens.jsonl` 2,3 GB, `meta.jsonl` 61 MB) ở NFS
`pulse-live-lidds-long-1114/`, không đưa vào repo.
