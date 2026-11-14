# pulse-live-lidds: lượt đủ 15 kịch bản (14/11/2026)

Run `pulse-live-lidds-15b-1114`, protocol `sentinel_pulse/protocol/pulse-live-lidds-v1.json` (+ amendment 1),
cluster-resident (systemd unit `lidds-run-master` trên .234 + loader trên k8s-worker1, điều phối qua marker NFS).
Toàn bộ **15 kịch bản LID-DS 2021** lần đầu chạy chung một lượt (capture → fit `CountTokenLM` + ngưỡng Gumbel
theo workload → live, chấm điểm bằng `scripts/analysis/lidds_live_score.py`). `alpha=0.00018`, horizon 30 s.

Tiến trình: 16 cycle capture, 24 cycle live, đủ 15 scenario xuất hiện trong schedule; master unit kết thúc
`Deactivated successfully`.

## Sửa unomi để đủ 15

CVE-2020-13942 (Apache Unomi) trước đó không Ready trong namespace cô lập: Karaf tải bundle Maven
(`cxf-karaf-commands:3.3.4`) từ Internet lúc khởi động, bị NetworkPolicy `default-deny` chặn egress → cổng 8181
không listen → readiness fail. Cách sửa: **prewarm image offline** — chạy `victim_unomi:latest` một lần có mạng
trên .234 cho Karaf nạp hết bundle vào local repo, `docker commit` → `victim_unomi:warm`/`:latest`, kiểm boot lại
với `--network none` (8181 listen trong ~40 s, không cần mạng), import vào containerd worker1, rollout restart.
Tar warm + sha256 lưu ở `prewarm-unomi-1114/` trên NFS để tái lập. `scenarios.json` không đổi (vẫn `victim_unomi:latest`).

## Kết quả

Gộp: **10 cycle exploit → 9 phát hiện (recall 0.90)**; độ trễ **p50 1.32 s / p95 4.17 s**; 13 cycle normal →
**7 báo nhầm (0.54)**; mọi cảnh báo trên dòng **native** (alarm_session_share = 0.0 ở mọi kịch bản có phát hiện).

| Kịch bản (dịch vụ) | capture windows / blocks | ngưỡng | exploit / phát hiện | recall | p50 (s) | báo nhầm | session share |
|---|---|---|---|---|---|---|---|
| CVE-2017-12635_6 (CouchDB RCE) | 300 / 3 | 9.76 | 2 / 2 | 1.0 | 4.16 | 0 | 0.0 |
| CVE-2017-7529 (Nginx overflow) | 266 / 7 | 1.42 | 1 / 1 | 1.0 | 1.34 | 0 | 0.0 |
| CVE-2018-3760 (Rails sprockets) | 240 / 4 | 13.84 | 1 / 1 | 1.0 | 0.93 | 1 | 0.0 |
| CVE-2019-5418 (Rails path traversal) | 274 / 3 | 9.05 | 1 / 1 | 1.0 | 0.81 | 1 | 0.0 |
| CVE-2020-13942 (Apache Unomi RCE) | 300 / 3 | 8.09 | 1 / 1 | 1.0 | 0.96 | 1 | 0.0 |
| CVE-2020-9484 (Tomcat deserialize) | 300 / 4 | 4.11 | 1 / 1 | 1.0 | 1.65 | 1 | 0.0 |
| EPS_CWE-434 (upload) | 300 / 3 | 1.41 | 1 / 1 | 1.0 | 0.89 | 1 | 0.0 |
| ZipSlip (ghi ngoài thư mục) | 298 / 3 | 0.46 | 1 / 1 | 1.0 | 1.32 | 0 | 0.0 |
| CVE-2012-2122 (MySQL auth bypass) | 585 / 7 | 4.34 | 1 / **0** | **0.0** | — | 1 | — |
| Bruteforce_CWE-307 | 212 / 4 | 2.26 | 0 | — | — | 0 | — |
| CVE-2014-0160 (Heartbleed) | 272 / 3 | 2.53 | 0 | — | — | 0 | — |
| CWE-89-SQL-injection (DVWA) | 300 / 4 | 5.70 | 0 | — | — | 0 | — |
| Juice-Shop (SQLi Node) | 300 / 4 | 18.87 | 0 | — | — | 0 | — |
| PHP_CWE-434 (DVWA upload) | 300 / 4 | 7.95 | 0 | — | — | 1 | — |
| CVE-2020-23839 (GetSimple XSS) | 0 (victim 7262) | — | — | — | — | — | lệch ghép capture |

## Giới hạn (cần lượt dài cho số liệu đồ án)

- **Lượt ngắn, ngưỡng thưa:** capture chỉ 3–4 block/kịch bản nên ngưỡng bị thắt → báo nhầm cao (7/13). Lượt dài
  (capture nhiều giờ, lưu lượng normal đều hơn) cần để ngưỡng ổn định và đo báo nhầm đúng.
- **5 kịch bản không có cycle exploit** (Bruteforce, Heartbleed, CWE-89-SQLi, Juice-Shop, PHP_CWE-434): 24 cycle live
  chia 15 scenario, xác suất rút exploit 0.5 nên một số scenario chưa được rút. Lượt live dài hơn sẽ phủ đủ.
- **CVE-2012-2122 (MySQL) miss:** auth bypass gần như không sinh chuỗi syscall lạ trong mysqld — khớp giới hạn đã
  nêu ở `pulse_live_lidds_detection.md` §3 (tấn công không tạo hành vi hệ thống mới).
- **CVE-2020-23839 lệch ghép capture:** victim có 7262 window nhưng 0 window rơi vào span capture (cùng kiểu lỗi
  timing join như MySQL ở lượt 13/11). Cần xem lại cách `lidds_live_score.py` ghép window ↔ block capture.

## Dữ liệu

`lidds-live-score.json` (điểm đầy đủ theo kịch bản), `schedule-capture.jsonl`, `schedule-live.jsonl` (lịch cycle,
uid pod victim, thời điểm exploit). Capture/token thô (`tokens.jsonl` 393 MB, `meta.jsonl` 11 MB) ở trên NFS
`pulse-live-lidds-15b-1114/`, không đưa vào repo.
