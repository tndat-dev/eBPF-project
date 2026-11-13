# pulse-live-lidds: first real-CVE run on the cluster (13/11/2026)

Protocol `sentinel_pulse/protocol/pulse-live-lidds-v1.json` (+ amendment 1). Closes weakness W2 (`notes/PAPER_PLAN.md`):
real vulnerable services on Kubernetes, their real exploits acting **inside the victim's own process tree**, scored by
the token model. Short validation run (`pulse-live-lidds-1113`), single node (k8s-worker1), lineage probe build.

Pipeline: victim Deployment in namespace `lidds-live` (watched by the resolver); normal traffic and the exploit from
excluded pods (`lidds-gen` / `lidds-atk`) over the network, so only the victim is probed. Capture phase (normal only)
→ per-victim `CountTokenLM` + Gumbel threshold (lidds-ml-v5 cluster rule) → live phase (exploit cycles) scored.
Code: `scripts/lidds_live/` (driver, run_probe, run_all), `scripts/analysis/lidds_live_score.py`.

## Result

| Scenario (service) | Capture windows | Exploit cycles | Detected | Latency p50 / p95 | Alarm session share | False-alarm cycles |
|---|---|---|---|---|---|---|
| CVE-2017-7529 (nginx range overflow) | 141 | 1 | 1 | 1.27 s | 0.0 | 0 (no live normal cycle) |
| CVE-2020-9484 (tomcat deserialization) | 300 | 2 | 2 | 1.55 / 1.68 s | 0.0 | 0 (no live normal cycle) |
| **pooled** | | **3** | **3 (recall 1.0)** | **1.40 / 1.66 s** | **0.0** | |

- **The token model, fit only on the cluster's own normal of each victim, detected every real exploit** running inside
  the victim's process, within ~1.3–1.7 s. This is on the real CVE services and the dataset's real exploits, not a
  self-written fixture, and the exploit is not a `kubectl exec` (closing the W2 attribution concern directly).
- **`alarm_session_share = 0.0`**: every exploit alarm is on the victim's **native** lineage stream (the service's own
  process tree), confirming H2 of `ml-final-study-v1` amendment 2 — the native stream detects in-process exploits.

## Limits of this short run (not the statistical run)

- Only 2 scenarios ran: the ZipSlip victim did not reach Ready; the metasploit-based exploits (Bruteforce, Heartbleed)
  did not build. The 6 built scenarios are CVE-2012-2122, CVE-2017-7529, CVE-2017-12635_6, CVE-2019-5418, CVE-2020-9484,
  ZipSlip (preflight).
- Few capture blocks (3–4) and few exploit cycles (1 and 2); the threshold is fit on little data.
- The live phase drew no normal (non-exploit) cycles (seed), so the false-alarm rate is not measured on live normal;
  only the capture normal fed the fit. A full run needs normal live cycles.
- Next: a longer run over all buildable scenarios with normal live cycles, for the thesis numbers.

## Lượt thứ hai (6 kịch bản, `pulse-live-lidds-full-1113`)

Đưa cả 6 victim lên (mysql, nginx, couchdb, rails, tomcat, zipslip), capture 500 s + live 1200 s (có cả cycle normal).

| Kịch bản (dịch vụ) | Capture windows | Exploit cycles | Detected | Latency p50 / p95 | Session share | False-alarm cycles | Ghi chú |
|---|---|---|---|---|---|---|---|
| CVE-2017-12635_6 (CouchDB RCE) | 300 | 1 | 1 | 3.98 s | 0.0 | 1/1 | ngưỡng từ 4 block → 1 báo nhầm |
| CVE-2017-7529 (Nginx overflow) | 119 | 1 | 1 | 1.41 s | 0.0 | 0/1 | |
| CVE-2019-5418 (Rails path traversal) | 258 | 1 | 1 | — | 0.0 | 0/1 | |
| CVE-2020-9484 (Tomcat) | 300 | 0 | — | — | — | 0 | seed không rút cycle exploit |
| CVE-2012-2122 (MySQL) | 0 | — | — | — | — | — | lệch ghép capture (14.192 window nhưng 0 trong span capture) |
| ZipSlip | — | — | — | — | — | — | quá ít window capture |
| **pooled** | | **3** | **3 (recall 1.0)** | **1.41 / 3.72 s** | **0.0** | **1/3** | |

**Gộp hai lượt:** bốn CVE thật được phát hiện ngay trong process của victim — Nginx (CVE-2017-7529), Tomcat
(CVE-2020-9484), CouchDB (CVE-2017-12635_6), Rails (CVE-2019-5418); recall 6/6 trên các cycle exploit có đủ dữ liệu,
mọi cảnh báo trên dòng native (session share 0.0).

**Giới hạn của lượt ngắn (cần lượt dài cho số liệu đồ án):** ngưỡng fit trên rất ít block (3–4) nên một kịch bản có báo
nhầm (CouchDB); vài victim ít lưu lượng (MySQL, ZipSlip) chưa đủ cửa sổ capture, và có lệch ghép timing capture với
MySQL. Lượt dài hơn (capture và live mỗi pha nhiều giờ, lưu lượng normal đều hơn cho mọi victim) sẽ cho ngưỡng ổn định
và recall/báo nhầm theo từng kịch bản đầy đủ. 15/15 image đã sẵn sàng cho lượt đó (đã khai 6 trong `scenarios.json`;
9 kịch bản còn lại cần bổ sung wiring victim/exploit vào `scenarios.json`).
