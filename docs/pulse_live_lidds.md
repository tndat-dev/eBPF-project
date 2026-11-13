# Dựng và chạy CVE thật của LID-DS 2021 trên cụm (pulse-live-lidds)

Tài liệu này mô tả đầy đủ cách đưa 15 kịch bản lỗ hổng thật của LID-DS 2021 lên cụm Kubernetes, chạy dưới probe token
của Pulse, để đo khả năng phát hiện exploit thật **ngay trong process của dịch vụ** (đóng điểm yếu W2 trong
[notes/PAPER_PLAN.md](../notes/PAPER_PLAN.md)). Protocol: `sentinel_pulse/protocol/pulse-live-lidds-v1.json` (+ amendment 1).

Mọi lệnh chạy trên lab (VPN). `.234` là master (có Docker, kubectl); `.237/.238/.239` là worker; `.233` là NFS.

---

## 1. Ý tưởng và kiến trúc

- **victim** của mỗi kịch bản = một Deployment `victim-<slug>` trong namespace **`lidds-live`** (cô lập mạng, ngoài
  ambient mesh). Resolver của Pulse theo dõi namespace này, nên syscall của victim đi qua đúng pipeline token như một
  workload production.
- **normal traffic** và **exploit** chạy từ pod **riêng** (nhãn `lidds-gen` / `lidds-atk`) gọi victim **qua mạng**.
  Resolver loại các pod này khỏi allow-list (`EXCLUDED_MARKERS`), nên **chỉ victim bị probe**, và exploit hiện ra trong
  cây process của chính victim — đúng như dataset (exploit là từ xa, victim mới là bên bị bất thường).
- **normal traffic là generator chung** (image `lidds-gen:latest`): client selenium/chrome của dataset đã rã, nên
  `normal.request` trong `scenarios.json` là một lệnh HTTP/DB gọi victim, chạy mỗi lần theo wait-time lấy mẫu
  (amendment 1). **victim và exploit image là của chính dataset** (dịch vụ có lỗ hổng thật, exploit thật).
- **Thẻ dòng dõi:** probe dùng bản build có thẻ native/session (`ml-final-study-v1` amendment 2). Vì exploit chạy trong
  process của victim (không phải `kubectl exec`), cảnh báo nằm trên **dòng native** — kiểm chứng trực tiếp giả thuyết H2.

```
  namespace lidds-live                          worker (pinned)
  ┌───────────────────────────┐        ┌──────────────────────────────────────┐
  │ victim-<slug> (Deployment)│◀── HTTP/DB ── lidds-gen-* (generator)          │
  │   dịch vụ có lỗ hổng thật  │◀── exploit ── lidds-atk-* (exploit image)      │
  └─────────────┬─────────────┘        │  probe eBPF (thẻ dòng dõi) → loader    │
                │ syscall                │  → tokens.jsonl (token window/0.5 s)  │
                ▼                        └──────────────────────────────────────┘
       resolver (lidds-live) → allow-list chỉ gồm cgroup victim
```

Mã nguồn: `scripts/lidds_live/` (driver, run_probe, run_all), `scripts/analysis/lidds_live_score.py`.

---

## 2. Mười lăm kịch bản và trạng thái build

Mã nguồn kịch bản: `github.com/LID-DS/LID-DS` (commit 5b8e414), clone sẵn tại `/var/tmp/lidds-live/LID-DS`. Mỗi kịch bản
có ba image tự dựng (`victim`, `normal`, `exploit`) hoặc victim là một image công khai pull về.

| Kịch bản | Dịch vụ / lỗ hổng | victim | exploit | Trạng thái |
|---|---|---|---|---|
| CVE-2012-2122 | MySQL 5.5.23 auth bypass | `vulhub/mysql:5.5.23` (pull) | `exploit_mysql` | **chạy được** |
| CVE-2017-7529 | Nginx range integer overflow | `victim_overflow` | `exploit_overflow` | **chạy được** |
| CVE-2017-12635_6 | CouchDB 2.1.0 RCE | `vulhub/couchdb:2.1.0` (pull) | `exploit_couchdb` | **chạy được** |
| CVE-2019-5418 | Rails path traversal | `victim_rails` | `exploit_rails` | **chạy được** |
| CVE-2020-9484 | Tomcat deserialization | `victim_tomcat` | `exploit_tomcat` | **chạy được** |
| ZipSlip | giải nén ghi ra ngoài thư mục | `victim_zipslip` | `exploit_zipslip` | **chạy được** |
| CVE-2018-3760 | Rails sprockets path traversal | `vulhub/rails:5.0.7` + apt | debian:9.2 | vá apt |
| CVE-2020-13942 | Apache Unomi OGNL RCE | `apache/unomi:1.5.1` | debian:9.2 | vá apt |
| CVE-2020-23839 | XSS | `php:7.4.9-apache-buster` | debian:9.2 | vá apt |
| CWE-89-SQL-injection | DVWA SQL injection | `vulnerables/web-dvwa` | debian:9.2 | vá apt |
| EPS_CWE-434 | upload file độc | `ubuntu:16.04` (schema-1) | debian:9.2 | vá apt + schema-2 |
| Juice-Shop | OWASP Juice Shop | `bkimminich/juice-shop` (pull) | debian:10 | vá apt |
| PHP_CWE-434 | DVWA upload | `vulnerables/web-dvwa` + chrome | alpine | bỏ chrome |
| Bruteforce_CWE-307 | brute force | `ubuntu:13.04` (schema-1) | metasploit 6.1.5 | **khó (metasploit)** |
| CVE-2014-0160 | Heartbleed OpenSSL | `ubuntu:13.04` (schema-1) | metasploit 6.1.5 | **khó (metasploit)** |

---

## 3. Image rã theo thời gian và cách vá

LID-DS 2021 (2021) dùng nhiều base image và URL nay đã chết. Ba lớp lỗi và cách xử lý:

### 3.1 Manifest schema-1 (ubuntu:13.04, ubuntu:16.04)

containerd và Docker hiện đại đã bỏ hỗ trợ manifest schema-1, nên `ubuntu:13.04`/`ubuntu:16.04` không pull được
(`schema 1 image manifests are no longer supported`). Chuyển sang schema-2 bằng **skopeo**:

```bash
sudo apt-get install -y skopeo          # cài một lần
sudo skopeo copy --format v2s2 docker://docker.io/library/ubuntu:13.04 docker-daemon:localrot/ubuntu:13.04
sudo skopeo copy --format v2s2 docker://docker.io/library/ubuntu:16.04 docker-daemon:localrot/ubuntu:16.04
```

rồi trỏ `FROM ubuntu:13.04` → `FROM localrot/ubuntu:13.04` trong Dockerfile victim.

### 3.2 apt của debian stretch/buster đã lưu kho và hết hạn GPG

debian 9 (stretch) và 10 (buster) đã EOL; kho chuyển sang `archive.debian.org`, và khoá GPG hết hạn nên apt từ chối
(`EXPKEYSIG ... is not signed`). Vá: trỏ nguồn apt sang archive với `[trusted=yes]`, tắt kiểm hạn, và cài với
`--allow-unauthenticated`:

```dockerfile
FROM debian:9.2
RUN printf 'deb [trusted=yes] http://archive.debian.org/debian stretch main\n\
deb [trusted=yes] http://archive.debian.org/debian-security stretch/updates main\n' > /etc/apt/sources.list \
 && printf 'Acquire::Check-Valid-Until "false";\nAcquire::AllowInsecureRepositories "true";\n' > /etc/apt/apt.conf.d/99archive
RUN apt-get update && apt-get install -o Acquire::AllowInsecureRepositories=true --allow-unauthenticated -y <packages>
```

(buster thì thay `stretch` bằng `buster`.) Script `fix_build.py` tự chèn các dòng này theo codename đọc từ `FROM`.

### 3.3 Client chrome/selenium chết

victim/normal của một số kịch bản cài `google-chrome-stable` và `chromedriver 2.42` từ `dl.google.com` và
`chromedriver.storage.googleapis.com` — đều đã mất. Hai xử lý:
- **normal:** bỏ hẳn client dataset, dùng generator HTTP/DB chung (amendment 1). Không build normal nữa.
- **victim** (ví dụ DVWA của PHP_CWE-434 cài kèm chrome): xoá các dòng cài chrome/chromedriver/selenium/xvfb; victim
  vẫn phục vụ bình thường.

### 3.4 metasploit (Bruteforce, Heartbleed)

Hai exploit này clone `metasploit-framework` 6.1.5 rồi `bundle install` trên ruby cũ — hỏng do gem/network. Đây là phần
rã sâu nhất; tách riêng, không chặn các kịch bản khác.

---

## 4. Build image (trên .234)

Mọi thứ chạy dưới user `dat` (nhóm `docker`), trong unit có `MemoryMax` để không ảnh hưởng cụm.

```bash
# 4.1 generator chung
docker build -f scripts/lidds_live/gen.Dockerfile -t lidds-gen:latest .

# 4.2 pull các victim là image công khai
for i in vulhub/mysql:5.5.23 vulhub/couchdb:2.1.0 vulhub/rails:5.0.7 apache/unomi:1.5.1 \
         php:7.4.9-apache-buster vulnerables/web-dvwa bkimminich/juice-shop; do docker pull "$i"; done

# 4.3 chuyển schema-1 (một lần)
sudo skopeo copy --format v2s2 docker://docker.io/library/ubuntu:13.04 docker-daemon:localrot/ubuntu:13.04
sudo skopeo copy --format v2s2 docker://docker.io/library/ubuntu:16.04 docker-daemon:localrot/ubuntu:16.04

# 4.4 build từng image (có log riêng cho mỗi image)
bash /var/tmp/lidds-live/build_ve.sh          # victim + exploit, ghi /var/tmp/lidds-live/VE.txt
# vá + build nốt các kịch bản rã apt:
python3 /var/tmp/lidds-live/fix_build.py       # ghi /var/tmp/lidds-live/REFIX.txt

# 4.5 kiểm kịch bản nào đủ image
bash scripts/lidds_live/preflight.sh scripts/lidds_live/scenarios.json
```

---

## 5. Nạp image lên worker

Workers chạy pod với `imagePullPolicy: Never`, nên image phải có trong containerd (`k8s.io`) của từng worker.
**Lưu ý topology ssh:** `.234` **không** có khoá ssh tới worker; mọi phân phối đi qua **NFS** (chia sẻ mọi node), không
route qua máy điều khiển:

```bash
# trên .234: lưu image ra NFS
docker save <image list> -o /mnt/sentinel-pulse-archive/lidds-images.tar
# trên mỗi worker: import từ NFS
sudo ctr -n k8s.io images import /mnt/sentinel-pulse-archive/lidds-images.tar
rm -f /mnt/sentinel-pulse-archive/lidds-images.tar
```

(`scripts/lidds_live/import_images.sh` tự động phần này khi `.234` ssh được worker; nếu không, dùng NFS như trên.)

---

## 6. Chạy

Pin mọi pod vào một worker để một loader thấy hết (`PULSE_LIDDS_NODE`), probe dùng bản build thẻ dòng dõi.

```bash
# 6.1 namespace cô lập
kubectl apply -f scripts/lidds_live/namespace.yaml

# 6.2 build probe thẻ dòng dõi trên worker (một lần)
cd sentinel_pulse/ebpf && make tokens TOKENS_BUILD_DIR=/home/dat/pulse-tokens-lineage

# 6.3 đưa victim lên worker ghim
PULSE_LIDDS_NODE=k8s-worker1.local python3 -c 'import json,sys;sys.path.insert(0,"scripts/lidds_live");import driver;\
cfg=json.load(open("scripts/lidds_live/scenarios.json"));[driver.apply(driver.victim_deployment(s,cfg[s])) for s in \
["CVE-2012-2122","CVE-2017-7529","CVE-2017-12635_6","CVE-2019-5418","CVE-2020-9484","ZipSlip"]]'
kubectl -n lidds-live wait --for=condition=available deploy --all --timeout=180s

# 6.4 probe trên worker (ghi token window + metadata cgroup→victim)
sudo systemd-run --unit=lidds-probe -p MemoryMax=4G -p OOMPolicy=continue \
   /bin/bash scripts/lidds_live/run_probe.sh /home/dat/pulse-tokens-lineage /var/tmp/lidds-cap /home/dat/eBPF-project

# 6.5 pha capture (chỉ normal) rồi pha live (có exploit)
SCN=CVE-2012-2122,CVE-2017-7529,CVE-2017-12635_6,CVE-2019-5418,CVE-2020-9484,ZipSlip
PULSE_LIDDS_NODE=k8s-worker1.local python3 scripts/lidds_live/driver.py capture \
   --scenarios-file scripts/lidds_live/scenarios.json --run-dir $RUN --duration 500 --only $SCN --seed 20261113
PULSE_LIDDS_NODE=k8s-worker1.local python3 scripts/lidds_live/driver.py live \
   --scenarios-file scripts/lidds_live/scenarios.json --run-dir $RUN --duration 1200 --only $SCN --seed 20261199

# 6.6 dừng probe, copy token window ra NFS run dir (worker có NFS)
sudo systemctl stop lidds-probe
sudo cp /var/tmp/lidds-cap/{tokens,meta}.jsonl $RUN/
```

victim của dataset kết thúc entrypoint bằng một shell tương tác; không có tty thì nó thoát → CrashLoop. Driver đặt
`tty: true, stdin: true` cho container victim để giữ nó sống (một kịch bản có thể ghi đè `victim.command`).

---

## 7. Chấm điểm

```bash
python3 scripts/analysis/lidds_live_score.py --run-dir $RUN --output $RUN/lidds-live-score.json
```

Với mỗi victim: học `CountTokenLM` từ cửa sổ của pha capture, đặt ngưỡng Gumbel (quy tắc cụm của lidds-ml-v5), chấm cửa
sổ pha live. Một cycle exploit được tính là phát hiện khi có cửa sổ của victim trong `[exploit_time, +30 s]` vượt ngưỡng.
Báo thêm: báo nhầm trên cycle normal, độ trễ, và **tỉ lệ session của cửa sổ cảnh báo** (gần 0 = phát hiện trên dòng
native của victim).

---

## 8. Dọn dẹp

```bash
kubectl delete namespace lidds-live
# trên mỗi worker: ctr -n k8s.io images rm <victim/exploit/generator images>
```

---

## 9. Kết quả

Biên nhận trong `validation-evidence/results-<date>/pulse-live-lidds/`. Lượt kiểm tuyến đầu tiên
(`pulse-live-lidds-1113`, 2 kịch bản): 3/3 exploit phát hiện, recall 1.0, độ trễ p50 1,40 s / p95 1,66 s, báo nhầm 0,
`alarm_session_share = 0.0` (phát hiện trên dòng native). Xem README trong thư mục biên nhận để biết số đầy đủ và giới hạn.
