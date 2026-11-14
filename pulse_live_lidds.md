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

Tài liệu phòng thủ đi kèm — hành vi quan sát được của từng kịch bản (cái cần phát hiện): [pulse_live_lidds_detection.md](pulse_live_lidds_detection.md).

---

## 2. Mười lăm kịch bản — đã dựng **15/15**

Mã nguồn kịch bản: `github.com/LID-DS/LID-DS` (commit 5b8e414), clone sẵn tại `/var/tmp/lidds-live/LID-DS`. Mỗi kịch bản
có image `victim` và `exploit` (tự dựng hoặc pull image công khai); image `normal` của dataset bị bỏ, thay bằng generator
chung (mục 3.3). Cột "Phần rã đã vá" cho biết đã phải xử lý gì để dựng được (chi tiết mục 3, nhật ký mục 4).

| Kịch bản | Dịch vụ / lỗ hổng | victim | exploit | Phần rã đã vá |
|---|---|---|---|---|
| CVE-2012-2122 | MySQL 5.5.23 auth bypass | `vulhub/mysql:5.5.23` (pull) | `exploit_mysql` | — |
| CVE-2017-7529 | Nginx range integer overflow | `victim_overflow` | `exploit_overflow` | — |
| CVE-2017-12635_6 | CouchDB 2.1.0 RCE | `vulhub/couchdb:2.1.0` (pull) | `exploit_couchdb` | — |
| CVE-2019-5418 | Rails path traversal | `victim_rails` (ruby:2.5.1) | `exploit_rails` | apt archive stretch + trusted |
| CVE-2020-9484 | Tomcat deserialization | `victim_tomcat` | `exploit_tomcat` | — |
| ZipSlip | giải nén ghi ra ngoài thư mục | `victim_zipslip` | `exploit_zipslip` | — |
| CVE-2018-3760 | Rails sprockets path traversal | `vulhub/rails:5.0.7` + apt | debian:9.2 | apt archive động + trusted |
| CVE-2020-13942 | Apache Unomi OGNL RCE | `apache/unomi:1.5.1` + apt | debian:9.2 | apt archive động + trusted |
| CVE-2020-23839 | XSS stored | `php:7.4.9-apache-buster` | debian:9.2 | apt archive buster + giữ python3-pip |
| CWE-89-SQL-injection | DVWA SQL injection | `vulnerables/web-dvwa` | debian:9.2 | bỏ chrome, giữ python3-pip, apt archive |
| EPS_CWE-434 | upload file độc | `ubuntu:16.04` (schema-1) | debian:9.2 | schema-2 (skopeo) + apt archive |
| Juice-Shop | OWASP Juice Shop | `bkimminich/juice-shop` (pull) | debian:10 | apt archive buster + giữ python3-pip |
| PHP_CWE-434 | DVWA upload | `vulnerables/web-dvwa` + chrome | alpine | bỏ trọn khối chrome (giữ python3-pip) |
| Bruteforce_CWE-307 | brute force HTTP login | `ubuntu:13.04` (schema-1) | metasploit (rebase) | schema-2 + **rebase image metasploit** |
| CVE-2014-0160 | Heartbleed OpenSSL | `ubuntu:13.04` (schema-1) | metasploit (rebase) | schema-2 + **rebase image metasploit** |

Kiểm nhanh kịch bản nào đủ cả hai image: `bash scripts/lidds_live/preflight.sh scripts/lidds_live/scenarios.json`
(với các kịch bản đã khai trong `scenarios.json`), hoặc `docker image inspect <victim> <exploit>`.

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

### 3.3 Client chrome/selenium chết (và cái bẫy `python3-pip`)

victim/normal của một số kịch bản cài `google-chrome-stable` + `chromedriver 2.42` + `selenium` từ `dl.google.com`,
`dl-ssl.google.com` và `chromedriver.storage.googleapis.com` — đều đã mất. Xử lý:
- **normal:** bỏ hẳn client selenium của dataset, dùng generator HTTP/DB chung (amendment 1). Không build normal nữa.
- **victim** (ví dụ DVWA của PHP_CWE-434, CWE-89 cài kèm chrome): bỏ các lệnh dựng chrome.

**Bẫy quan trọng (đã mắc một lần):** các Dockerfile này cài `python3-pip` **trên cùng một dòng apt** với
`xvfb`/`udev`/`google-chrome`, ví dụ `apt-get install -y python3 python3-pip wget unzip xvfb udev`. Nếu xoá cả dòng
(regex quét từ khoá chrome) thì **mất luôn `pip3`**, và các lệnh `RUN pip3 install ...` ngay sau đó chết với `exit 127`
(pip3 not found). Cách đúng (fixer v3): chỉ **bỏ từng gói chrome** (`xvfb`, `udev`, `google-chrome-stable`) khỏi dòng
apt, **giữ** `python3`, `python3-pip`, `wget`, `unzip`; còn các lệnh `RUN` thuần chrome (thêm repo google, `apt-key`,
tải/giải nén `chromedriver`, `pip install selenium`/`pyvirtualdisplay`) thì thay bằng `RUN true`. Phải nối các dòng có
`\` thành một lệnh logic trước khi sửa để không cắt giữa một `RUN` nhiều dòng (lỗi đã gặp ở fixer v2).

### 3.4 Base không ghi rõ codename debian (archive động)

`vulhub/rails:5.0.7`, `apache/unomi:1.5.1`, `php:7.4.9-apache-buster` là ảnh debian nhưng **tên FROM không chứa
`debian:9`/`debian:10`**, nên không thể suy codename từ dòng FROM để trỏ archive. Giải pháp (fixer v2/v3): chèn một
`RUN` **tự phát hiện codename trong ảnh** rồi mới trỏ archive, chạy được cho stretch/buster/bất kỳ:

```dockerfile
RUN if [ -f /etc/debian_version ]; then . /etc/os-release 2>/dev/null; CN=${VERSION_CODENAME:-stretch}; \
      printf 'deb [trusted=yes] http://archive.debian.org/debian %s main\n\
deb [trusted=yes] http://archive.debian.org/debian-security %s/updates main\n' "$CN" "$CN" > /etc/apt/sources.list; \
      printf 'Acquire::Check-Valid-Until "false";\nAcquire::AllowInsecureRepositories "true";\n' > /etc/apt/apt.conf.d/99archive; \
    fi
```

(tự no-op trên ảnh không phải debian). Đây là bản thay cho cách chèn cứng codename ở mục 3.2.

### 3.5 Phần rã sâu nhất: metasploit (Bruteforce, Heartbleed) — rebase

Hai exploit này không chỉ cần một thư viện: Dockerfile gốc **clone `metasploit-framework` 6.1.5 từ nguồn rồi
`bundle install`** trong một khối `RUN` khổng lồ, trên `ubuntu:bionic` (ruby 2.5, đã EOL). Metasploit 6.1.5 cần ruby
mới hơn và hàng trăm gem phải biên dịch; năm 2026 thì bundle/gem gãy (thoát mã 5, không phải lỗi apt nên vá apt vô ích).
Đây là phần rã **sâu nhất**.

**Cách vá — rebase sang image metasploit dựng sẵn.** Không build metasploit từ nguồn nữa, mà dùng image chính thức
`metasploitframework/metasploit-framework:latest` (Alpine, đã có ruby + `msfrpcd` chạy được ở
`/usr/src/metasploit-framework/`, có sẵn `python3`/`pip3`) làm base, rồi chỉ chồng phần glue python:

```dockerfile
# scripts/lidds_live/exploit_metasploit.Dockerfile
FROM metasploitframework/metasploit-framework:latest
USER root
RUN (pip3 install --no-cache-dir --break-system-packages pymetasploit3 || pip3 install --no-cache-dir pymetasploit3)
COPY exploit.py /exploit.py
WORKDIR /usr/src/metasploit-framework
ENTRYPOINT ["python3","-u","/exploit.py"]
```

Chỉnh một dòng trong `exploit.py` của kịch bản: `"./msfrpcd ..."` → `"/usr/src/metasploit-framework/msfrpcd ..."` (image
mới không để `msfrpcd` trong PATH). Exploit dùng module **auxiliary scanner** qua `msfrpcd`
(`scanner/ssl/openssl_heartbleed`, `scanner/http/http_login`) nên **không cần database** — bỏ luôn phần postgres/db.sql
của Dockerfile gốc. Victim của hai kịch bản là `ubuntu:13.04` (đã chuyển schema-2, mục 3.1).

Kiểm chứng image rebase chạy được (không cần victim): `pymetasploit3` import được, `msfrpcd` khởi động, pymetasploit3
kết nối tới msfrpc, và module nạp được (có tuỳ chọn `RHOSTS`). Nhờ vậy đủ **15/15** kịch bản.

```bash
# dựng lại hai exploit metasploit (trong thư mục exploit của mỗi kịch bản, sau khi sửa exploit.py)
docker build -f scripts/lidds_live/exploit_metasploit.Dockerfile -t exploit_heartbleed CVE-2014-0160/exploit
docker build -f scripts/lidds_live/exploit_metasploit.Dockerfile -t exploit_bruteforce Bruteforce_CWE-307/exploit
```

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

# 4.5 vá + build nốt các kịch bản rã (xem mục 4.6 cho thứ tự thực tế)
python3 /var/tmp/lidds-live/fix_build.py       # (v1) ghi /var/tmp/lidds-live/REFIX.txt

# 4.6 kiểm kịch bản nào đủ image
bash scripts/lidds_live/preflight.sh scripts/lidds_live/scenarios.json
```

### 4.6 Nhật ký dựng thực tế (toàn bộ các vòng)

Dựng không xong trong một lần; mỗi lỗi lộ ra một lớp rã. Thứ tự đã làm (mỗi image một log riêng tại
`/var/tmp/lidds-live/logs/<scenario>--<image>.log`):

1. **build_ve.sh (vòng 1):** build thẳng victim+exploit của 15 kịch bản. Xong ngay: nginx, tomcat, zipslip, mysql+couchdb
   (victim pull), vài exploit. Lộ hai lỗi lớn: `ubuntu:13.04/16.04` schema-1 không pull được, và các normal/victim selenium
   chết. Hai exploit metasploit treo 40 phút rồi bỏ.
2. **skopeo + bỏ build normal:** chuyển `ubuntu:13.04/16.04` sang `localrot/*` (mục 3.1); bỏ build image normal (thay bằng
   generator); chỉ build victim+exploit. Rails victim vẫn fail apt (GPG hết hạn) → thêm `[trusted=yes]` +
   `--allow-unauthenticated` (mục 3.2) → victim_rails ok.
3. **fix_build.py (v1):** chèn archive theo codename **đọc từ dòng FROM** + bỏ dòng chrome (regex) + nới apt. Thêm được
   `exploit_sprockets`, `exploit_unomi`, `victim_xss`, `exploit_eps`. Nhưng regex bỏ chrome **xoá nhầm dòng cài
   `python3-pip`** → nhiều victim fail `pip3: exit 127`; và base `vulhub/rails`, `apache/unomi` không có codename trong
   FROM nên không được trỏ archive.
4. **fix_build2.py (v2):** reset Dockerfile, chuyển sang **archive động** (tự phát hiện codename trong ảnh, mục 3.4).
   Thêm `victim_sprockets`, `victim_unomi`. Nhưng vẫn còn bỏ nhầm `python3-pip`, và regex cắt giữa `RUN` nhiều dòng của
   Juice-Shop.
5. **fix_build3.py (v3):** sửa chính xác (mục 3.3): nối dòng `\` trước; chỉ bỏ gói chrome khỏi dòng apt, **giữ
   python3-pip**; các `RUN` chrome thuần → `RUN true`. Thêm `exploit_xss`, `victim_sql`, `exploit_sql`, `exploit_juice`,
   `victim_php`. → **13/15**.
6. **rebase metasploit (mục 3.5):** `exploit_heartbleed`, `exploit_bruteforce` trên image metasploit dựng sẵn. → **15/15**.

Các script `fix_build*.py` nằm ở `/var/tmp/lidds-live/` trên .234 (sinh ra trong quá trình dựng, không nằm trong repo);
cách vá cốt lõi đã mô tả ở mục 3 để tái lập.

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
