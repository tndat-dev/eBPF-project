# Đánh giá thực tế và có giá trị ngoài (external validity) cho phía tấn công của Sentinel Pulse

Phạm vi: (a) công cụ giả lập tấn công và môi trường vulnerable-by-design miễn phí cho Kubernetes/container; (b) cách các đánh giá container runtime detector đã công bố dựng tập tấn công và lập luận về độ phủ; (c) workload benign thực tế; (d) baseline deep-learning syscall HIDS có code công khai và số đo trên LID-DS; (e) external validity, gán nhãn, và kế hoạch an toàn cho Pulse.
Ngày tra: 30/10/2026. Metadata repo (license, sao, lần push cuối) lấy từ GitHub REST API (`api.github.com/repos/<repo>`) trong phiên này. Ký hiệu: **[Đo]** = số tác giả đo và công bố; **[Tuyên bố]** = mô tả/tuyên bố của dự án, chưa kiểm độc lập; **[Suy luận]** = suy luận của người ghi.

## Q1. Công cụ giả lập tấn công và môi trường dễ bị tấn công: mô phỏng gì, ATT&CK, an toàn, license

### Takeaway
Không có công cụ miễn phí nào phủ trọn ATT&CK for Containers ở mức syscall. Bộ phù hợp nhất cho Pulse là: Atomic Red Team (9 test container, MIT), Falco `event-generator` (hành vi syscall đáng ngờ, Apache-2.0), CDK (discovery/credential/persistence/escape trong một binary, Apache-2.0), Peirates (credential access/lateral movement qua service account, GPL-2.0), ảnh CVE thật từ Vulhub (MIT) và mã kịch bản LID-DS (GPL-3.0) để có exploit thật chạy trong process dịch vụ. Stratus Red Team (Apache-2.0) chủ yếu tác động lên Kubernetes API (8 kỹ thuật K8s), nên chỉ sinh dấu vết syscall gián tiếp. Các module escape của CDK/BOtB/deepce chạm host, không được chạy trên cụm live dùng chung.

### Cited Findings
**Atomic Red Team** (redcanaryco, MIT, 12.742 sao, push 27/10/2026 — [repo](https://github.com/redcanaryco/atomic-red-team))
- Index nền tảng `containers` chỉ có **9 test duy nhất** (11 mục nếu tính theo tactic): T1611 Escape to Host #1 "Deploy container using nsenter container escape", #2 "Mount host filesystem to escape privileged Docker container", #3 "Privilege Escalation via Docker Volume Mapping"; T1053.002 #3 "At - Schedule a job via kubectl in a Pod" (execution/persistence/privilege-escalation); T1136.001 #10 "Create a Linux user via kubectl in a Pod"; T1105 #39 "Curl Insecure Connection from a Pod"; T1069.001 #7 "Permission Groups Discovery for Containers- Local Groups"; T1046 #9 "Network Service Discovery for Containers"; T1195.002 #1 "Simulate npm package installation on a Linux system". Các tactic stealth, lateral-movement, collection, credential-access, impact, exfiltration: **0 test container** — [containers-index.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/Indexes/Indexes-Markdown/containers-index.md)

**Stratus Red Team** (DataDog, Apache-2.0, 2.435 sao, push 29/10/2026 — [repo](https://github.com/DataDog/stratus-red-team))
- 8 kỹ thuật Kubernetes: `k8s.credential-access.dump-secrets`, `k8s.credential-access.steal-serviceaccount-token` (Credential Access); `k8s.persistence.create-admin-clusterrole` (Persistence, Privilege Escalation); `k8s.persistence.create-client-certificate`, `k8s.persistence.create-token` (Persistence); `k8s.privilege-escalation.hostpath-volume`, `k8s.privilege-escalation.nodes-proxy`, `k8s.privilege-escalation.privileged-pod` (Privilege Escalation) — [attack-techniques list](https://stratus-red-team.cloud/attack-techniques/list/)
- Mỗi kỹ thuật map ATT&CK và có vòng đời warmup → detonate → revert/cleanup [Tuyên bố] — [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/cyber-attack-simulation-with-stratus-red-team.md); [Datadog open source](https://opensource.datadoghq.com/projects/stratus-red-team/)

**MITRE Caldera** — repo đã chuyển sang `apache/caldera` (GitHub redirect từ `mitre/caldera`), Apache-2.0, 7.472 sao, push 12/10/2026 — [repo](https://github.com/apache/caldera). Chưa đọc tài liệu ability/plugin cho container trong phiên này (xem Gaps).

**CDK** (cdk-team, Apache-2.0, 4.779 sao, push 01/05/2026 — [repo](https://github.com/cdk-team/CDK))
- `cdk evaluate [--full]`: OS info, capabilities, mounts, net namespace, biến môi trường/process/file nhạy cảm, kube-proxy route_localnet (CVE-2020-8558), DNS service discovery, K8s API server, service account, cloud metadata API.
- `cdk run <module>`: escape (`runc-pwn` CVE-2019-5736, `shim-pwn` CVE-2020-15257, `docker-sock-pwn`, `docker-api-pwn`, `mount-disk`, `lxcfs-rw`, `mount-cgroup`, `abuse-unpriv-userns` CVE-2022-0492, `mount-procfs`, `check-ptrace`, `rewrite-cgroup-devices`, `cap-dac-read-search`); discovery (`service-probe`, `istio-check`, `k8s-psp-dump`); remote control (`reverse-shell`, `kubelet-exec`); credential access (`registry-brute`, `ak-leakage`, `etcd-get-k8s-token`, `k8s-secret-dump`, `k8s-configmap-dump`); privilege escalation (`k8s-get-sa-token`, `copy-fail-cve-2026-31431` x86_64); persistence (`webshell-deploy`, `k8s-backdoor-daemonset`, `k8s-shadow-apiserver`, `k8s-mitm-clusterip` CVE-2020-8554, `k8s-cronjob`).
- README: dùng không có đồng thuận trước là bất hợp pháp; chỉ cho kiểm thử bảo mật — [CDK README](https://github.com/cdk-team/CDK)

**Peirates** (inguardians, GPL-2.0, 1.488 sao, push 29/10/2026 — [repo](https://github.com/inguardians/peirates)): tool pentest K8s, tự động lấy service account token/secrets để leo quyền và pivot trong cụm — [Help Net Security](https://www.helpnetsecurity.com/2023/12/06/pentesting-kubernetes-open-source-tools/)

**kube-hunter** (aquasecurity, Apache-2.0, 5.087 sao, push cuối **19/03/2024** — [repo](https://github.com/aquasecurity/kube-hunter)); một danh sách tool đánh dấu là deprecated/unmaintained — [container-security.site](https://www.container-security.site/general_information/tools_list.html)

**BOtB** (brompwnie, GPL-3.0, 690 sao, push cuối **27/09/2023** — [repo](https://github.com/brompwnie/botb)): phân tích và khai thác container, có chế độ autopwn — [0xsyr0 handbook](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/container.md)

**deepce** (stealthcopter, Apache-2.0, 1.585 sao, push 21/12/2025 — [repo](https://github.com/stealthcopter/deepce)): Docker enumeration, privilege escalation, container escape; có chế độ exploit qua Docker socket — [0xsyr0 handbook](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/container.md)

**Falco event-generator** (falcosecurity, Apache-2.0, 141 sao, push 25/10/2026 — [repo](https://github.com/falcosecurity/event-generator))
- Nhóm action: `helper` (ExecLs, RunShell, NetworkActivity), `syscall` (lớn nhất, nhắm ruleset Falco mặc định; chỉ action của rule stable chạy mặc định, `--all` bật phần còn lại), `k8saudit` (tắt mặc định, "best-effort").
- Helm chart vào namespace `event-generator`; `config.loop=false` chạy một lần dạng Job; `--loop` sinh một event mỗi 100 ms vô hạn; `suite test` (từ v0.13) chạy kịch bản YAML và kiểm alert.
- Cảnh báo: "We strongly recommend that you run the program within Docker", "some commands might alter your system" (sửa file dưới /bin, /etc, /dev) — [README](https://github.com/falcosecurity/event-generator)

**Kubernetes Goat** (madhuakula, MIT, 5.922 sao, push 16/04/2026 — [repo](https://github.com/madhuakula/kubernetes-goat)): **22 kịch bản**, gồm sensitive keys in codebases, DIND exploitation, SSRF, container escape to host, attacking private registry, NodePort exposed services, Helm v2 tiller (deprecated), crypto miner container, namespaces bypass, gaining environment information, DoS memory/CPU, hidden in layers, RBAC least-privilege misconfiguration, cùng các bài phòng thủ (Falco, Tetragon, Kyverno, NSP…). Trang kịch bản không có cảnh báo triển khai rõ ràng (chỉ ghi "intentionally vulnerable by design") — [scenarios](https://madhuakula.com/kubernetes-goat/docs/scenarios)

**Vulhub** (MIT, 21.423 sao, push 17/10/2026): "Pre-Built Vulnerable Environments Based on Docker-Compose" — [repo](https://github.com/vulhub/vulhub)

**BishopFox badPods** (MIT, 714 sao, push 30/12/2025): "manifests that will create pods with elevated privileges" — [repo](https://github.com/BishopFox/badPods)

**MTKPI** (Multi Tool Kubernetes Pentest Image) — gom tool pentest K8s vào một image — [repo](https://github.com/r0binak/MTKPI)

**LID-DS (mã kịch bản)** — file LICENSE là GNU GPL v3 "or (at your option) any later version", copyright 2021 Grimmer, Nirsberger, Kaelble, Rucks, Röhling, Kreußel, Ganz (GitHub API hiển thị `NOASSERTION`) — [LICENSE](https://github.com/LID-DS/LID-DS/blob/master/LICENSE). Mỗi kịch bản có ba vai Docker: attacker, victim, user sinh traffic benign; công bố mã của cả 15 kịch bản — [Extended Abstract LID-DS 2021](https://dbs.uni-leipzig.de/file/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf); thời điểm request của user được lấy mẫu từ log web server thật — [Dataset Report](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf)

**Dataset escape khác**: "Docker Container Escape Attack Dataset" (IEEE DataPort, DOI 10.21227/ensx-jv79) gồm chuỗi syscall và Linux capabilities của container benign và hostile; kịch bản mount host filesystem, process injection, kernel module độc, lạm dụng Docker socket — [IEEE DataPort](https://ieee-dataport.org/documents/docker-container-escape-attack-dataset-capabilities-and-system-call-traces)

**Kỹ thuật ATT&CK liên quan**: T1611 Escape to Host gồm bind-mount host filesystem, privileged container, lạm dụng `unshare`/`keyctl`, `docker.sock`; T1610 Deploy Container thường nối với T1611 (deploy container privileged lên một node rồi escape) — [T1611 mirror](https://redteam.y-security.de/MITRE/techniques/T1611/); [T1610 mirror](https://redteam.y-security.de/MITRE/techniques/T1610/)

### Inferences
- [Suy luận] Bảng phân loại an toàn cho cụm live dùng chung (3 worker, AIMS):
  - **An toàn trong namespace riêng** (chỉ chạm process trong pod, hoặc API với RBAC bị giới hạn trong namespace): ART T1046/T1069.001/T1105/T1136.001/T1053.002; `cdk evaluate`; CDK `service-probe`, `istio-check`, `k8s-secret-dump`/`k8s-configmap-dump`/`k8s-get-sa-token` với SA chỉ có quyền trong namespace thử; Peirates với SA giới hạn; `event-generator` action `syscall` chạy trong container (các action sửa /bin, /etc, /dev chỉ sửa filesystem của container); exploit RCE của Vulhub/LID-DS vào service dễ bị tấn công trong namespace riêng.
  - **Không chạy trên cụm live**: mọi module escape (CDK `runc-pwn`, `shim-pwn`, `mount-*`, `lxcfs-rw`, `rewrite-cgroup-devices`, `abuse-unpriv-userns`; ART T1611 #1–#3; BOtB autopwn; deepce exploit; badPods; Stratus `hostpath-volume`/`privileged-pod`/`nodes-proxy`), persistence cấp cụm (`k8s-backdoor-daemonset`, `k8s-shadow-apiserver`, `k8s-mitm-clusterip`, Stratus `create-admin-clusterrole`), `etcd-get-k8s-token`. Những thứ này cần một VM/cụm dùng-một-lần riêng (ví dụ một node tách biệt bị taint, xoá sau khi chạy), hoặc thay bằng dữ liệu offline (CB-DS).
- [Suy luận] Stratus K8s tác động qua Kubernetes API, nên dấu vết chính nằm ở audit log; với detector syscall như Pulse chỉ hai kỹ thuật tạo pod (`hostpath-volume`, `privileged-pod`) sinh syscall trong container, và chỉ khi pod đó chạy lệnh. Không nên tính Stratus vào độ phủ syscall của Pulse.
- [Suy luận] Peirates là GPL-2.0, BOtB và LID-DS là GPL-3.0: chạy như công cụ thì không ràng buộc; chỉ khi chép mã vào repo Pulse mới phải giữ license GPL cho phần đó. Port kịch bản LID-DS sang manifest K8s nên giữ trong thư mục riêng ghi rõ GPL-3.0.
- [Suy luận] kube-hunter (không push từ 03/2024) và BOtB (từ 09/2023) có rủi ro không còn khớp K8s/kernel hiện tại; nên coi là tuỳ chọn.

### Gaps
- Không đọc được tài liệu Caldera về agent Linux (Sandcat) và ability cho container/K8s; không xác nhận số ability ATT&CK cho container.
- Không tìm thấy repo "kube-security-lab" theo các tên đã đoán (`ksoclabs/…`, `Lexus-Kubesec/…`); chưa xác định repo chuẩn.
- Không kiểm được số kỹ thuật ATT&CK mà Peirates/kube-hunter map chính thức; không tìm thấy simulator cryptominer "an toàn" có tài liệu (ví dụ chế độ benchmark không kết nối pool) — chỉ biết SciTePress dùng `xmrig` thật (Q2).

## Q2. Các đánh giá runtime detector đã công bố: số và loại tấn công, workload benign, cách lập luận độ phủ

### Takeaway
Các đánh giá công bố dùng tập tấn công nhỏ (3 đến khoảng 20 kịch bản), thường tự dựng, và hiếm khi đo báo nhầm dưới workload benign thực tế. Tiêu chuẩn cao nhất trong nhóm đọc được là ReplicaWatcher (NDSS 2024): 13 kịch bản CVE/CWE thật trên 2 ứng dụng microservice, 30–50 user benign, 6 ngày snapshot, so với 3 baseline tái hiện. Bài SciTePress 2025 so Falco/Tetragon/Tracee chỉ với 3 tấn công (nsenter, stress-ng, xmrig), 20 lần lặp, không mô tả workload benign, và báo FPR 0 %.

### Cited Findings
**SciTePress 2025 — "Comparative Analysis of eBPF-Based Runtime Security Monitoring Tools in Monitoring and Threat Detection on Kubernetes"** (Aldien Asy Syairozi, Arizal; National Cyber and Crypto Polytechnic, Indonesia; metadata PDF ghi RITECH 2025) — [PDF](https://www.scitepress.org/Papers/2025/142727/142727.pdf)
- 3 cụm Kubernetes giống nhau trên DOKS (DigitalOcean), mỗi cụm 3 node 2 vCPU / 4 GB RAM / 80 GB disk, control plane do nhà cung cấp quản lý; mỗi cụm cài một tool (Falco, Tetragon hoặc Tracee); giám sát bằng Dynatrace.
- 3 tấn công lấy từ OWASP Kubernetes Top 10: container escape bằng `nsenter`, DoS bằng `stress-ng`, cryptomining bằng `xmrig` trong container bị chiếm; phát động từ một VPS; **mỗi kịch bản lặp 20 lần**.
- [Đo] MTTD: escape — Tetragon nhanh nhất 1,17822 s; DoS — Falco nhanh nhất 1,11985 s; cryptomining — Tetragon 0,420968 s, Falco và Tracee "trên một giây".
- [Đo] DR 100 % và FPR 0 % cho cả ba tool.
- [Đo] CPU baseline: Falco 431,5 mcore, Tetragon 6,5 mcore, Tracee 91,6 mcore; khi có tấn công: 433,5 / 6,9 / 93,7 mcore. Memory: Falco 392,08 MB khi có tấn công; Tracee 573,11 MB.

**ReplicaWatcher — "Training-less Anomaly Detection in Containerized Microservices"** (El Khairi, Caselli, Peter, Continella; NDSS 2024) — [PDF](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf); code [utwente-scs/ReplicaWatcher](https://github.com/utwente-scs/ReplicaWatcher) (GitHub API: không có license, 8 sao, push 08/12/2024)
- Hai nền tảng: ứng dụng e-commerce tự xây 7 microservice, mỗi service một công nghệ khác nhau, cài sẵn lỗ hổng từ thư viện phổ biến; và Google Online Boutique (GOB, bài viết nói 11 microservice) với 3 lỗ hổng tiêm thêm.
- **13 kịch bản**: Authentication Bypass (CWE-89, CWE-307 — Login); Information Disclosure (CVE-2019-5418, CVE-2018-3760 — Checkout; CVE-2017-14849 — Payment*); Remote Code Execution (CVE-2017-12636, CVE-2022-24706 — Product DB; File Inclusion — User Profile; CWE-502 — Recommendation*); Command Injection (CWE-434 — User Profile; CVE-2012-1823 — Login; CVE-2018-19518 — Signup; CVE-2014-6271 — Cart; CWE-78 — Shipping*); Privilege Escalation (CVE-2017-12635 — Product DB). (* = GOB.)
- Benign: chế độ normal có **30 đến 50 user**; chế độ attack có thêm một user là attacker. Số replica 2–6.
- Mỗi microservice bị tấn công: 1.000 snapshot normal + 250 snapshot attack, chia đều cho 5 cấu hình replica; snapshot 30 s; tổng **15.000 normal và 3.750 attack**, "six days of monitoring". Thu bằng Sysdig + chisel tuỳ biến. Máy GCP e2-standard-4 (4 vCPU, 16 GB) chạy Ubuntu.
- Nghiên cứu drift: GOB chạy 3 giờ, đổi .NET SDK 7.0.201 → 7.0.302 (cập nhật image) để tạo normality drift.
- Baseline tái hiện: STIDE-BoSC, CHIDS, CDL.
- [Đo] Precision trung bình 91,08 %, recall 98,35 % trên 13 kịch bản.
- Phạm vi đe doạ tự giới hạn: tấn công từ mạng; giả định attacker không tấn công đồng thời mọi replica; tự nhận giới hạn với brute-force và với exfiltration lén hơn.

**CHIDS** (El Khairi et al., ACM CCSW 2022): LID-DS 2019 (10 kịch bản) cộng **CB-DS** tự dựng với 10 kịch bản container breakout, tổng 20; đánh giá trace-level, 4-fold CV; AUC trung bình 99,97 % cho container breakout — [CHIDS PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf); code [Asbatel/ContainerHIDS](https://github.com/Asbatel/ContainerHIDS) (MIT, 26 sao, push 15/05/2023). Ghi chú: bản phát hành CB-DS mà dự án tải về chứa 9 × 99 recording attack (protocol `cbds-confirmation-v1` amendment 1, xem `validation-evidence/results-20261029/cbds/README.md`).

**Her et al., IEEE Access 2025** — so KubeArmor, Falco, Tetragon, Tracee; thiên về kiến trúc và cơ chế enforcement: KubeArmor và Tetragon có enforcement chủ động, Tracee và Falco thiên về audit [chỉ đọc snippet] — [PDF](https://cclab.info/papers/2025_her_access.pdf)

**Báo cáo vendor** (AccuKnox, "Container Runtime Security Comparative Insights 2025") là tài liệu của một vendor cạnh tranh, không phải đánh giá độc lập — [AccuKnox](https://accuknox.com/technical-papers/container-runtime-security-comparison)

**Phương pháp luận ML-in-security**: Arp et al., "Dos and Don'ts of Machine Learning in Computer Security" (USENIX Security 2022, Distinguished Paper) xác định các pitfall chung trong thiết kế/đánh giá hệ thống học máy cho bảo mật và khảo sát 30 bài ở hội nghị top trong 10 năm, kết luận các pitfall này phổ biến và có thể dẫn tới kết quả lạc quan sai — [arXiv 2010.09470](https://arxiv.org/abs/2010.09470)

### Inferences
- [Suy luận] Độ phủ trong các bài trên được lập luận theo **loại tác động** (ReplicaWatcher: 5 nhóm threat impact) hoặc theo **danh mục rủi ro** (SciTePress: OWASP K8s Top 10), không theo ma trận ATT&CK đầy đủ. Pulse có thể vượt mức này bằng một bảng tactic × technique ghi rõ "đã thử / phát hiện / không áp dụng cho syscall".
- [Suy luận] FPR 0 % của SciTePress không so được với Pulse: bài không mô tả workload benign, dùng rule-based tool, và báo nhầm chỉ được đo trong cửa sổ thử ngắn. Pulse đo báo nhầm trên 24 h với AIMS nên khắt khe hơn; điều này nên nói rõ khi so.
- [Suy luận] Cách ReplicaWatcher dựng tập tấn công (lỗ hổng thật trong các service đa công nghệ, attacker là "một user nữa" giữa traffic benign) là mẫu trực tiếp cho Pulse: đưa CVE thật vào một app thứ hai, tấn công qua đường mạng thay vì `kubectl exec`.
- [Suy luận] Năm fixture hiện tại của Pulse vào qua `kubectl exec` và chỉ dùng syscall hiếm; đây là kiểu "attack sẵn có tín hiệu" mà Arp et al. cảnh báo có thể làm kết quả lạc quan. 77,3 % trên LID-DS 2021 (exploit thật trong process dịch vụ) là số đại diện hơn.

### Gaps
- Không tìm thấy so sánh Falco/Tetragon/Tracee 2023–2026 ở venue bảo mật/hệ thống lớn có workload benign thực và đo báo nhầm dài hạn.
- Không đọc full text Her et al. 2025 (số attack, workload).
- Bài SciTePress không ghi rõ kernel/phiên bản tool trong phần đã trích; không xác nhận được.

## Q3. Workload benign thực tế: benchmark microservice, trace sản xuất, biến thiên traffic

### Takeaway
Benchmark microservice miễn phí phổ biến (Online Boutique, DeathStarBench, TrainTicket; Sock Shop đã archived) đều có Apache-2.0, nhưng văn liệu anomaly detection trên chúng gần như chỉ dùng log/metric/trace, không dùng syscall. Trace sản xuất Alibaba (2021, 2022) cho hình dạng tải thật nhưng có lỗi nhất quán đã được ghi nhận. Cách rẻ nhất để có traffic biến thiên suốt 24 h là dùng load generator với profile theo giờ lấy từ trace thật hoặc từ log web như LID-DS.

### Cited Findings
- **Online Boutique** (GoogleCloudPlatform/microservices-demo, Apache-2.0, 21.097 sao, push 27/10/2026): "10 microservices showcasing Kubernetes, Istio, and gRPC" — [repo](https://github.com/GoogleCloudPlatform/microservices-demo). ReplicaWatcher gọi là 11 microservice — [NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf) (chênh lệch có thể do cách đếm).
- **DeathStarBench** (delimitrou, Apache-2.0, 959 sao, push cuối **09/07/2024**) — [repo](https://github.com/delimitrou/DeathStarBench)
- **TrainTicket** (FudanSELab, Apache-2.0, 920 sao, push 21/11/2025) — [repo](https://github.com/FudanSELab/train-ticket)
- **Sock Shop** (microservices-demo/microservices-demo, Apache-2.0) **archived**, push cuối 05/12/2023 — [repo](https://github.com/microservices-demo/microservices-demo)
- Dataset anomaly trên các benchmark này đều ở mức log/metric/trace:
  - AnoMod (MSR 2026 data showcase): SocialNetwork (DeathStarBench) và TrainTicket, 4 loại anomaly, 5 modality kể cả code coverage, công bố trên Zenodo — [MSR 2026](https://2026.msrconf.org/details/msr-2026-data-and-tool-showcase-track/21/AnoMod-A-Dataset-for-Anomaly-Detection-and-Root-Cause-Analysis-in-Microservice-Syste)
  - TrainTicketTrace (SANER 2026): trace, metric, log từ TrainTicket dưới tải giả lập, một bản sạch và 9 bản có lỗi cài sẵn — [SANER 2026](https://conf.researchr.org/details/saner-2026/saner-2026-workshops-tutorials-track/43/TrainTicketTrace-A-Multi-Fault-Distributed-Dataset-for-Microservice-Fault-Detection-)
  - Eadro: TrainTicket và SocialNetwork, log/KPI/trace với lỗi tiêm — [arXiv 2302.05092](https://arxiv.org/pdf/2302.05092)
  - arXiv 2606.09942: Online Boutique, Sock Shop, TrainTicket trên Kubernetes, 100 ca fault injection mỗi hệ, metric qua Istio/Prometheus/cAdvisor — [arXiv 2606.09942](https://arxiv.org/pdf/2606.09942)
- **Alibaba microservice traces**: Luo et al., "Characterizing Microservice Dependency and Performance: Alibaba Trace Analysis", SoCC 2021, tr. 412–426; trace 2021 và 2022 gần 20.000 microservice, bản 2021 trong 12 giờ; dữ liệu công bố lấy mẫu 0,5 %, hơn 20 triệu trace. Huye et al. phát hiện bản 2021 có "numerous inconsistencies" khiến không dựng lại chính xác topology trace; bản 2022 cũng có nhưng ít hơn nhiều — [arXiv 2504.13141](https://arxiv.org/pdf/2504.13141); repo [alibaba/clusterdata](https://github.com/alibaba/clusterdata) (GitHub API: không khai license, 2.242 sao).
- **LID-DS 2021**: thời điểm request của user benign lấy mẫu từ log web server thật; thống kê tài nguyên mỗi giây — [Dataset Report](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf)
- **ReplicaWatcher**: 30–50 user benign đồng thời; drift tạo bằng cập nhật image (.NET SDK) — [NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)

### Inferences
- [Suy luận] Online Boutique là ứng viên tốt nhất cho "app thứ hai" của Pulse: Apache-2.0, còn bảo trì (push 10/2026), chạy được với Istio, đa ngôn ngữ (đa dạng runtime nên đa dạng hồ sơ syscall), và đã là nền tảng của ReplicaWatcher nên có điểm tham chiếu. DeathStarBench không push từ 07/2024; Sock Shop đã archived.
- [Suy luận] Để sửa giới hạn "biến thiên traffic chỉ 90 phút đầu": dùng load generator chạy suốt 24 h, số user theo profile ngày–đêm (ví dụ lấy hình dạng request-rate theo giờ từ trace Alibaba hoặc từ phân bố thời điểm request của LID-DS), cộng các sự kiện benign có lịch: rollout image (như drift .NET của ReplicaWatcher), scale replica, cronjob backup, `kubectl exec` quản trị. Ghi profile và seed để tái lập.
- [Suy luận] Vì chưa có dataset syscall nào trên các benchmark này, một bản ghi syscall công khai của Online Boutique dưới tải 24 h + tấn công có nhãn sẽ là đóng góp dataset nhỏ nhưng mới.

### Gaps
- Không kiểm trong phiên này load generator đi kèm Online Boutique (công cụ, tham số) và công cụ replay trace Alibaba; không tìm thấy công cụ replay chính thức.
- Không tìm thấy bài anomaly detection mức syscall nào dùng DeathStarBench hoặc TrainTicket.

## Q4. Baseline deep-learning syscall HIDS có code công khai và số đo trên LID-DS 2019/2021

### Takeaway
Hai baseline tái hiện được với code công khai và số đo đã công bố: (1) các decision engine trong thư viện LID-DS (GPL-3.0: AE, AE-TF, CNN, LSTM, MLP, OCSVM, SCG, SOM, STIDE, Torus-SOM) với số đo trên **LID-DS 2019** ở EISA 2021 (DR/FA, ngưỡng max-validation); (2) CHIDS (MIT, autoencoder trên đồ thị chuỗi syscall với feature argument) với P/R/F1 trace-level trên **LID-DS 2019** và CB-DS. Không tìm thấy bài Transformer hay LSTM nào có code công khai và số đo đầy đủ 15 kịch bản LID-DS 2021; các số LID-DS 2021 công bố đều là abstract-level, tập con kịch bản, đơn vị khác nhau.

### Cited Findings
**Thư viện LID-DS** — [repo](https://github.com/LID-DS/LID-DS), GPL-3.0 ([LICENSE](https://github.com/LID-DS/LID-DS/blob/master/LICENSE)), 60 sao, push 29/08/2026
- `algorithms/decision_engines/`: `ae.py`, `aetf.py`, `cnn.py`, `lstm.py`, `mlp.py`, `ocsvm.py`, `scg.py`, `som.py`, `stide.py`, `torus_som.py`; script `ids_ae_main.py`, `ids_lstm_main.py`, `ids_mlp_main.py`, `ids_som_main.py`, `ids_torus_som_main.py`, `run_experiments.py` — [algorithms/](https://github.com/LID-DS/LID-DS/tree/master/algorithms)
- `LSTM` mặc định `epochs=300`, `batch_size=1` — [lstm.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/decision_engines/lstm.py). `AE_TF` (Keras, `batch_size=256`, `epochs=1000`) có chú thích "I used this to check our AE results - its seems booth have similar results" — [aetf.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/decision_engines/aetf.py)
- Loader hợp nhất hỗ trợ LID-DS-2019, LID-DS-2021, ADFA-LD, CTF (WRTD), scap (CB-DS) — [README](https://github.com/LID-DS/LID-DS)
- **Định nghĩa metric (code)**: ngưỡng = điểm anomaly lớn nhất trên validation (chỉ normal); DR = số recording exploit có ít nhất một alarm ở hoặc sau thời điểm exploit đầu tiên / số recording exploit; false alarm gộp thành chuỗi liên tiếp (CFA) trong recording normal và phần trước exploit; `precision_with_cfa = alarm_count / (alarm_count + cfp_normal + cfp_exploits)`; `f1_cfa` từ precision_cfa và DR — [performance_measurement.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/performance_measurement.py); [ids.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/ids.py)
- **Số đo trên LID-DS 2019** (Grimmer, Kaelble, Rahm, EISA 2021): 7 thuật toán (BOSC, STIDE, SCG, OCSVM, MLP, CNN, AE), n-gram ID syscall (OHE hoặc word2vec), có/không thread information (TI), hơn 30.000 cấu hình grid search; split 2019: 200 normal train, 50 normal validation, còn lại là test; t′attack = tattack − 2 s. [Đo] STIDE/BOSC có TI: DR 0,986 với 61,5 / 110,4 FA mỗi kịch bản; MLP có TI (n = 7, l = 1): DR 0,789, FA 4,2; AE có TI: FA 2,2, DR khoảng 0,62; CNN đạt 0,99 / 4 FA ở CVE-2017-7529; TI nâng Heartbleed từ 0,06 (MLP, không TI) lên 0,95 (STIDE) — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf) (tổng hợp lại trong `research_notes/Cải thiện Pulse trên LID DS/published_results.md`). Cấu hình tốt nhất được chọn sau khi nhìn kết quả test, nên là cận trên lạc quan.
- Ví dụ tham chiếu LID-DS 2021 trên wiki: STIDE 7-gram, CVE-2017-7529, DR 1,0 (119/119), CFA normal 5, precision_with_cfa 0,9597, f1_cfa 0,9794 — [wiki ids_example](https://github.com/LID-DS/LID-DS/wiki/ids_example)

**CHIDS** — code [Asbatel/ContainerHIDS](https://github.com/Asbatel/ContainerHIDS) (MIT; thư mục `chids/`, `datasets/`, `figures/`, `requirements.txt`, `setup.py`), bài [CCSW 2022](https://conand.me/publications/elkhairi-ccsw-2022.pdf)
- Tiền xử lý: chia syscall thành "scap" τ = 1 s, dựng đồ thị chuỗi syscall, ba feature USI (syscall chưa thấy), UAI (argument chưa thấy), FI (tần suất, chặn trên β = 5) đưa vào autoencoder; ngưỡng D_thresh = γ × max lỗi tái tạo train, γ = 1,4 "empirically define"; 4-fold CV; một trace là độc nếu một sequence độc.
- [Đo] LID-DS 2019 trace-level P / R / F1, ví dụ: CVE-2017-7529 0,9946 / 0,9885 / 0,9915; CVE-2019-5418 0,9986 / 0,9989 / 0,9987; ZipSlip 0,9881 / 0,9987 / 0,9934; CVE-2012-2122 0,9983 / 0,7935 / 0,8842; CWE-307 0,9942 / 0,9183 / 0,9547; Heartbleed không có trong bảng (tác giả ghi là thất bại). CDL tái hiện (autoencoder trên vector tần suất) recall 0,0057 / 0,0102 / 0,1224 ở CVE-2017-7529 / CVE-2019-5418 / ZipSlip.

**ReplicaWatcher** — code công khai nhưng không có license file, số đo trên dataset riêng (không phải LID-DS); tái hiện CHIDS, CDL, STIDE-BoSC — [NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf); [repo](https://github.com/utwente-scs/ReplicaWatcher)

**Các ứng viên khác đã kiểm, không đạt điều kiện "code + số công bố trên LID-DS"**
- Transformer với phân loại syscall (Bortolini, Obelheiro, Maziero; SBSeg 2025, bài ngắn): F1 0,90 so với 0,92 của mô hình gốc, giảm hơn 86 % thời gian chạy, nhưng **chỉ trên ADFA-LD**, không nêu code — [SBSeg 2025 PDF](https://sol.sbc.org.br/index.php/sbseg/article/download/36676/36463)
- Decoder-only transformer có giải thích (Helsinki): đánh giá trên DongTing, ADFA-LD, PLAID, không phải LID-DS — [PDF](https://haic.fi/wp-content/uploads/2026/05/Explainable-Anomaly-Detection-in-System-Call-Sequences.pdf)
- TextRank + RF/LSTM/CNN+LSTM/BiLSTM/CNN+BiGRU (Electronics 15(9):1856, 2026): LID-DS 2021, chỉ 3 kịch bản đại diện (bỏ 6 kịch bản multi-stage), split cùng kịch bản theo file, F1 0,90–0,94 (DL), 0,55–0,63 (RF); không xác nhận code — [DOI 10.3390/electronics15091856](https://doi.org/10.3390/electronics15091856)
- Guo, DSAI 2024: autoencoder trên đồ thị ngữ cảnh đầy đủ (syscall, tên process, TID, giá trị trả về, tham số), "LID-DS across 13 scenarios, … approximately 14,950 samples", accuracy trung bình 96,8 %, F1 97,7 % (abstract) — [DOI 10.1145/3677892.3677893](https://doi.org/10.1145/3677892.3677893)
- Repo cá nhân `swarajjoshi10-ship-it/host-based-instrusion-detection` (không license, 0 sao, tạo 21/10/2026): so Isolation Forest, OCSVM, autoencoder, LSTM next-call trên ADFA-LD và LID-DS 2021, ngưỡng p99 trên normal; README thừa nhận chính sách hai ngưỡng được chọn "after seeing borderline kills" — [repo](https://github.com/swarajjoshi10-ship-it/host-based-instrusion-detection). Repo `AkshatKapur1/AAR-System-Call-Anomaly-Detection` (không license, 0 sao) — [repo](https://github.com/AkshatKapur1/AAR-System-Call-Anomaly-Detection). Cả hai không phải công bố có bình duyệt.
- Rhodes University MSc 2023: NLP trên trace LID-DS với Random Forest/Isolation Forest + PCA, không phải DL sequence — [repository](https://researchrepository.ru.ac.za/handle/20.500.14915/3571)

### Inferences
- [Suy luận] Baseline DL rẻ và bảo vệ được nhất cho luận văn: chạy **MLP và LSTM của thư viện LID-DS** trên đúng split cố định của LID-DS 2021, đúng `MaxScoreThreshold` và `performance_measurement.py`, báo DR, CFA, precision_with_cfa, f1_cfa theo từng kịch bản. Như vậy cùng tiền xử lý, cùng định nghĩa metric với STIDE mà dự án đã chạy, và không phụ thuộc mã của bên thứ ba thiếu license. Phải ghi rõ đây là "tái hiện engine của thư viện trên 2021", không phải số đã công bố, vì nhóm Leipzig chưa công bố số MLP/LSTM trên 2021.
- [Suy luận] Baseline thứ hai: **CHIDS** (MIT) trên LID-DS 2019 để kiểm việc tái hiện (so với Table 4 đã công bố) rồi trên LID-DS 2021 và CB-DS. CHIDS dùng feature argument, đúng loại tín hiệu Pulse đang thiếu ở ZipSlip/CVE-2019-5418, nên là đối chứng có thông tin. Cần chuyển metric trace-level của CHIDS sang recording-level DR/CFA để cùng trục.
- [Suy luận] Chi phí: LSTM mặc định `batch_size=1`, `epochs=300` trên các kịch bản LID-DS 2021 hàng trăm triệu syscall có thể rất chậm trên CPU; nên giữ tham số mặc định cho kịch bản nhỏ và đăng ký trước cách giảm (subsample train) nếu phải.

### Gaps
- Không tìm thấy Transformer/LSTM HIDS bình duyệt nào có code công khai và số đầy đủ 15 kịch bản LID-DS 2021.
- Chưa mở README/requirements của CHIDS (README nhánh `main` trả 404); chưa biết phiên bản Python/TF cần và lệnh chạy chính xác.
- Không có số MLP/LSTM/CNN chính thức trên LID-DS 2021 từ nhóm Leipzig.

## Q5. External validity và gán nhãn: nhiều kernel/distro, reviewer độc lập, kappa, red/blue mù; kế hoạch an toàn cho Pulse

### Takeaway
Không tìm thấy nghiên cứu overhead eBPF qua nhiều phiên bản kernel; các nghiên cứu hiện có đo trên một kernel (ví dụ Linux 6.1) hoặc so hai phiên bản. Mẫu gán nhãn có reviewer thứ hai và Cohen's κ có tồn tại (SIR-Bench: κ = 0,87), nhưng chính các bài dùng κ cũng cảnh báo rằng người gán nhãn là tác giả thì chỉ là kiểm tra giới hạn. Không tìm thấy bài học thuật về detector container dùng bài tập red/blue mù; Pulse có thể làm một bản nhỏ, chi phí thấp.

### Cited Findings
- arXiv 2608.11418 "A Study of Kernel Telemetry Options for Security-Oriented Provenance": đo overhead bắt dữ liệu eBPF qua các loại program tracepoint, kprobe, fentry/tracing, LSM; host Debian 12, Linux 6.1.0-amd64 (một kernel); overhead = tăng CPU time tương đối giữa workload có trace và baseline không trace — [arXiv 2608.11418](https://arxiv.org/pdf/2608.11418)
- Cloudflare, LPC 2020: ước lượng chi phí tail call ở hai kernel 5.4 và 5.5 (thay đổi retpoline ở 5.5); chỉ đọc abstract — [LPC 2020](https://lpc.events/event/7/contributions/676/)
- Craun et al. (eBPF workshop 2024): cả ba cách tiếp cận đều gây overhead lớn lên **process không bị trace** — [VTechWorks](https://vtechworks.lib.vt.edu/items/45dbacb6-99e0-4a97-9d4b-ec71926e4137)
- Piotrowski: phương pháp benchmark overhead DTrace (FreeBSD) và eBPF (Linux) — [BSDCan 2023](https://papers.freebsd.org/2023/bsdcan/piotrowski-performance_analysis_of_dtrace_on_freebsd_and_ebpf_on_linux/)
- Gán nhãn kép: SIR-Bench — một kỹ sư gán nhãn, người thứ hai review, bất đồng (khoảng 8 % ca) giải quyết bằng thảo luận; đồng thuận triage (true vs false positive) 94,2 %, **κ = 0,87**; tập phát hiện mới trùng trung bình 81,3 % Jaccard — [arXiv 2604.12040](https://arxiv.org/pdf/2604.12040)
- Bài ICS: hai người gán nhãn cửa sổ độc lập, κ = 0,978, nhưng cả hai là tác giả nên tự nhận đây là kiểm tra hợp lý "limited rather than an independent validation" — [arXiv 2606.30493](https://arxiv.org/pdf/2606.30493)
- Định nghĩa κ = (p_o − p_e) / (1 − p_e); ví dụ dữ liệu lệch 95/5: bộ phân loại luôn đoán lớp đa số có accuracy 0,95 nhưng κ = 0 — [permetrics CKS](https://permetrics.readthedocs.io/stable/pages/classification/CKS.html)
- Ước lượng metric khi không có ground truth (malware) là hướng bổ sung cho review thủ công — [arXiv 1810.07260](https://arxiv.org/pdf/1810.07260)
- Arp et al. (USENIX Security 2022): pitfall về dữ liệu/nhãn và đánh giá phổ biến trong 30 bài top-tier — [arXiv 2010.09470](https://arxiv.org/abs/2010.09470)

### Inferences
**Kế hoạch cụ thể và an toàn cho Pulse** [Suy luận; mọi bước dùng công cụ miễn phí; không bước nào là fault test hạ tầng; không chạy song song với một live run/soak đang đo]

1. **Namespace thử cô lập** `pulse-redteam` (và `pulse-victim2`): ServiceAccount riêng, Role chỉ trong namespace (không ClusterRole), Pod Security Admission `restricted` cho mọi pod attacker trừ khi kịch bản cần khác; CiliumNetworkPolicy chặn egress ra ngoài cụm và tới namespace AIMS, chỉ cho attacker → victim; ResourceQuota/LimitRange (CPU/RAM) để DoS/miner không ảnh hưởng AIMS; xoá namespace ngay sau mỗi đợt (theo quy tắc resource hygiene).
2. **Tầng A — giữ 5 fixture** làm positive control (so sánh với các đợt trước).
3. **Tầng B — hành vi post-exploitation trong container (mức syscall)**: ART T1046, T1069.001, T1105, T1136.001, T1053.002; `cdk evaluate --full`; CDK `service-probe`, `istio-check`, `k8s-secret-dump`, `k8s-configmap-dump`, `k8s-get-sa-token` với SA giới hạn; Peirates với SA giới hạn; Falco `event-generator run syscall` (không `--all`, không `--loop`) trong pod; miner chạy giới hạn CPU, không kết nối pool. Phủ thêm Discovery, Credential Access, Execution, Persistence (trong container), Command and Control, Impact (resource hijacking).
4. **Tầng C — exploit thật vào process dịch vụ (initial access/execution)**: triển khai 4–6 service dễ bị tấn công trong `pulse-victim2`, ưu tiên các CVE có cả ở LID-DS 2021 và ReplicaWatcher (CVE-2019-5418, CVE-2018-3760, CVE-2017-12635/12636, CWE-89, CWE-307, CWE-434), port từ mã kịch bản LID-DS (GPL-3.0, giữ ba vai attacker/victim/user) hoặc ảnh Vulhub (MIT); attacker là pod trong cùng namespace, gửi exploit qua mạng giữa traffic benign. Đây là cầu nối trực tiếp giữa số offline 77,3 % và số live.
5. **Tầng D — escape**: không chạy trên cụm live. Dùng CB-DS offline (đã đăng ký); nếu cần live, dựng một VM/kind dùng-một-lần tách mạng, chạy CDK escape module + ART T1611, xoá sau đó.
6. **App thứ hai**: Online Boutique trong namespace riêng với load generator chạy suốt 24 h theo profile ngày–đêm (seed cố định), cộng sự kiện benign có lịch: rollout image, scale replica, `kubectl exec` quản trị bằng binary vô hại (giữ lớp negative "benign binary").
7. **Kernel thứ hai**: một worker VM tạm với kernel khác (ví dụ Ubuntu 22.04 kernel 5.15 hoặc HWE mới hơn 6.8) chỉ để đo: BPF verifier load thành công, overhead CPU/latency theo cách tương đối của arXiv 2608.11418, và FPR trên cùng workload; báo như kiểm tra portability, không phải đánh giá đầy đủ.
8. **Gán nhãn và mù**: một người (không phải người phân tích) sinh lịch tấn công ngẫu nhiên (thời điểm, kịch bản) và giữ kín; người phân tích gán nhãn mọi alert (TP / FP / không rõ) trước khi mở lịch; reviewer thứ hai độc lập gán nhãn một mẫu ngẫu nhiên phân tầng (ví dụ ≥ 100 alert gồm cả FP và TP); báo % đồng thuận và Cohen's κ, và ghi rõ nếu reviewer có liên quan tới dự án (giới hạn như bài ICS ở trên). Đăng ký trước protocol như các protocol hiện có.
9. **Báo độ phủ**: bảng ATT&CK for Containers tactic × technique với ba trạng thái (đã thử–phát hiện / đã thử–trượt / ngoài tầm syscall như audit-log-only), số lần lặp mỗi technique (SciTePress dùng 20), và MTTD từ kernel đến alert để so với mục tiêu ≤ 2–3 s.

### Gaps
- Không tìm thấy nghiên cứu overhead eBPF nhiều kernel/distro; không có số chuẩn để so.
- Không tìm thấy bài đánh giá detector container/HIDS học thuật có bài tập red-team/blue-team mù hay κ giữa reviewer cho nhãn alert syscall.
- Bài CHEOPS 2026 về overhead eBPF tới 41 % ở I/O nhỏ đồng thời cao chỉ được thấy qua blog vendor, chưa kiểm — [groundcover](https://www.groundcover.com/guides/ebpf-monitoring-performance-overhead)
