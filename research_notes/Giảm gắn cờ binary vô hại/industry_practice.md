# Thực tiễn ngành và mã nguồn mở: cách công cụ runtime-security cho container tách process mới vô hại (kubectl exec, cron, probe, cập nhật gói) khỏi process độc hại

Phạm vi và cách làm. Khảo sát ngày 30/10/2026, nguồn web miễn phí. Mỗi dòng trong "Cited Findings" lấy từ trang hoặc file đã mở thật trong phiên này. Riêng các dòng gắn **[Snippet]** chỉ thấy qua đoạn trích của công cụ tìm kiếm, chưa mở toàn văn. Mã nguồn mở (Falco rules, Tetragon proto, Datadog agent) được tải bằng `curl` từ nhánh `main` ngày 30/10/2026 và đọc trực tiếp.

Nhãn dùng trong file:
- **[Docs hãng]**: tài liệu chính thức của nhà cung cấp. Mô tả cơ chế, không phải số đo độc lập.
- **[Tuyên bố hãng]**: tuyên bố tiếp thị hoặc định tính của hãng.
- **[Mã nguồn]**: đọc trực tiếp từ code hoặc rule mã nguồn mở. Đây là hành vi thật của phần mềm tại commit `main` ngày 30/10/2026.
- **[Độc lập]**: bài báo hoặc đánh giá bên thứ ba.
- Mục "Inferences" là suy luận của người viết, không phải kết quả đo.

Sản phẩm trả phí (Sysdig Secure, Defender for Containers, Prisma Cloud, NeuVector bản hãng, Aqua, Datadog SaaS, GuardDuty, GKE CTD) chỉ dùng để so sánh. Mọi đề xuất triển khai ở Q6 chỉ dùng công cụ miễn phí và mã nguồn mở.

Bối cảnh Pulse do coordinator cung cấp, không phải nguồn web: một binary vô hại chạy qua `kubectl exec` (chỉ gọi `getpid`) bị Pulse gắn cờ ở 86–95 % số lần thử. Rule "tripwire" (syscall ID chưa từng có trong profile) gần như không báo nhầm. Falco với rule mặc định: phần lớn cảnh báo lúc bình thường đến từ "Unexpected connection to K8s API Server from container", còn drift detection chỉ kêu trên 10/65 container (overlayfs).

---

## Q1. Drift / immutability controls: làm sao quyết định một binary "thuộc image", cấu hình thế nào, có gap và false positive gì

### Takeaway
Mọi drift control công khai cơ chế đều dựa vào **nguồn gốc file** (file được tạo hoặc sửa sau khi container khởi động, trên thực tế là nằm ở upper layer của overlayfs), không dựa vào hành vi. Không tài liệu nào được đọc mô tả việc so hash từng file với manifest của image. Vì vậy drift **không kêu** khi một binary đã có sẵn trong image được chạy qua `kubectl exec`. Drift cũng bỏ sót script chạy bằng interpreter có sẵn (LOTL) và code chạy từ volume. Mặc định của hãng rất dè dặt: Defender để default rule là *Ignore*, GKE tắt detector mặc định, hai rule drift cũ của Falco bị `enabled: false`, còn GuardDuty chỉ phát finding cho "suspicious instances".

### Cited Findings
**Falco (mã nguồn mở, CNCF)**
- **[Mã nguồn]** Rule `Drop and execute new binary in container` (stable, priority **CRITICAL**) có điều kiện `spawned_process and container and proc.is_exe_upper_layer=true and not container.image.repository in (known_drop_and_execute_containers) and not known_drop_and_execute_activities`. Mô tả rule ghi: "is_exe_upper_layer filter field only applies for container runtimes that use overlayfs". Rule cũng gợi ý allowlist theo image hoặc loại namespace non-prod, và nêu: "Common anti-patterns include administrators or SREs performing ad-hoc debugging." Output có `proc_exe_ino_ctime`, `ctime_duration_proc_start`, `container_start_ts` để phân tích. File yêu cầu `required_engine_version: 0.57.0`. — [falco_rules.yaml (main, 30/10/2026)](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- **[Docs hãng]** Định nghĩa các trường: `proc.is_exe_upper_layer` là "'true' if this process' executable file is in upper layer in overlayfs"; `proc.is_exe_from_memfd` là "executable file … is an anonymous file created using memfd_create()"; `proc.is_exe_writable` là executable ghi được bởi chính user spawn nó; `proc.exe_ino.ctime_duration_proc_start` là "Number of nanoseconds between modifying status of executable image and spawning a new process". — [Falco supported fields](https://falco.org/docs/reference/rules/supported-fields/)
- **[Mã nguồn]** Hai rule drift đời cũ `Container Drift Detected (chmod)` và `Container Drift Detected (open+create)` (sandbox, ERROR) đều `enabled: false`. Comment trong file: "'docker cp' will not be identified" và "Drift rules will be noisy in environments in which containers are built (e.g. docker build)". Rule chmod tự nhận "can generate significant noise" và khuyên dùng rule upper-layer mới vì nó dùng "unambiguous kernel signals". — [falco-sandbox_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml)
- **[Mã nguồn]** Rule `Launch Package Management Process in Container` (incubating, ERROR) được mô tả là "excellent auditing rule to monitor general drifts" và "helps identify common anti-patterns of ad-hoc debugging". Rule loại trừ `user.name != "_apt"` và tổ tiên là package manager. — [falco-incubating_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml)

**Microsoft Defender for Containers (trả phí)**
- **[Docs hãng]** "Binary drift happens when a container runs an executable that didn't come from the original image." Policy gồm các rule có thứ tự ưu tiên (first match wins). Scope theo cloud, container name, image name, namespace, pod labels, pod name, cluster name, với toán tử starts/ends/equals/contains. Mỗi rule có "Allow list for processes", và process ngoài danh sách thì sinh alert. Có ba action: alert, blocking, ignore. Rule "Default binary drift" mặc định là **Ignore drift detection**; rule mẫu "Alert on Kube-System namespace" có sẵn. Alert có độ nghiêm trọng high. Sensor nhận policy mới trong vòng 30 phút. Blocking cần sensor ≥ 0.10.2. Tài liệu ghi "remove rules that generate too many false positives" nhưng không đưa ra số FP. Trang không nói cách xác định "came from the original image". Ngày tài liệu: ms.date 03/07/2026, cập nhật 08/08/2026. — [Microsoft Learn: Binary drift detection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/binary-drift-detection)

**Sysdig Secure (trả phí)**
- **[Docs hãng]** Drift là binary "not part of the container's original image". Có các tùy chọn: *Binary Drift* (event), *Prevent Execution* (kernel ≥ 5.0 chặn trước khi chạy, kernel < 5.0 kill sau khi phát hiện), *Volume Drift* (coi mọi binary từ volume là drift), exceptions theo full path (string/regex), process-based exceptions, "Prohibited Binaries" (chặn cả binary có sẵn trong image). Policy chỉ áp cho container, không áp cho host. Tài liệu ghi: "Auto-tuning is not used, so false positives should be reduced through Scope". Notification mặc định giới hạn khoảng 1 lần / 5 phút. — [Sysdig docs: Drift Detection policy](https://docs.sysdig.com/en/sysdig-secure/drift_policy/)
- **[Docs hãng]** Mục Known Limitations nêu ba gap. (1) "Drift detections tracks the execution of binaries that were not part of the original image", nên script chạy bằng interpreter có sẵn (ví dụ Python) không bị gắn cờ. (2) "As the Drift Detection policy uses overlays for detection, execution from persistent volumes is not considered 'drifted.'" (3) Kernel < 5.13 chỉ theo dõi tối đa 128 container/node. — [Sysdig docs: Drift Detection policy](https://docs.sysdig.com/en/sysdig-secure/drift_policy/)
- **[Snippet][Tuyên bố hãng]** Thông cáo ra mắt Drift Control tháng 6/2022 mô tả tính năng là chặn động các executable không có trong image gốc. — [BusinessWire 28/06/2022](https://www.businesswire.com/news/home/20220628005539/en)

**AWS GuardDuty Runtime Monitoring (trả phí)**
- **[Docs hãng]** `Execution:Runtime/NewBinaryExecuted` (Medium): "A newly created or recently modified binary file in a container has been executed." Finding có chi tiết `modifyingProcess`, tức process đã ghi file, trong ví dụ là `/usr/bin/dpkg`. Tài liệu nói thẳng: "it is also a common usage pattern. Therefore, GuardDuty uses mechanisms to identify suspicious instances of this activity and generates this finding type only for suspicious instances." Cơ chế lọc này không được công bố. `Execution:Runtime/NewLibraryLoaded` có logic tương tự cho thư viện. — [GuardDuty Runtime Monitoring finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html)

**Google GKE Container Threat Detection (trả phí, SCC Premium/Enterprise)**
- **[Docs hãng]** `Added Binary Executed` và `Added Library Loaded` (Low) bắt binary "was not part of the original container image" hoặc "was modified from the original container image". Cả hai nằm trong nhóm "disabled by default". Trang không bàn về FP. Giới hạn được nêu: thông tin container gửi kèm theo kiểu best effort và "can be dropped from the reported finding". — [GKE Container Threat Detection overview](https://docs.cloud.google.com/security-command-center/docs/concepts-container-threat-detection-overview)

**Aqua (trả phí; Tracee là bản mở của Aqua)**
- **[Snippet][Docs hãng]** Drift Prevention "Enforces container immutability and detects any unapproved changes to running containers by continuously comparing them to their originating images". — [Aqua: cloud workload security](https://aquasec.com/use-cases/cloud-workload-security)
- **[Snippet]** Trong lab AWS workshop của Aqua, một bản sao của `ls` đổi tên thành `list` bị chặn vì là drift. Đổi tên không lách được drift vì bản sao nằm ở upper layer. — [Aqua AWS workshop: Drift Prevention](https://aqua.awsworkshop.io/runtime_security/drift_prevention.html)

**NeuVector (SUSE, mã nguồn mở)**
- **[Docs hãng]** Chế độ process profile "Zero-drift" là mặc định ở bản ≤ 5.6.0. Zero-drift cho phép các process sinh ra từ parent process gốc của image và chặn cài file mới hoặc sửa file. Chế độ này không cần allow-list đã học. Từ 5.6.1, deployment mới mặc định chế độ "Basic", chỉ dựa vào process/file rules. SUSE khuyên đặt namespace hệ thống (kube-system) ở Basic và pod ứng dụng ở zero-drift. — [NeuVector: Process profile rules](https://open-docs.neuvector.com/policy/processrules)

**Tetragon (Cilium/Isovalent, mã nguồn mở)**
- **[Mã nguồn]** Trong `tetragon.proto`, `BinaryProperties` chỉ có `setuid`, `setgid`, `privileges_changed` và `file`. Trường `file` chỉ được điền khi binary là shm ẩn danh, file `memfd_create`, hoặc file đã bị xóa khỏi filesystem. Proto **không có** trường kiểu "upper layer"/"overlay": grep `upper|overlay` không trả về kết quả nào. — [tetragon.proto (main, 30/10/2026)](https://github.com/cilium/tetragon/blob/main/api/v1/tetragon/tetragon.proto)

**Cơ chế nền (overlayfs)**
- **[Snippet]** overlay2 xếp các layer image read-only làm lowerdir và một upperdir ghi được cho mỗi container. Sửa một file vốn chỉ có ở lower layer sẽ kích hoạt copy-up lên upper layer. — [Docker docs: OverlayFS driver](https://docs.docker.com/storage/storagedriver/overlayfs-driver)
- **[Snippet]** Một bản patch trên danh sách LSM (01/2026) ghi nhận vấn đề TOCTOU: kiểm tra exec có thể pass trên file ở lower layer, rồi một lần ghi sau đó copy-up file đó. — [LSM archive 01/2026](https://kernsec.org/pipermail/linux-security-module-archive/2026-January/055077.html)

### Inferences
- Tín hiệu cốt lõi của drift là "executable ở upper layer hoặc ctime sau khi container start". Tín hiệu này chỉ trả lời câu hỏi "binary có được thêm vào sau không", không trả lời "process có độc hại không". Với kịch bản Pulse (binary vô hại chỉ gọi `getpid`, chạy qua `kubectl exec`), drift chỉ kêu nếu binary đó được `kubectl cp` hoặc ghi vào container, khi đó nó nằm ở upper layer. Nếu binary vô hại có sẵn trong image thì drift im lặng. Cả hai trường hợp đều không phân biệt được ý đồ: drift tách theo *nguồn gốc*, không theo *độc hại*.
- Việc Falco drift chỉ kêu trên 10/65 container khớp với hai giới hạn được ghi trong tài liệu: chỉ áp cho overlayfs, và chỉ kêu khi executable thực sự ở upper layer (interpreter có sẵn thì không). Cần kiểm chứng trên dữ liệu lab của Pulse xem 55 container còn lại có phải là trường hợp chạy binary có sẵn trong image không.
- Mặc định "ignore", "disabled" hoặc "chỉ suspicious instances" ở Defender, GKE và GuardDuty cho thấy chính các hãng coi drift thô là quá ồn để bật alert mặc định. Đây là suy luận từ cấu hình mặc định, không có số FP đi kèm.

### Gaps
- Không hãng nào công bố số FP hoặc tỉ lệ alert của drift detection. GuardDuty không công bố cơ chế lọc "suspicious instances".
- Defender, Aqua và GKE không nói rõ "thuộc image" được kiểm bằng overlay layer, ctime hay hash. Sysdig nói rõ "uses overlays". Chỉ Falco có code công khai.
- Datadog Workload Protection có drift (theo tên event) nhưng không tìm được trang tài liệu mô tả cơ chế.
- Không tìm thấy nghiên cứu độc lập đo FP hoặc FN của `proc.is_exe_upper_layer` trên workload thật.

---

## Q2. Behavioural process baselining / learning mode: học bao lâu, xử lý process mới vô hại thế nào, có số FP không

### Takeaway
Các sản phẩm baselining đều học **allow-list process theo image** (tên + đường dẫn, đôi khi kèm cây cha–con). Thời gian học ngắn: Datadog mặc định 15 phút ổn định + 3 phút warm-up, Prisma khoảng 1 giờ + 24 giờ dry-run, NeuVector "vài giờ đến vài ngày". Process mới sau khi học bị báo như một *sự kiện lệch profile* chứ không chấm điểm dị thường theo tần suất. Hai cách giảm ồn là tự học thêm (Prisma "alert once then add", Datadog auto-suppression) và tự cho phép probe (NeuVector). **Không tìm thấy số FP công bố** nào đáng tin. Đánh giá độc lập duy nhất (SciTePress 2025) báo 0 % FPR mà không mô tả workload vô hại.

### Cited Findings
**Datadog Workload Protection: agent mã nguồn mở (Apache-2.0), cấu hình mặc định đọc trực tiếp**
- **[Mã nguồn]** Mặc định trong `system-probe-cws.yaml`:
  - `activity_dump.dump_duration: 900s` (pha học cgroup, tối thiểu 10 phút), `traced_cgroups_count: 5`.
  - `security_profile.enabled: true`, `max_image_tags: 20` (mỗi profile giữ tối đa 20 phiên bản tag image), `max_count: 400`.
  - `anomaly_detection.enabled: true`, `event_types: [exec]`: chỉ sự kiện exec sinh anomaly mặc định.
  - `minimum_stable_period.exec: 900s` và `.dns: 900s`, `workload_warmup_period: 180s`, `unstable_profile_time_threshold: 1h`, `unstable_profile_size_threshold: 5000000`.
  - `rate_limiter`: 2000 sự kiện / 1 s / 256 key.
  - `auto_suppression.enabled: true`, `event_types: [exec, dns]`.

  — [datadog-agent: system-probe-cws.yaml](https://github.com/DataDog/datadog-agent/blob/main/pkg/config/schema/yaml/system-probe-cws.yaml)
- **[Mã nguồn]** Ý nghĩa các khóa trên, theo comment trong code. "minimum amount of time during which the events that diverge from their profiles are automatically added in their profiles without triggering an anomaly detection event". "WorkloadWarmupPeriod defines the duration we ignore the anomaly detections for because of workload warm up". "UnstableProfileTimeThreshold … maximum amount of time to wait until a profile that hasn't reached a stable state is considered as unstable". `AnomalyDetectionSilentRuleEventsEnabled`: "do not send rule event if also part of an anomaly event". — [datadog-agent: pkg/security/config/config.go](https://github.com/DataDog/datadog-agent/blob/main/pkg/security/config/config.go)
- **[Mã nguồn]** Mỗi node trong cây hoạt động được gắn `GenerationType`: `runtime`, `snapshot`, `profile_drift` ("added because of a drift from a security profile") hoặc `workload_warmup`. Hàm `isValidRootNode` bỏ qua `runc*` và `containerd-shim*` khi chọn gốc cây, nên process do runtime spawn được treo dưới gốc riêng. — [activity_tree.go](https://github.com/DataDog/datadog-agent/blob/main/pkg/security/security_profile/activity_tree/activity_tree.go)
- **[Mã nguồn]** Thư mục activity tree có `syscalls_node.go`, tức profile có lưu tập syscall theo process. — [datadog-agent security_profile/activity_tree](https://github.com/DataDog/datadog-agent/tree/main/pkg/security/security_profile/activity_tree)
- **[Docs hãng]** Workload Protection có "over 350 agent rules and 200 detection rules", bao phủ hơn 40 loại event. — [Datadog runtime anomaly detection / Workload Protection](https://docs.datadoghq.com/security/threats/runtime_anomaly_detection)

**Prisma Cloud (Twistlock), trả phí**
- **[Docs hãng]** Mỗi model ứng với 1 image digest; trong K8s, model tách theo cluster và namespace. Model kết hợp phân tích tĩnh (ví dụ parse script ENTRYPOINT) và học động. Các pha:
  - **Learning** khoảng 1 giờ tích lũy. Trong pha này chỉ log sự kiện dựa trên threat (file độc, IP rủi ro).
  - **Dry run 24 giờ**. Có thay đổi hành vi thì quay lại Learning thêm 24 giờ.
  - **Active**: model thành allow-list. Chỉ tự quay lại Learning được trong 24 giờ đầu.
  - **Archived** sau 24 giờ không còn container dùng model.

  Có bốn action: Disable, Alert, Prevent (chỉ dừng process vi phạm), Block (dừng cả container). Khi "Extended behavioral models" bật, hoạt động sau pha học "judged low likelihood of being malicious is alerted once, then added to the model". Có detection "Processes started from modified binaries". Có thể chủ động "Extend Learning" hoặc "Manual Learning". Trang không bàn về FP. — [Prisma Cloud: Runtime defense for containers](https://docs.prismacloud.io/admin-guide/runtime-defense/runtime-defense-containers)

**NeuVector (SUSE, mã nguồn mở)**
- **[Docs hãng]** Chế độ **Discover** học baseline process cho từng service và tạo whitelist rule. **Monitor** không học thêm mà báo vi phạm. **Protect** chặn. Thời gian học: "Several hours should be sufficient, but some applications may require a few days to be fully exercised". Khuyến nghị: qua Monitor, đổi vi phạm hợp lệ thành whitelist rồi mới sang Protect. — [NeuVector: Modes](https://open-docs.neuvector.com/policy/modes)
- **[Docs hãng]** Rule học được gồm name, path hoặc cả hai. "Kubernetes liveness probes are automatically allowed and added to learned rules, even in Monitor and Protect". Danh sách process đáng ngờ dựng sẵn (nmap, nc, ncat, socat, ssh, scp, telnet, dnscat…, reverse shell khi stdin/stdout cùng nối vào một socket) **không bao giờ được học**: luôn báo ở Discover/Monitor và chặn ở Protect. Khi chuyển group sang Monitor/Protect cần review rule đã học. — [NeuVector: Process profile rules](https://open-docs.neuvector.com/policy/processrules)

**KubeArmor (CNCF, mã nguồn mở)**
- **[Docs hãng]** Khi một workload có ít nhất một policy Allow, KubeArmor chạy theo allow-list ("least permissive"). Mọi thao tác ngoài allow-list bị *audit* hoặc *block* theo default posture. Posture cấu hình toàn cục (`defaultFilePosture`, `defaultNetworkPosture`, `defaultCapabilitiesPosture`) hoặc theo namespace qua annotation `kubearmor-file-posture`. Process thuộc nhóm File. Tài liệu tự mâu thuẫn ở mặc định toàn cục: trang ghi `audit`, help của flag ghi `block`. — [KubeArmor: Default posture](https://docs.kubearmor.io/kubearmor/documentation/default_posture)
- **[Snippet][Docs hãng]** Discovery Engine (`karmor discover`) tự sinh policy least-permissive từ dữ liệu quan sát của KubeArmor/Cilium, ra file YAML để `kubectl apply`. Không thấy đánh giá độc lập về độ đầy đủ của policy sinh ra. — [KubeArmor wiki: IoT Edge](https://github.com/kubearmor/KubeArmor/wiki/KubeArmor-to-protect-IoT-Edge-containerized-workloads)

**Sysdig**
- **[Docs hãng]** Policy drift "Auto-tuning is not used", nên giảm FP bằng scope. — [Sysdig docs: Drift Detection policy](https://docs.sysdig.com/en/sysdig-secure/drift_policy/)

**Số FP công bố / đánh giá độc lập**
- **[Độc lập]** Syairozi & Arizal, RITECH 2025 (SCITEPRESS, tr. 136–141), so sánh Falco, Tetragon và Tracee trên 3 node DOKS (2 vCPU/4 GB). Ba kịch bản (escape bằng `nsenter`, DoS `stress-ng`, cryptominer `xmrig`), mỗi kịch bản 20 lần. Detection rate 100 % và **FPR 0 %** cho cả ba công cụ. MTTD khoảng 0,42–1,62 s (ví dụ cryptomining: Tetragon 0,421 s, Falco 1,140 s, Tracee 1,116 s). Bài **không mô tả workload vô hại**, số cửa sổ hay sự kiện âm, cũng không nói dùng rule mặc định hay tự viết, và không có mục limitations. — [SciTePress 2025 PDF](https://scitepress.org/publishedPapers/2025/142727/pdf/index.html)
- **[Snippet]** Các số FP container khác tìm được đều đến từ blog hoặc tổng hợp không rõ phương pháp. Ví dụ một bài WJAETS 2025 nói ruleset tinh chỉnh đạt FPR 3,2 % so với 12,8 % nhưng không nêu nguồn dữ liệu. Không nên trích dẫn. — [WJAETS-2025-1091](https://wjaets.com/sites/default/files/fulltext_pdf/WJAETS-2025-1091.pdf)

### Inferences
- Các sản phẩm baselining **cũng "gắn cờ việc một process mới chạy"**, tức đúng hiện tượng của Pulse. Khác biệt là họ phát nó thành một *sự kiện có danh tính* (đường dẫn binary, cây cha, image digest), rồi giảm ồn bằng ba lớp: (a) học tiếp hoặc auto-suppress khi lệch nằm trong pha warm-up/ổn định; (b) allow-list theo image; (c) mức nghiêm trọng thấp. Không sản phẩm nào được khảo sát dùng *cường độ syscall của pha khởi động* làm tín hiệu. Burst execve/mmap/openat lúc khởi động của một process mới nằm ngoài mô hình của họ.
- Datadog chỉ bật anomaly cho `exec` (và auto-suppress `exec` + `dns`), với cửa sổ ổn định 15 phút. Điều này gợi ý rằng tập *đường dẫn exec* của một image hội tụ nhanh và rẻ để học. Đây là một "tripwire theo exec-path", tương tự tripwire syscall-ID mà Pulse đã có.
- 0 % FPR của SciTePress 2025 không dùng được làm bằng chứng FP vì không có workload vô hại được mô tả. Nếu Pulse báo FP trên lưu lượng bình thường có kiểm soát thì đã chặt hơn chuẩn của bài này.

### Gaps
- Không mở được tài liệu chính thức về: Sysdig Secure profiling/"image profiles", Aqua behavioural profiles, Wiz Runtime Sensor, CrowdStrike Falcon Cloud Security, Upwind. Không có số học, FP hay alert volume cho các sản phẩm này.
- Trang tài liệu Datadog về "security profiles" (URL cũ `/security/workload_protection/security_profiles/`) trả 404. Chi tiết trên lấy từ code agent; chưa xác minh backend SaaS của Datadog có thêm lọc nào.
- Không tìm thấy case study hay báo cáo hãng nào nêu FP rate hoặc số alert/ngày trước và sau baselining.

---

## Q3. Xử lý riêng `kubectl exec`: dựa vào ngữ cảnh phiên exec (tty, parent, init tree, audit log), là alert, info hay bị bỏ qua? Ephemeral/debug container?

### Takeaway
Thực tiễn chung: **exec tương tác của admin được xem là sự kiện audit hoặc mức NOTICE, gắn với danh tính lấy từ K8s audit log, không phải phát hiện độc hại.** Mức nghiêm trọng cao dành cho (a) binary drift, (b) shell được spawn bởi *process dịch vụ* (RCE), (c) công cụ đã biết là xấu. Có ba cách nhận diện process thuộc phiên exec: parent là `runc`/`containerd-shim` cộng `proc.tty` (Falco), `in_init_tree=false` (Tetragon), và gốc cây riêng khi bỏ qua runc/shim (Datadog). Prisma còn có tùy chọn **bỏ qua toàn bộ** hoạt động trong phiên attach.

### Cited Findings
- **[Mã nguồn]** Falco `Terminal shell in container`: priority **NOTICE**, điều kiện `shell_procs and proc.tty != 0 and container_entrypoint`. `container_entrypoint` nghĩa là parent không tồn tại hoặc thuộc `runc:[0:PARENT]`, `runc:[1:CHILD]`, `runc`, `containerd-shim`, `crio`, `conmon`…. Mô tả: "Common when using 'kubectl exec' in Kubernetes. Correlate with k8saudit exec logs if possible to find user or serviceaccount token used (fuzzy correlation by namespace and pod name). Rather than considering it a standalone rule, it may be best used as generic auditing rule while examining other triggered rules in this container/tty." — [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- **[Mã nguồn]** Falco `Run shell untrusted` (NOTICE) chỉ kêu khi shell có tổ tiên là *process dịch vụ được bảo vệ* (`protected_shell_spawner`: Java/Tomcat/Kafka/Elasticsearch, node…). Mô tả tự nhận "can be noisier" và có danh sách ngoại lệ dài: cron, logrotate, `exechealthz`, package manager, nginx, postgres… Gợi ý tinh chỉnh dùng `proc.ppid.duration` và `proc.vpgid.name`/`proc.vpgid.exe`. — [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- **[Docs hãng]** Các trường phiên của Falco: `proc.tty` ("0 for processes without a terminal"), `proc.sid`/`proc.is_sid_leader`, `proc.vpgid`/`proc.is_vpgid_leader`. Các trường `proc.is_container_healthcheck/liveness_probe/readiness_probe` đã *deprecated*, khuyên dùng plugin `k8smeta`. — [Falco supported fields](https://falco.org/docs/reference/rules/supported-fields/)
- **[Mã nguồn]** Falco k8saudit plugin:
  - `Attach/Exec Pod` (NOTICE) có điều kiện `ka.target.subresource in (exec,attach)`, output có `ka.user.name` và `ka.uri.param[command]`.
  - `EphemeralContainers Created` (NOTICE) ghi lại tên và image của ephemeral container (`kubectl debug`).
  - `ClusterRole With Pod Exec Created`.

  Comment nêu giới hạn: engine audit không có trạng thái nên không biết pod được exec vào có privileged hay không. Nó cũng không dùng được image name, vì sự kiện tạo pod và sự kiện exec tách rời nhau. — [k8s_audit_rules.yaml](https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/rules/k8s_audit_rules.yaml)
- **[Mã nguồn]** Tetragon `Process.in_init_tree` (BoolValue, field 20): "If set to true, this process is containerized and is a member of the process tree rooted at pid=1 in its PID namespace. This is useful if, for example, you wish to discern whether a process was spawned using a tool like nsenter or kubectl exec." Release mới nhất ngày 30/10/2026 là v1.7.1 (25/08/2026). — [tetragon.proto](https://github.com/cilium/tetragon/blob/main/api/v1/tetragon/tetragon.proto), [Tetragon releases](https://github.com/cilium/tetragon/releases)
- **[Snippet]** Có dashboard Grafana cộng đồng "Tetragon 'kubectl exec' Audit", liệt kê các lần kubectl exec theo cluster, namespace và workload. — [Grafana dashboard 20189](https://grafana.com/grafana/dashboards/20189)
- **[Docs hãng]** Prisma Cloud có tùy chọn "Allow all activity in attached sessions": bỏ qua runtime rules (process, network, filesystem) cho phiên `docker/kubectl exec` để troubleshooting không sinh audit hay bị chặn. Tùy chọn này chỉ cho Linux, và **không** bỏ qua DNS query, listening port, raw socket. — [Prisma Cloud: Runtime defense for containers](https://docs.prismacloud.io/admin-guide/runtime-defense/runtime-defense-containers)
- **[Docs hãng]** NeuVector tự cho phép liveness probe, kể cả ở Monitor/Protect. Exec probe là process mới do kubelet tạo trong container, giống về mặt cơ chế với kubectl exec. — [NeuVector: Process profile rules](https://open-docs.neuvector.com/policy/processrules)
- **[Docs hãng]** GuardDuty `Execution:Runtime/SuspiciousShellCreated` (Low) chỉ kêu khi "a network-accessible service … has launched an interactive shell", tức dựa trên parent là dịch vụ mạng, không phải mọi exec. — [GuardDuty Runtime Monitoring findings](https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html)
- **[Docs hãng]** Datadog Workload Protection có giám sát "remote user sessions" (kèm ảnh Kubernetes remote access), nhưng trang không nói các phiên này được loại trừ hay hạ mức. — [Datadog Workload Protection](https://docs.datadoghq.com/security/threats/runtime_anomaly_detection)
- **[Mã nguồn]** Falco `Contact K8S API Server From Container` (NOTICE, output "Unexpected connection to K8s API Server from container") chỉ có allowlist dựng sẵn theo image hạ tầng và `k8s.ns.name = "kube-system"`. Macro `user_known_contact_k8s_api_server_activities` mặc định `never_true`, và file hướng dẫn người dùng tự liệt kê namespace/image được phép. Đây là lý do rule này ồn trên workload có client K8s ngoài kube-system. — [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)

### Inferences
- `in_init_tree=false` (Tetragon) hoặc parent `runc`/`containerd-shim` (Falco, Datadog) cho biết process **không thuộc entrypoint**. Nhưng nhóm này gồm cả kubectl exec, exec probe (liveness/readiness/startup), `kubectl cp` (dùng `tar` qua exec) và nsenter từ host. Muốn gọi đó là "admin exec" cần ghép thêm (a) danh sách lệnh probe trong pod spec và (b) sự kiện `pods/exec` trong audit log (user, command, thời điểm). Falco tự ghi là việc ghép này "fuzzy" (theo namespace/pod).
- Không công cụ nào được khảo sát đặt kubectl exec tương tác ở mức alert cao theo mặc định. Hai lựa chọn phổ biến là NOTICE/audit (Falco) và bỏ qua hẳn (Prisma, tùy chọn). Kẻ tấn công có quyền exec (T1609) lại được nhận diện chủ yếu qua *danh tính/nguồn gọi bất thường* trong audit log (xem Q5) và qua *nội dung* phiên (drift, công cụ xấu, syscall hiếm), không phải qua việc "có exec".
- **Cảnh báo cho thiết kế thí nghiệm Pulse:** nếu harness lab tiêm cả binary vô hại lẫn exploit qua cùng một `kubectl exec` với cùng một danh tính admin, thì cơ chế tách dựa trên phiên exec/audit **không thể** phân biệt hai loại. Việc tách khi đó phải dựa vào nội dung (nguồn gốc binary, exec-path allow-list, syscall tripwire). Nếu gating theo `in_init_tree` được thêm vào, nó sẽ đồng thời che cả attack được tiêm qua exec.

### Gaps
- Không xác minh được `in_init_tree` có mặt từ phiên bản Tetragon nào, có mặc định trong JSON export không, và có dùng được trong TracingPolicy selector hay export filter không. Mới chỉ thấy trong proto.
- Không tìm thấy tài liệu chính thức về cách Sysdig, Defender, GKE hay Datadog xếp hạng riêng `kubectl exec`.
- Không có số đo nào về tỉ lệ exec tương tác trong cụm production thật.

---

## Q4. Quản lý exception/allowlist: thực hành và điểm yếu (giả tên được allowlist, LOTL)

### Takeaway
Thực hành tốt là **thu hẹp exception bằng nhiều thuộc tính** (process + đường dẫn + image/namespace + cmdline), không dùng tên process đơn lẻ. Allowlist theo đường dẫn hoặc tên bị lách bởi LOTL: dùng interpreter hoặc công cụ có sẵn trong image, chạy từ volume, hoặc copy-up/TOCTOU trên overlayfs. Ngược lại, đổi tên một binary được copy vào **không** lách được drift dựa trên upper layer.

### Cited Findings
- **[Docs hãng]** Falco exceptions (có từ 0.28.0) là một phần của rule, do tác giả rule định nghĩa. Một exception có thể là cặp process + thư mục, "but not a process name only (too broad)". — [Falco docs v0.29: Rule exceptions](https://v0-29.falco.org/docs/rules/exceptions)
- **[Mã nguồn]** Bộ rule mặc định của Falco "does not use [exceptions] by default". Việc tinh chỉnh được để cho các macro/list mẫu `user_known_*`, `known_drop_and_execute_containers`… mặc định rỗng hoặc `never_true`. — [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- **[Snippet][Docs hãng]** Datadog: tổ hợp thuộc tính càng cụ thể thì suppression càng chính xác. "suppressing based on fewer attributes increases the possibility of tuning out actual malicious activities". Với process, nên dùng executable, arguments và thông tin parent. — [Datadog: Tuning Workload Protection signals](https://docs.datadoghq.com/security/workload_protection/guide/tuning-rules/)
- **[Docs hãng]** Sysdig: exception theo full path (string hoặc regex), process-based exception (process được phép chạy file drift), và "Prohibited Binaries" để chặn cả công cụ có sẵn trong image. Nếu một mục vừa là exception vừa bị cấm thì exception thắng. — [Sysdig docs: Drift Detection policy](https://docs.sysdig.com/en/sysdig-secure/drift_policy/)
- **[Docs hãng]** Sysdig nêu các gap LOTL: script qua interpreter có sẵn không bị bắt, volume không bị coi là drift. — [Sysdig docs: Drift Detection policy](https://docs.sysdig.com/en/sysdig-secure/drift_policy/)
- **[Docs hãng]** Defender: allowlist process theo scope, rule ưu tiên trên xuống, first match wins. Tài liệu khuyên sửa hoặc xóa rule sinh quá nhiều FP. — [Microsoft Learn: Binary drift detection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/binary-drift-detection)
- **[Docs hãng]** NeuVector: rule theo name và/hoặc path, có wildcard. Một rule Deny không được dùng wildcard ở cả name và path. Deny có name wildcard thắng Allow có name wildcard. Process đáng ngờ dựng sẵn không bao giờ được học tự động, nên luôn phải allow tường minh. — [NeuVector: Process profile rules](https://open-docs.neuvector.com/policy/processrules)
- **[Snippet]** Demo Aqua: bản sao `ls` đổi tên `list` vẫn bị chặn do drift. — [Aqua AWS workshop](https://aqua.awsworkshop.io/runtime_security/drift_prevention.html)
- **[Snippet]** Rủi ro TOCTOU và copy-up trên overlayfs đối với kiểm tra dựa trên path/hash (LSM list, 01/2026). — [LSM archive](https://kernsec.org/pipermail/linux-security-module-archive/2026-January/055077.html)
- **[Docs hãng]** MITRE T1609, mitigation M1042: gỡ công cụ không cần thiết khỏi container. M1038: container/filesystem read-only, image tối giản. — [MITRE ATT&CK T1609](https://attack.mitre.org/techniques/T1609/)

### Inferences
- Allowlist theo tên process (`proc.name`) có thể bị lách bằng cách đặt tên trùng. Kết hợp với điều kiện upper-layer/inode thì không đổi tên được vì file mới vẫn ở upper layer. Allowlist theo *đường dẫn trong image* bền hơn, nhưng vẫn thua LOTL: `python -c`, `sh -c`, `curl | sh` đều chạy binary có sẵn. Lớp còn lại bắt được LOTL là hành vi: syscall hiếm (tripwire), mạng ra ngoài, cây process bất thường.
- Image distroless hoặc tối giản (M1042) làm cả LOTL lẫn exec tương tác khó hơn. Đây là biện pháp phòng ngừa, không phải phát hiện, và không đo được trong Pulse.

### Gaps
- Không tìm thấy nghiên cứu học thuật hoặc talk có số liệu về việc lách allowlist của Falco/Tetragon bằng cách giả tên hay đường dẫn. Truy vấn chỉ ra tài liệu exceptions.
- Không có dữ liệu công khai về tỉ lệ exception "quá rộng" trong triển khai thật.

---

## Q5. MITRE ATT&CK for Containers: hướng dẫn phát hiện T1609 "Container Administration Command" (và T1610 "Deploy Container")

### Takeaway
MITRE coi tín hiệu đáng tin cho T1609 là **sử dụng bất thường các công cụ quản trị** (`kubectl exec`, `docker exec`, kubelet API). Nghĩa là danh tính, tài khoản, IP nguồn ngoài mặt phẳng quản trị, kết hợp với việc *tạo process bất ngờ* trong container. Việc "có một process mới chạy qua exec" tự nó không được coi là tín hiệu.

### Cited Findings
- **[Docs]** T1609 (v1.3, tạo 29/03/2021, sửa 24/10/2025, ATT&CK v20): kẻ tấn công lạm dụng Docker daemon, Kubernetes API server hoặc kubelet để chạy lệnh trong container, ví dụ `kubectl exec`. Detection strategy DET0065 / analytic AN0177: "Defenders may detect abuse of container administration commands by observing anomalous use of management utilities". Analytic này nối việc dùng bất thường `docker exec`/`kubectl exec`/kubelet API với "unexpected process creation inside containers". Chuỗi đáng ngờ gồm API request trái phép rồi chạy lệnh trong pod, "often from unusual accounts, automation scripts, or IP addresses outside the cluster management plane". — [MITRE ATT&CK T1609](https://attack.mitre.org/techniques/T1609/)
- **[Docs]** Mitigation của T1609: M1042 (gỡ tính năng/công cụ), M1038 (read-only, image tối giản, SELinux), M1035 (hạn chế truy cập API, TLS, just-in-time access), M1026 (không chạy root, Pod Security Standards, NodeRestriction), M1018 (RBAC least privilege, tránh `system:masters`). Procedure examples: Hildegard và TeamTNT (kubelet API run), Kinsing (entrypoint), Peirates, Siloscape… — [MITRE ATT&CK T1609](https://attack.mitre.org/techniques/T1609/)
- **[Mã nguồn]** Falco gắn tag T1610 cho rule `Kubernetes Client Tool Launched in Container` (sandbox, WARNING). Falco cũng có `ClusterRole With Pod Exec Created` để theo dõi việc cấp quyền exec. — [falco-sandbox_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml), [k8s_audit_rules.yaml](https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/rules/k8s_audit_rules.yaml)

### Inferences
- Với một bộ phát hiện chỉ thấy syscall trên node như Pulse, phần "anomalous use" của T1609 (ai, từ đâu) nằm ngoài tầm nhìn. Nó cần K8s audit log. Phần mà Pulse thấy được là "unexpected process creation inside containers". Theo MITRE, phần này chỉ thành tín hiệu khi ghép với ngữ cảnh quản trị bất thường. Vì vậy nên trình bày cảnh báo "process mới" của Pulse như một sự kiện T1609 *ứng viên* cần ghép với audit log, không phải phát hiện độc lập.

### Gaps
- Chưa mở trang T1610 "Deploy Container" để trích hướng dẫn phát hiện chính xác (giới hạn số lần gọi công cụ).
- Trang T1609 không liệt kê rõ data component (Process Creation, Command Execution, Kubernetes audit) trong nội dung đã đọc.

---

## Q6. Cơ chế nào một pipeline eBPF/Tetragon miễn phí, mã nguồn mở có thể áp dụng cho Pulse

### Takeaway
Có năm cơ chế mở và miễn phí, đều có tiền lệ trong ngành. Theo thứ tự lợi ích/chi phí:
1. **Gắn nhãn nguồn gốc phiên** (`in_init_tree`, parent runc/shim, tty) kết hợp **ghép K8s audit `pods/exec`** và **lệnh probe trong pod spec**.
2. **Exec-path allow-list theo image**, học trong warm-up kiểu Datadog: 180 s warm-up, 900 s ổn định, auto-suppression.
3. **Kiểm tra nguồn gốc binary** (upper layer / memfd) bằng Falco chạy song song, hoặc tự kiểm từ mountinfo.
4. **Giữ syscall tripwire** cho mọi process, kể cả process trong phiên exec.
5. **Phân tầng mức nghiêm trọng** thay vì để burst khởi động quyết định điểm dị thường.

Không cơ chế nào trong số này tách được "độc hại" với "vô hại" khi cả hai cùng được tiêm qua một exec admin bằng binary có sẵn trong image. Đó là giới hạn chung của ngành, cần ghi vào phần limitations.

### Cited Findings
- **[Mã nguồn]** Tetragon (Apache-2.0) có sẵn `in_init_tree` để phân biệt process từ `kubectl exec`/`nsenter`. Nó cũng có `BinaryProperties.file` cho binary memfd/shm/đã xóa (fileless). Tetragon **không** có trường upper-layer. — [tetragon.proto](https://github.com/cilium/tetragon/blob/main/api/v1/tetragon/tetragon.proto)
- **[Mã nguồn]** Falco (Apache-2.0) có sẵn: `Drop and execute new binary in container` (`proc.is_exe_upper_layer`, CRITICAL, stable), `proc.is_exe_from_memfd`, `Terminal shell in container` (NOTICE), và trong plugin k8saudit: `Attach/Exec Pod` và `EphemeralContainers Created` (NOTICE). — [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml), [k8s_audit_rules.yaml](https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/rules/k8s_audit_rules.yaml), [Falco fields](https://falco.org/docs/reference/rules/supported-fields/)
- **[Mã nguồn]** Datadog agent (Apache-2.0) là một bản cài đặt mở của baselining exec theo image. Tham số mặc định: warm-up 180 s, ổn định 900 s, profile không ổn định sau 1 h, auto-suppression cho exec/dns, profile kèm tập syscall. Có thể đọc hoặc sao chép thiết kế, kể cả khi không dùng backend SaaS. — [system-probe-cws.yaml](https://github.com/DataDog/datadog-agent/blob/main/pkg/config/schema/yaml/system-probe-cws.yaml), [config.go](https://github.com/DataDog/datadog-agent/blob/main/pkg/security/config/config.go)
- **[Docs hãng]** NeuVector (mã nguồn mở) có tiền lệ tự cho phép liveness probe và học process theo name+path trong Discover. KubeArmor (mã nguồn mở) có tiền lệ allow-list với posture audit/block. — [NeuVector process rules](https://open-docs.neuvector.com/policy/processrules), [KubeArmor default posture](https://docs.kubearmor.io/kubearmor/documentation/default_posture)
- **[Docs hãng]** Prisma có tiền lệ "attached sessions" bypass (nhưng vẫn giữ DNS, listen, raw socket) và "alert once then add to model". — [Prisma Cloud runtime defense](https://docs.prismacloud.io/admin-guide/runtime-defense/runtime-defense-containers)

### Inferences
Đây là đề xuất thiết kế cho Pulse, chưa được kiểm chứng.

1. **Gắn nhãn phiên exec (rẻ, độ trễ thấp).** Từ luồng `process_exec` của Tetragon, đánh dấu process có `in_init_tree=false`, cùng toàn bộ hậu duệ (dùng liên kết parent–child có sẵn). Ghép nhãn đó với:
   - (a) lệnh exec-probe trong pod spec (đọc từ K8s API, miễn phí);
   - (b) sự kiện `pods/exec` từ K8s audit log (bật audit policy ở mức Metadata hoặc Request; đọc qua Falco k8saudit plugin hoặc webhook tự viết), ghép theo ns/pod/thời điểm.

   Chi phí: phải bật audit log trên API server và chấp nhận ghép "fuzzy". Độ trễ của audit backend có thể vượt ngân sách 3 s, nên nhãn audit có thể đến sau. Một cách là cho cảnh báo của Pulse đi kèm trường "exec_session=true, audit_user=?" để điền về sau.
2. **Không để burst khởi động của process trong phiên exec chi phối điểm cửa sổ 0,5 s của container.** Có hai cách:
   - (a) Tách syscall theo nhóm process (init-tree và exec-tree) trong eBPF. Đếm theo cgroup không đủ, cần thêm khóa `in_init_tree`/tgid.
   - (b) Hạ mức cảnh báo nếu cửa sổ bị chi phối bởi exec-tree mà binary nằm trong exec-allow-list của image.

   Tiền lệ: Prisma bypass phiên attach (vẫn giữ DNS, listen, raw socket), Datadog dùng warm-up và auto-suppression.
3. **Exec-path allow-list theo image digest.** Khóa là (image digest, exe path, parent exe path), học trong pha warm-up giống Datadog (180 s / 900 s). Exe mới thì phát sự kiện "new exec path" ở mức NOTICE, nằm trong allow-list thì không cảnh báo. Đây là "tripwire theo exec-path", tương tự tripwire syscall-ID đã có FP gần 0. Có thể đánh giá bằng đúng giao thức hiện tại của Pulse: có rule và không có rule.
4. **Nguồn gốc binary.** Tetragon không có trường upper-layer. Có hai lựa chọn miễn phí:
   - (a) Chạy Falco song song chỉ với `Drop and execute new binary in container` và rule memfd.
   - (b) Tự kiểm ở user-space: lấy `upperdir` của container từ `/proc/<pid>/mountinfo` (overlay), rồi `stat` file exe trong upperdir.

   Cách (b) có race nếu file bị xóa hoặc thay ngay sau exec, và chỉ đúng với overlayfs. Đây là suy luận, chưa thử. Upper-layer cho FP với package update hoặc `kubectl cp` hợp lệ. Falco tự khuyên allowlist theo image hoặc namespace non-prod.
5. **Giữ syscall tripwire và tín hiệu nội dung cho cả process trong phiên exec.** Đây là lớp duy nhất còn bắt được LOTL hoặc attack được tiêm qua exec bởi danh tính hợp lệ. Allowlist hay bypass phiên exec không được tắt lớp này. Tiền lệ: Prisma giữ DNS, listen và raw socket trong phiên attach; NeuVector không bao giờ học "suspicious processes".
6. **Đánh giá trung thực cho luận văn.** Báo cáo riêng ba nhóm:
   - (i) binary vô hại có sẵn trong image, chạy qua exec;
   - (ii) binary vô hại được copy vào (upper layer);
   - (iii) attack qua exec.

   Mỗi cơ chế ở trên có lợi ở nhóm khác nhau: allow-list giúp (i), provenance thất bại ở (ii) vì vẫn kêu, và gating theo phiên exec có thể che (iii). Không có số FP công bố từ ngành để so sánh; chỉ có SciTePress 2025, mà bài này không mô tả workload vô hại.

### Gaps
- Chưa xác minh `in_init_tree` có trong JSON export mặc định của Tetragon v1.7.x, hay có cần flag nào không. Cần thử trên lab: `kubectl exec` vào một pod rồi xem trường này trong `tetra getevents -o json`.
- Chưa có số đo độ trễ của K8s audit backend (log hoặc webhook) trên cụm lab so với ngân sách ≤ 3 s.
- Chưa kiểm cách tự tra upperdir từ `mountinfo` trên runtime đang dùng ở lab (containerd overlayfs snapshotter). Cũng chưa kiểm vì sao drift chỉ kêu ở 10/65 container.
