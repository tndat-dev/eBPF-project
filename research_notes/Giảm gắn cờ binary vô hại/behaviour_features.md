# Phân biệt process mới độc hại với process mới vô hại trong container: mô hình theo process, xử lý pha khởi động, đặc trưng "ý đồ" và đánh giá với nhóm đối chứng vô hại

Ghi chú nghiên cứu, ngày 30/10/2026. Nhãn dùng trong ghi chú:
- **[Đo]**: số liệu đo trong bài hoặc tài liệu gốc.
- **[Tài liệu]** / **[Mã nguồn]**: trích từ docs hoặc code (rule, detector, dataloader).
- **[Snippet]**: chỉ đọc được abstract hoặc tóm tắt từ kết quả tìm kiếm, chưa đọc toàn văn.
- **[Đo cục bộ]**: tự đo trên máy host bằng `strace`, có ghi lệnh để chạy lại.

Ghi chú này tránh lặp lại `research_notes/Cải thiện Pulse trên LID DS/improvement_techniques.md`. File đó đã có: argument và errno trên LID-DS, CHIDS và ReplicaWatcher (Bảng IV), STIDE/SCG có thread information, ngưỡng và tính khả thi của eBPF. Ở đây các nguồn đó chỉ được nhắc lại khi trả lời trực tiếp câu hỏi về process mới vô hại.

## 1. Mô hình theo process, thread hoặc executable bên trong container (thay vì gộp theo container): ai làm, và báo nhầm với process mới vô hại thay đổi ra sao

### Takeaway
Các hệ có mô hình theo executable (pH/ImSafe, process baseline của StackRox/RHACS) không coi executable chưa thấy là bất thường. Chúng coi đó là "chưa có profile": giai đoạn học thì không báo động, hoặc chỉ báo "rủi ro" chứ không vi phạm. Cách này xoá được báo nhầm kiểu binary đối chứng, nhưng cũng bỏ qua mọi binary mới độc hại. Vì vậy với Pulse, mô hình theo executable chỉ có ích khi đi kèm đặc trưng ý đồ (mục 3) cho các executable chưa có profile. Không tìm được bài nào đo FPR trên process mới vô hại khi chuyển từ mô hình gộp theo container sang mô hình theo process.

### Cited Findings
- [Tài liệu] **pH (Somayaji & Forrest)**, theo mô tả trong bài Thread Homeostasis:
  - Mỗi chương trình có một profile riêng. "Multiple instances of the same program code will point to the same training data."
  - Profile chỉ chuyển sang chế độ phát hiện khi đã "frozen": tỉ lệ số call liên tiếp không thêm gì mới trên tổng số call vượt ngưỡng (mặc định 4), rồi giữ frozen thêm một khoảng thời gian (mặc định một tuần) mới được đánh dấu "normal".
  - Tác giả viết: "A premature termination of training can result in a high percentage of false-positives".
  - Cơ chế "tolerization": nếu số anomaly vượt `anomaly limit`, pH chấp nhận hành vi đó là bình thường, hủy giám sát và học lại. Ngược lại, nếu LFC vượt `tolerize limit` thì pH xoá dữ liệu train.
  - Hệ quả: chương trình mới không bị chấm điểm cho đến khi có profile.

  — [Thread Homeostasis, arXiv 1910.01012 (mô tả pH, §3)](https://arxiv.org/pdf/1910.01012)
- [Tài liệu] **ImSafe** (phỏng theo pH, mỗi ứng dụng một profile, cửa sổ sequence mặc định dài 6) ghi nhận "One execution on one hundred gives us an alarm". Nâng ngưỡng giảm được báo nhầm nhưng dễ bị tấn công né. — [ImSafe docs](https://imsafe.sourceforge.net/inside.htm)
- [Tài liệu] **StackRox / Red Hat ACS, process baseline**:
  - Hệ thống "creates a process baseline for every container type in a deployment".
  - Pha discovery kết thúc "After an hour from when [RHACS] receives the first process indicator". Độ dài chỉnh qua `ROX_BASELINE_GENERATION_DURATION`.
  - Khi chưa khoá, process mới "show up as risks, but they do not trigger any violations".
  - Khi đã khoá (phải khoá thủ công), "New processes that are not in the process baseline trigger violations".

  Đây là mô hình theo executable cho từng vai trò container, đúng bằng đơn vị "per workload" của Pulse. Không có số FPR. — [RHACS 4.7 docs, Using process baselines](https://docs.redhat.com/ko/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.7/html/operating/use-process-baselines_evaluate-security-risks)
- [Mã nguồn] **Falco "Drop and execute new binary in container"** (maturity_stable, priority CRITICAL):
  - Điều kiện: `spawned_process and container and proc.is_exe_upper_layer=true`, cộng danh sách image ngoại lệ. Tức là executable không thuộc image gốc (chỉ áp dụng với overlayfs).
  - Mô tả rule tự nêu: "Common anti-patterns include administrators or SREs performing ad-hoc debugging".

  — [falcosecurity/rules, falco_rules.yaml (commit e7b066b, 22/10/2026)](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- [Snippet] Sysdig cho biết rule cũ dựa trên `chmod` "noisy" và bị tắt mặc định. Rule upper-layer được giới thiệu là tín hiệu kernel "unambiguous" hơn. — [Sysdig blog, container drift detection with Falco](https://www.sysdig.com/blog/container-drift-detection-with-falco)
- [Đo] **Abed et al. 2015**:
  - Coi cả container như một process và dùng BoSC với cửa sổ trượt.
  - Trace 3.804.000 syscall, 875.000 syscall dùng để train, 40 syscall khác nhau, khoảng 17k BoSC trong database normal.
  - Tấn công tạo trung bình 695 mismatch mỗi epoch, normal là 33.
  - Với epoch S=1000 và ngưỡng 10: TPR 100 %, FPR 2 %. Epoch càng nhỏ thì FPR càng thấp.

  — [Abed, Clancy, Levy, arXiv 1611.03056](https://arxiv.org/pdf/1611.03056)
- [Đo] Tách theo thread (thread information, LID-DS 2019) nâng DR ở 6/7 thuật toán, còn số FA thì lẫn lộn. Ví dụ Heartbleed: STIDE từ DR 0,00 lên 0,95. Chi tiết đã có ở ghi chú trước. — [Grimmer et al., EISA 2021](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- [Đo] **ADFA-LD**: mỗi trace là một process, nên đây là bài toán "process độc hại vs process vô hại" ở mức host. STIDE II đạt DR khoảng 80 % với FAR khoảng 18 %. Ở FAR dưới 1 %, DR chỉ còn 18,9 % (FAR 0,7 %). — [Grimmer et al., Intrusion Detection on System Call Graphs](https://dbs.uni-leipzig.de/file/Intrusion-Detection-on-System-Call-Graphs.pdf)
- [Đo] **CHIDS (CCSW 2022)**, phần thăm dò dữ liệu:
  - Ở CWE-307, "unseen arguments are triggered more often during the normal execution of containers than during the attack phase".
  - Tác giả quy cho hai nguyên nhân: hành vi người dùng không lặp lại, và base image (ví dụ `alpine:latest`) được cập nhật.
  - CHIDS chỉ theo dõi argument đường dẫn của `clone`/`open`/`stat`/`execve`. Đường dẫn dài hơn ba cấp thư mục thì bỏ tên file.

  — [El Khairi et al., CHIDS PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf)
- [Tài liệu] **ReplicaWatcher (NDSS 2024)**:
  - So sánh các replica với nhau; dùng readiness probe để "temporarily exclude replicas being created or deleted ... preventing false alarms".
  - Thừa nhận ở phần hạn chế: "activities related to DevOps and maintenance (e.g., execing into a pod for debugging), might diverge ... and thus can be classified as anomalies".

  — [ReplicaWatcher NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)

### Inferences
- Trong cả hai họ hệ thống theo executable (pH, RHACS), executable mới không bị chấm bằng mô hình bất thường. Nếu Pulse key mô hình theo executable (inode hoặc hash đường dẫn exe, trong từng vai trò image), binary đối chứng sẽ hết bị gắn cờ, nhưng cả 5 tấn công cũng là binary mới nên cũng bị bỏ qua. Novelty theo executable vì vậy không phải tín hiệu tách hai nhóm. Nó chỉ có ích để **định tuyến**:
  - Executable đã có profile thì dùng mô hình theo workload như hiện tại.
  - Executable chưa có profile thì chỉ chấm bằng (a) phần sau khởi động (mục 2) và (b) khối đặc trưng ý đồ (mục 3), với ngưỡng hiệu chỉnh trên một tập process exec vô hại (mục 5).
- Rule upper-layer của Falco sẽ bắn cả cho binary đối chứng lẫn tấn công nếu chúng được copy vào container (kubectl cp). Nó không tách được hai nhóm trong thiết kế campaign hiện tại, chỉ cho biết "đây là binary lạ".
- Trong eBPF, đếm theo process chỉ cần thêm key `tgid` (hoặc `exe inode`) vào map đếm, cộng tracepoint `sched_process_exec`/`sched_process_exit` để mở và đóng một "vector đời process". Một binary sống dưới 0,5 s có thể được chấm ngay khi `exit_group`, nên không làm chậm alert (suy luận, chưa đo).

### Gaps
- Không tìm được bài nào đo FPR trên process mới vô hại khi chuyển từ đếm theo container sang đếm theo process trong cùng dataset.
- Không tìm được số FPR công bố cho process baseline của RHACS hay NeuVector. Docs chỉ mô tả cơ chế.
- Chưa đọc được toàn văn bài gốc của pH (Somayaji & Forrest 2000) và Hofmeyr et al. 1998, nên không có số FP theo từng chương trình.

## 2. Xử lý pha khởi động: "initialization vs serving phase" (TSS, SysPart, Confine, SPEAKER, PhaseSeed), HIDS bỏ qua hoặc tách riêng pha khởi động, và khả năng trừ một profile khởi động chung

### Takeaway
Văn liệu seccomp theo pha cho thấy tập syscall lúc khởi động khác rõ với lúc phục vụ: `execve`, `setuid` và các syscall tương tự bị loại sau khi khởi động xong. Nhưng `mprotect` vẫn cần ở pha phục vụ của cả 6 server được thử. Vì vậy đếm theo ID không tách được tấn công dựa trên `mprotect`; phải dùng argument. Với HIDS, cách xử lý được ghi nhận là **loại khỏi giám sát** (LID-DS đánh dấu `warmup_end`, ReplicaWatcher bỏ qua replica chưa ready), chứ không phải trừ đi. Đo cục bộ cho thấy burst khởi động glibc gần như cố định: 30 syscall cho `/bin/true`, giống hệt binary gọi `getpid` chỉ thiếu đúng `getpid`. Nhưng burst thay đổi mạnh theo runtime: static 16, Python 353, Go khoảng 2.400 dưới strace. "Profile khởi động chung" vì thế khả thi nếu chia theo họ runtime. Phân bin theo vị trí syscall kể từ lần exec gần nhất an toàn hơn trừ template.

### Cited Findings
- [Đo] **Temporal System Call Specialization** (Ghavamnia et al., USENIX Security 2020), Bảng 3: số syscall giữ lại trên 333, ở pha init so với pha serving.

  | Ứng dụng | Init | Serving |
  |---|---|---|
  | Nginx | 104 | 97 |
  | Apache | 94 | 79 |
  | Lighttpd | 95 | 76 |
  | Bind | 99 | 85 |
  | Memcached | 99 | 84 |
  | Redis | 90 | 82 |

  — [TSS PDF (NSF PAR)](https://par.nsf.gov/servlets/purl/10219920); [trang USENIX](https://www.usenix.org/conference/usenixsecurity20/presentation/ghavamnia)
- [Đo] TSS, Bảng 4, trên 17 syscall "security-critical" lấy từ shellcode và ROP payload:
  - Temporal specialization loại tổng cộng 53, còn library debloating loại 35, tức tăng 51 %.
  - Sau pha init, `execve` bị loại ở hầu hết server.
  - **`mprotect` không bị loại ở cả 6 ứng dụng**, vì là "crucial operation for most applications".
  - Điểm chuyển pha được xác định thủ công trong source, ví dụ `ngx_worker_process_cycle` (Nginx) và `child_main` (Apache).

  — [TSS PDF](https://par.nsf.gov/servlets/purl/10219920)
- [Đo] **SysPart** (CCS 2023):
  - Định nghĩa serving phase là "the beginning of a top-level loop, where it spends most time executing", tìm bằng phân tích tĩnh cộng động trên binary, không cần source.
  - Trung bình chỉ cho phép nhiều hơn TSP 8,33 % syscall, và lọc được bằng TSP các syscall critical trong 88,23 % trường hợp.

  — [SysPart, arXiv 2309.05169](https://arxiv.org/pdf/2309.05169)
- [Đo] **Confine** (RAID 2020), 150 Docker image:
  - Hơn một nửa số container bị tắt từ 145 syscall trở lên (trên 326). Trung bình 148 với top-15 image.
  - Tác giả đếm filter mặc định của Docker là 49 syscall.
  - Nginx cần 160 syscall theo phân tích tĩnh, trong khi phân tích động của Wan et al. chỉ thấy 76. Đây là bằng chứng rằng profile học động bỏ sót đường thực thi hiếm.
  - Confine mô tả SPEAKER là "separates the required system calls into two main phases, booting and runtime", trích xuất động cho từng pha.

  — [Confine PDF](https://www3.cs.stonybrook.edu/~mikepo/papers/confine.raid20.pdf)
- [Tài liệu] Docker docs: profile seccomp mặc định tắt "around 44 system calls out of 300+". Lệch với con số 49 của Confine; có thể do phiên bản profile khác nhau. — [Docker docs, Seccomp security profiles](https://docs.docker.com/engine/security/seccomp/)
- [Đo] **PhaseSeed** (arXiv 11/2025):
  - Phân tích pha init bằng chạy động. Quan hệ points-to tạo ra trong init "remain constant across multiple runs" khi cấu hình không đổi.
  - Khi sinh profile seccomp, lọc thêm được 9 syscall security-critical.

  — [PhaseSeed, arXiv 2511.06661](https://arxiv.org/pdf/2511.06661)
- [Snippet] Một bài về seccomp lập trình bằng eBPF nêu rằng filter cBPF không thể chỉ áp tập init trong pha init, còn bản eBPF thì làm được. — [arXiv 2302.10366](https://arxiv.org/pdf/2302.10366)
- [Snippet] Container runtime tự áp seccomp lên chính nó trước khi exec binary trong container, nên các syscall setup của runtime cũng phải được cho phép. — [Moby forum](https://forums.mobyproject.org/t/docker-seccomp-prevents-system-calls-issued-by-oci-runtime/297)
- [Mã nguồn] **LID-DS 2021**: metadata mỗi recording có `time.container_ready`, `time.warmup_end` và `time.exploit[]`. Tức là dataset đánh dấu sẵn pha warm-up. Repo cũng có `dataloader/data_loader_cbds.py` cho CB-DS. — [LID-DS recording_2021.py @5b8e414](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/dataloader/recording_2021.py)
- [Tài liệu] ReplicaWatcher dùng readiness probe để tạm loại các replica đang được tạo, "preventing false alarms". Đây là loại pha khởi động container khỏi giám sát. — [ReplicaWatcher NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Đo cục bộ] Burst khởi động, đo bằng `strace -qq` trên Ubuntu với glibc 2.39, kernel 7.0.0-38, ngày 30/10/2026. Binary thử là `int main(){getpid();}`, biên dịch `gcc -O2`.
  - **Bản động** (`g_dyn`): tổng 31 syscall, gồm `mmap` 8, `mprotect` 3, `pread64` 2, `openat` 2, `fstat` 2, `close` 2, và mỗi loại sau 1 lần: `execve`, `brk`, `arch_prctl`, `access`, `read`, `set_tid_address`, `set_robust_list`, `rseq`, `prlimit64`, `munmap`, `getpid`, `exit_group`.
  - **`/bin/true`**: 30 syscall, cùng multiset với `g_dyn` trừ `getpid`.
  - **Bản static** (`gcc -static`): 16 syscall (`brk` 5, `mprotect` 1, `readlinkat`, `getrandom`, ...).
  - **`/bin/ls`**: 156 syscall (`openat` 45, `mmap` 30).
  - **`jq --version`**: 149. **`python3 -c pass`**: 353 (`rt_sigaction` 66).
  - **Go static** (`gh --version`, `strace -f -c`): 2.403 syscall, gồm `futex` 849, `rt_sigaction` 114, `mmap` 52, `clone` 12. Số `futex` có lẽ bị strace thổi phồng.
- [Đo cục bộ] Cả 3 lần `mprotect` lúc khởi động của `g_dyn` đều là `PROT_READ` (RELRO). Mapping `PROT_EXEC` duy nhất là `mmap` có fd (text của libc). Số `mprotect` có `PROT_EXEC` trong trace của `jq`, `python3` và `gh` đều bằng 0.

  Lệnh chạy lại: `strace -qq -o tr.txt ./g_dyn; grep -E "mprotect|mmap" tr.txt`.

### Inferences
- Lý do exec-aware novelty bắt được syscall hiếm nhưng không tách được `mprotect` và `seccomp`:
  - `mprotect` có trong mọi lần khởi động glibc (đo cục bộ) và cả trong pha serving của server (TSS Bảng 4).
  - `seccomp` (hoặc `prctl(PR_SET_SECCOMP)`) có lẽ do runc gọi trên đường `kubectl exec` (snippet Moby). Điểm này cần kiểm trên dữ liệu Pulse: syscall ID `seccomp` có xuất hiện trong cgroup container lúc chạy binary đối chứng không.
  - Vậy hai tấn công này chỉ tách được bằng argument (prot mới chứa `PROT_EXEC` trên vùng anonymous, opcode seccomp không hợp lệ), errno, hoặc vị trí (sau khi binary đã vào `main`).
- **Profile khởi động chung trừ khỏi cửa sổ**: khả thi về nguyên tắc vì burst glibc gần như cố định giữa các binary C nhỏ (30–31 syscall, cùng multiset). Nhưng nó dao động mạnh theo runtime (static 16, Python 353, Go khoảng 2.400) và theo số thư viện hay locale (`ls` 156). Trừ template "số execve × template" sẽ sai số lớn với `ls`, `python` hay Go.
- Cách an toàn hơn là **phân bin theo pha trong kernel**:
  - Map `tgid → số syscall kể từ execve`, reset ở `sched_process_exec`.
  - Syscall thứ k ≤ K, hoặc tuổi task < T ms, đi vào khối "startup". Phần còn lại vào khối "steady".
  - K hoặc T học theo họ runtime, nhận diện qua interpreter `PT_INTERP` hoặc dấu hiệu Go hay static. Gợi ý ban đầu: K khoảng 32 cho glibc động, khoảng 16 cho static; với Go hay Python thì dùng T theo thời gian.
  - Với binary đối chứng, khối steady chỉ còn `getpid` và `exit_group`. Với 5 tấn công, khối steady chứa chính syscall tấn công.
  - Chi phí là một lookup hash map cho mỗi syscall. Không thêm độ trễ ngoài cửa sổ 0,5 s.
  - Tất cả là suy luận, chưa đo.
- Rủi ro của cách tách theo pha: kẻ tấn công có thể đặt hành vi vào constructor hoặc `LD_PRELOAD` để rơi vào khối startup. Vì vậy đặc trưng ý đồ (mục 3) phải chấm trên cả hai khối, không chỉ khối steady.
- LID-DS 2021 đã có `warmup_end`. Pulse có thể kiểm offline ngay: (a) loại warm-up, (b) tách bin startup/steady theo thread, rồi so FA. Dữ liệu và dataloader đã có sẵn.

### Gaps
- Không đọc được toàn văn SPEAKER (Lei et al.), sysfilter (RAID 2020; link PDF trả về HTML), DockerSlim và "Shrinking the kernel attack surface". Không có số đo của chúng về pha khởi động.
- Không tìm được bài HIDS nào mô hình riêng pha dynamic loader hoặc libc init của từng process và báo cáo FPR.
- Số đo cục bộ là trên host Ubuntu, không phải trong pod của cluster. Burst của `kubectl exec` (runc init, setns, seccomp, cgroup) chưa được đo.

## 3. Đặc trưng "ý đồ độc hại" thay cho novelty thuần: syscall và argument nhạy cảm (ptrace, namespace, đổi quyền bộ nhớ sang executable, nạp module, file credential), errno, hành vi sau khởi động

### Takeaway
Có một danh mục syscall/argument nhạy cảm đã được chuẩn hoá trong công cụ mã nguồn mở (Falco, Tracee, profile seccomp mặc định của Docker, quyền SELinux `execmem`). Danh mục này khớp trực tiếp với các tấn công của Pulse: `PTRACE_TRACEME` là rule stable của Falco và detector TRC-102 của Tracee; `mprotect` sang X là `mem_prot_alert` của Tracee; `setns`, `unshare`, `seccomp` nằm trong danh sách chặn của Docker. Văn liệu malware Linux cho thấy lỗi quyền và việc dò danh tính là phổ biến: 33,84 % mẫu gặp EPERM/EACCES hoặc truy vấn uid/gid. Không tìm được bài nào đo đặc trưng ý đồ trên nhóm đối chứng "binary mới vô hại". Đây là khoảng trống, và cũng là đóng góp có thể có của Pulse.

### Cited Findings
- [Mã nguồn] **Falco** (falcosecurity/rules, commit e7b066b, 22/10/2026):
  - "PTRACE anti-debug attempt" (stable, NOTICE): `evt.type=ptrace and evt.arg.request contains PTRACE_TRACEME`.
  - "PTRACE attached to process" (stable, WARNING): request ∈ {POKETEXT, POKEDATA, ATTACH, SEIZE, SETREGS} và `not known_ptrace_procs`.
  - Các rule stable khác: "Fileless execution via memfd_create" (`proc.is_exe_from_memfd=true`), "Execution from /dev/shm", "Linux Kernel Module Injection Detected", "Detect release_agent File Container Escapes".
  - Rule incubating: "Change thread namespace" (`evt.type=setns` từ chương trình không thuộc danh sách runc, containerd, kubelet, CNI...) và "Change namespace privileges via unshare" (`unshare` trong container không có `CAP_SYS_ADMIN`).
  - Danh sách ngoại lệ của rule setns cho thấy chính runtime (runc, containerd) có gọi `setns`.

  — [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml); [falco-incubating_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml)
- [Mã nguồn] **Tracee** (commit 2f9dc40, 29/09/2026):
  - TRC-102 "Anti-Debugging detected": event `ptrace` với filter `request=0` (PTRACE_TRACEME), MITRE "Debugger Evasion".
  - TRC-104 "Dynamic code loading detected": event `mem_prot_alert` với `alert=4` (W+X→X), MITRE "Software Packing".
  - Các loại `mem_prot_alert`: `MmapWX` ("Mmaped region with W+E permissions!"), `MprotectToX` ("Protection changed to Executable!"), `MprotectXToWX`, `MprotectWXToX`.

  — [tracee detectors/anti_debugging.go](https://github.com/aquasecurity/tracee/blob/main/detectors/anti_debugging.go); [detectors/dynamic_code_loading.go](https://github.com/aquasecurity/tracee/blob/main/detectors/dynamic_code_loading.go); [types/trace/trace.go](https://github.com/aquasecurity/tracee/blob/main/types/trace/trace.go)
- [Tài liệu] **SELinux memory protection**:
  - `execmem` áp cho mmap anonymous có `PROT_EXEC` và cho mapping file `MAP_PRIVATE` vừa `PROT_WRITE` vừa `PROT_EXEC`.
  - `execheap` và `execstack` áp cho `mprotect` làm heap hoặc stack thành executable.
  - `execmod`: `mprotect` lên mapping file đã bị sửa (COW) "will fail with EACCES".
  - Khuyến nghị: "programs should never use memory regions which are writable and executable at the same time".

  — [Drepper, SELinux memory protection tests](https://www.akkadia.org/drepper/selinux-mem.html)
- [Tài liệu] **Docker default seccomp**, lý do chặn từng nhóm:
  - `setns`, `unshare`, `clone` với cờ namespace, `mount`, `bpf`: bị gate bởi `CAP_SYS_ADMIN`.
  - `kexec_load` bởi `CAP_SYS_BOOT`; `init_module` bởi `CAP_SYS_MODULE`.
  - `perf_event_open`: có thể làm lộ thông tin host. `keyctl`: keyring "is not namespaced". `userfaultfd` và `personality` cũng bị chặn.
  - `ptrace` chỉ bị chặn trên kernel trước 4.8.

  — [Docker docs](https://docs.docker.com/engine/security/seccomp/)
- [Đo] Bộ 17 syscall security-critical của TSS chia ba nhóm:
  - Cmd execution: `clone`, `execveat`, `execve`, `fork`, `ptrace`.
  - Permission: `chmod`, `mprotect`, `setgid`, `setreuid`, `setuid`.
  - Networking: `accept4`, `accept`, `bind`, `connect`, `listen`, `recvfrom`, `socket`.

  Trong đó `mprotect` không bị loại khỏi pha serving ở bất kỳ ứng dụng nào. — [TSS PDF](https://par.nsf.gov/servlets/purl/10219920)
- [Đo] **Cozzi et al., "Understanding Linux Malware" (S&P 2018)**:
  - Bảng VI: 986 mẫu (12,65 %) gặp lỗi EPERM, 716 (9,19 %) EACCES, 1.609 (20,65 %) truy vấn danh tính user, 877 (11,26 %) truy vấn group. Tổng 2.637 mẫu (33,84 %) "getting privileges errors or probing identities".
  - Bảng VII, khác biệt khi chạy bằng user so với root: chạy lệnh shell đặc quyền 21,96 %, thả file vào thư mục bảo vệ 16,15 %, persistence toàn hệ thống 9,82 %, can thiệp sandbox 2,31 %, ptrace lên process khác 0,38 %.
  - Hơn 50 % mẫu đổi tên process. Hơn 4K mẫu gọi `prctl(PR_SET_NAME)` hoặc sửa `argv[0]`.

  — [Cozzi et al., S&P 2018 PDF](https://www.s3.eurecom.fr/docs/oakland18_cozzi.pdf)
- [Snippet] **Callchains** (Haruyama et al., IEICE Trans. Commun. 2007) chỉ giám sát các hoạt động có dùng POSIX capability (1003.1e), nhằm giảm báo nhầm của phát hiện bất thường dựa trên syscall, và báo cáo capability nào đã được dùng làm "risk information". Abstract không có số liệu. — [IEICE abstract](https://global.ieice.org/en_transactions/communications/10.1093/ietcom/e90-b.10.2646/_p)
- [Đo] **Gupta et al. (Electronics 2024)**, phân tích tĩnh ELF:
  - Chia syscall thành 10 nhóm chức năng và gán mức rủi ro High/Medium/Low.
  - Trên 1.117 malware IoT ARM và 1.214 binary vô hại: F1 96,86 %. Kiểm định chi-square cho p < 2,2×10⁻¹⁶.

  — [Electronics 13(15):2906 PDF](https://mdpi-res.com/d_attachment/electronics/electronics-13-02906/article_deploy/electronics-13-02906.pdf)
- [Snippet] **Bortolini, Obelheiro, Maziero (SBSeg 2025)**: nhóm syscall theo mức đe doạ và chức năng trước khi đưa ma trận tần suất bigram vào Transformer. Đạt F1 0,90 (bản gốc 0,92), thời gian chạy giảm hơn 86 %. Trang bài không nêu dataset. — [SBSeg 2025](https://sol.sbc.org.br/index.php/sbseg/article/view/36676)
- [Đo] **CHIDS** dùng "unseen argument" (đường dẫn) cho `execve`/`open`/`stat`/`clone` làm một trong ba tín hiệu. Phần số liệu đã có ở ghi chú LID-DS. — [CHIDS PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf)

### Inferences
- Ánh xạ 5 tấn công của Pulse sang đặc trưng ý đồ có nguồn tham chiếu:

  | Tấn công | Đặc trưng có nguồn | Ghi chú |
  |---|---|---|
  | `ptrace(PTRACE_TRACEME)` trên con | Falco stable; Tracee TRC-102 | chỉ cần `args[0]` ở `sys_enter` |
  | `mprotect` churn trên trang anonymous | Tracee `mem_prot_alert`; SELinux `execmem`/`execheap` | burst glibc có 0 lần `PROT_EXEC` trên `mprotect` (đo cục bộ) |
  | `setns` với fd sai | Falco incubating; Docker chặn | runc cũng gọi `setns`; cần errno hoặc "sau exec của binary user" |
  | `seccomp` với op sai | Docker profile, Callchains (capability) | runtime cũng áp seccomp trước exec; cần op hoặc errno |
  | `execveat` với fd sai | TSS (nhóm Cmd execution) | errno `EBADF`; `execveat` hiếm trong binary thường |

- Binary đối chứng (chỉ `getpid`) không chạm đặc trưng nào ở trên. Nếu dùng danh mục này, Pulse gần như chắc chắn tách được 5 tấn công với nhóm đối chứng.

  Nhưng phản biện sẽ nói đây là **vòng tròn**: tấn công được chọn chính vì gọi syscall nhạy cảm. Để tránh, cần:
  1. Cố định danh mục trước khi xem dữ liệu test, chỉ lấy từ nguồn ngoài (Docker default seccomp, rule stable của Falco/Tracee, 17 syscall của TSS) và đăng ký trước như cách làm của `cbds-confirmation-v1`.
  2. Đo FPR trên nhóm lệnh admin thật (mục 5).
  3. Kiểm trên LID-DS/CB-DS, nơi tấn công là exploit thật.
- Errno là đặc trưng ý đồ có bằng chứng: 33,84 % malware Linux gặp EPERM/EACCES hoặc dò uid/gid (Cozzi). Cả 5 tấn công của Pulse đều thất bại hoặc chỉ tác động cục bộ trong process. Một khối "lỗi trên syscall nhạy cảm" (errno ∈ {EPERM, EACCES, EBADF, EINVAL}) bổ sung tự nhiên cho khối `errno` đề xuất ở ghi chú LID-DS (bản đó không phân biệt syscall nhạy cảm).
- JIT là nguồn báo nhầm đã biết của đặc trưng W→X: JVM, V8/Node, .NET, PCRE-JIT, LuaJIT. Đây là kiến thức chung, chưa có nguồn trong phiên này. Vì vậy đặc trưng `prot→X` trên vùng anonymous phải được hiệu chỉnh theo từng vai trò image (conformal theo workload như Pulse đang làm), không dùng làm tripwire tuyệt đối.

#### Danh mục thiết kế ứng viên cho Pulse (suy luận, chưa đo; đều chỉ cần counter trong BPF)
- **D1. Bin theo pha exec**: map `tgid → chỉ số syscall kể từ execve`. Khối startup và steady tách riêng (mục 2). Mô hình workload hiện tại chỉ ăn khối steady; khối startup chấm bằng novelty đường dẫn thư viện nếu có.
- **D2. Khối ý đồ** (khoảng 16–24 cột), mỗi cột đếm theo (nhóm syscall hoặc argument, errno ok hay fail):
  - `ptrace` theo nhóm request: TRACEME, ATTACH/SEIZE, POKE/SETREGS.
  - `mmap`/`mprotect` có `PROT_EXEC` trên vùng anonymous (fd=-1); W+X.
  - Nhóm namespace: `setns`/`unshare`/`clone`-NEW*.
  - Nhóm sandbox: `seccomp`/`prctl(PR_SET_SECCOMP)`.
  - Nhóm exec: `execve`/`execveat` thất bại.
  - Module: `init_module`/`finit_module`.
  - Kernel-API: `bpf`/`perf_event_open`/`keyctl`/`userfaultfd`/`personality`/`kexec_load`.
  - Credential: `setuid`*/`capset` thất bại.
  - `memfd_create` rồi exec.
  - Open đường dẫn nhạy cảm: `/proc/*/mem`, `/etc/shadow`, `release_agent`, `docker.sock`.

  Có thể đưa khối này thẳng vào vector 249 chiều hiện tại, hoặc làm nhánh "support" thứ hai.
- **D3. Định tuyến theo executable**: hash inode exe kèm cờ "đã thấy trong normal của workload".
  - Executable đã thấy: dùng mô hình hiện tại.
  - Executable chưa thấy: chỉ D1-steady + D2, hiệu chỉnh trên tập exec vô hại (D4).
- **D4. Hiệu chỉnh riêng cho process do exec tạo ra** (Mondrian/class-conditional conformal):
  - Calibration set là các lệnh admin vô hại chạy qua `kubectl exec` (`ls`, `cat`, `ps`, `env`, `sh -c`, `curl`, `python -c`, trình quản lý gói ở chế độ list).
  - Không dùng trạng thái steady của workload làm calibration cho nhóm này.
  - Nhận diện process exec bằng chuỗi cha: con của `runc init` hoặc containerd-shim, không phải hậu duệ của PID 1 trong container.
  - Khái niệm Mondrian CP là kiến thức chung, chưa lấy nguồn trong phiên này.
- **D5. Chấm khi process kết thúc**: với process sống dưới 0,5 s, chấm ngay ở `sched_process_exit` bằng vector đời process. Có thể rút ngắn kernel-to-alert so với chờ đủ 2 cửa sổ liên tiếp. Tuy vậy, luật "2 cửa sổ liên tiếp" phải được định nghĩa lại cho trường hợp này.

### Gaps
- Không tìm được bài nào đo FPR của đặc trưng ý đồ (danh sách syscall nhạy cảm, W→X, errno) trên binary mới vô hại hoặc lệnh admin trong container.
- Rule Falco/Tracee không có số FPR công bố.
  - [Snippet] Một bài SCITEPRESS 2025 so sánh Falco, Tetragon và Tracee về MTTD, và báo cáo không có báo nhầm trên kịch bản thử nhỏ. Chưa đọc được toàn văn (link PDF trả về HTML). — [SCITEPRESS 2025](https://www.scitepress.org/PublishedPapers/2025/142727)
- Không đọc được toàn văn Mutz et al. 2006 (TISSEC; link PDF trả về HTML) và Maggi et al. 2010 (TDSC). Ghi chú LID-DS đã có Kruegel 2003 và Mutz 2007 (RAID, context).
- Không xác minh được tỉ lệ dùng `PTRACE_TRACEME` chống debug trong malware Linux. Bảng VII của Cozzi chỉ có "ptrace request on another process" (0,38 %).

## 4. Mô hình sequence và graph theo thread (STIDE, BoSC, graph, LSTM/GRU, Transformer, LLM 2023–2026): FPR trên chương trình vô hại chưa thấy và độ trễ mỗi quyết định

### Takeaway
Không có bài nào báo cáo riêng FPR trên chương trình vô hại chưa thấy. Dataset gần nhất là DongTing: normal là 6.850 chương trình test hồi quy kernel, tấn công là chương trình kích hoạt bug. Mỗi mẫu là một chương trình riêng, tức đúng dạng "process mới vô hại vs process mới độc hại". Transformer decoder-only trên DongTing đạt AUC 0,979 so với LSTM 0,972, nhưng trên ADFA-LD chỉ 0,425 so với 0,292. Mô hình sequence cần cửa sổ dài (512 syscall), trong khi toàn bộ đời binary đối chứng chỉ khoảng 31 syscall. Mô hình sequence theo thread vì thế không giải quyết trực tiếp burst exec; nó hợp với exploit chạy trong process đã có (Heartbleed: DR từ 0,00 lên 0,95 với thread info).

### Cited Findings
- [Đo] **Elnagar & Sovio** (poster Helsinki 2026): Transformer decoder-only dự đoán token kế tiếp, cửa sổ 512, stride 256, train chỉ trên normal.

  | Dataset | AUC (bài) | AUC LSTM (2 lớp, 400 cell) |
  |---|---|---|
  | DongTing | 0,979 | 0,972 |
  | ADFA-LD | 0,425 | 0,292 |
  | PLAID | 0,878 | 0,750 |

  Thời gian suy luận trung bình: ONNX 149,66 ms trên Raspberry Pi và 33,65 ms trên Jetson; TensorRT 21,94 ms trên Jetson; TFLite giảm AUC xuống 0,880. Đây là poster, không có FPR. — [Poster PDF](https://haic.fi/wp-content/uploads/2026/05/Explainable-Anomaly-Detection-in-System-Call-Sequences.pdf)
- [Snippet] **DongTing** (Zenodo, 2022):
  - 18.966 sequence. Phía tấn công có 12.116 sequence từ 17.855 chương trình kích hoạt bug, trên 26 bản kernel.
  - Phía normal có 6.850 chương trình từ 4 bộ test hồi quy kernel.
  - Baseline: CNN/RNN, LSTM, Wavenet, ECOD.

  — [Zenodo record 6627050](https://zenodo.org/records/6627050)
- [Đo] LID-DS 2019 với thread information (EISA 2021): STIDE DR 0,986 với FA 61,5; BoSC DR 0,986 với FA 110,4; SCG DR 0,895 với FA 29,1. FA là số cụm báo động. — [EISA 2021](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- [Đo] Độ trễ CHIDS:
  - Chuỗi tốt nhất ứng với τ = 100 ms.
  - Xử lý 30 sequence, mỗi sequence 10k–20k syscall, song song trong trung bình 3,52 s (laptop i7-10850H, 8 core). Nhanh hơn CDL 3,25 s và nhanh hơn STIDE-BoSC 5,15 phút.
  - STIDE-BoSC với 10-gram trên sequence dài mất "minutes of processing" và mất đồng bộ với thời gian thực.

  — [CHIDS PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf)
- [Đo] Fournier et al. 2023: LSTM ngang hoặc hơn Transformer ở 3/6 hành vi mới; attention chủ yếu cục bộ (đã có ở ghi chú trước). — [arXiv 2309.02206](https://arxiv.org/pdf/2309.02206)
- [Snippet] OMNISEC (LLM, provenance, arXiv 2025) lập luận rằng phương pháp đã học hành vi có sẵn có thể gắn cờ "new but legitimate operations", làm tăng báo nhầm. Hệ này dựng knowledge base hành vi vô hại từ log. Không có số FPR trên chương trình mới. — [arXiv 2503.03108](https://arxiv.org/pdf/2503.03108)

### Inferences
- Với binary đối chứng (khoảng 31 syscall cả đời, theo đo cục bộ), một cửa sổ 512 syscall của sequence model chủ yếu là padding hoặc syscall của process khác. Mô hình n-gram hay Transformer theo thread sẽ chấm burst loader của một binary C có sẵn trong image hoàn toàn quen thuộc, vì loader giống nhau giữa các binary glibc.

  Vì vậy sequence theo thread có thể **giảm** báo nhầm cho binary đối chứng (burst `/bin/true` trùng với burst `g_dyn`, chỉ thiếu `getpid`), với điều kiện normal của workload có ít nhất một lần exec binary glibc. Burst của runc thì chưa rõ. Đây là giả thuyết kiểm được ngay trên dữ liệu live của Pulse.
- Về độ trễ, STIDE theo thread (hash n-gram) và BoSC chạy được trong ngân sách dưới 2 s. LSTM/Transformer cần khoảng 20–150 ms mỗi cửa sổ trên phần cứng edge (poster Helsinki), vẫn trong ngân sách. Nhưng chưa có bằng chứng chúng hơn n-gram có ngưỡng trên LID-DS (ghi chú trước).

### Gaps
- Không tìm được FPR công bố theo chương trình chưa thấy cho LSTM/Transformer/LLM. Bài báo đầy đủ của DongTing (số FPR của baseline) chưa đọc được.
- Không tìm được classifier syscall dựa trên LLM (2023–2026) nào có cả FPR lẫn latency trên container. eBPF-Guard (Empirical Software Engineering 2026) chỉ có abstract, không có số.

## 5. Có đánh giá nào chứa nhóm đối chứng "process mới vô hại", hoặc đo FPR trên hoạt động admin (kubectl exec, cron, health check, trình quản lý gói)?

### Takeaway
Không tìm được bài học thuật nào đo FPR trên `kubectl exec`/`docker exec` vô hại hay lệnh admin làm một lớp riêng. Các nguồn chỉ **thừa nhận** đây là nguồn báo nhầm: ReplicaWatcher (phần hạn chế), mô tả rule Falco ("administrators or SREs performing ad-hoc debugging"), MITRE DET0065. Sản phẩm thì né bằng thiết kế: RHACS chỉ báo "risk" khi baseline chưa khoá. Nhóm đối chứng của Pulse (binary chỉ gọi `getpid` qua cùng đường `kubectl exec`) có vẻ là thiết kế đánh giá chưa ai công bố. Nên giữ và mở rộng nó thành bộ lệnh admin thật.

### Cited Findings
- [Tài liệu] ReplicaWatcher thừa nhận hoạt động DevOps hoặc bảo trì như "execing into a pod for debugging" có thể bị phân loại là anomaly. Bài không có số đo cho lớp này. — [ReplicaWatcher NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Mã nguồn] Falco "Terminal shell in container": `spawned_process and shell_procs and proc.tty != 0`, tức `kubectl exec -it` mở shell. Rule upper-layer liệt kê admin/SRE debug là anti-pattern. — [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- [Mã nguồn] Falco k8saudit "Attach/Exec Pod" (NOTICE): `ka.target.subresource in (exec,attach)`. Output gồm user, pod, namespace và `command=%ka.uri.param[command]`. Nghĩa là audit log của Kubernetes cho biết ai exec lệnh gì, độc lập với syscall. — [k8s_audit_rules.yaml](https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/rules/k8s_audit_rules.yaml)
- [Snippet] MITRE DET0065 (Container Administration Command Abuse) chỉ coi exec là đáng ngờ khi bất thường: user lạ, IP nguồn lạ, namespace lạ, tần suất tăng đột biến, hoặc process sinh ra ngoài dự kiến trong container. — [MITRE DET0065](https://attack.mitre.org/detectionstrategies/DET0065/)
- [Tài liệu] RHACS: trước khi khoá baseline, process mới "show up as risks, but they do not trigger any violations". — [RHACS docs](https://docs.redhat.com/ko/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.7/html/operating/use-process-baselines_evaluate-security-risks)
- [Đo] CHIDS ghi nhận hành vi người dùng "non-repetitive", có thể vô tình sinh syscall hoặc argument chưa thấy. Ở CWE-307, argument chưa thấy xuất hiện ở trace normal nhiều hơn ở trace tấn công. — [CHIDS PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf)
- [Tài liệu] Ở pha trinh sát kill chain, ReplicaWatcher cho kẻ tấn công dùng lệnh built-in của shell (`read < /etc/passwd`, `echo $USER`), vốn "yielding no new processes or syscalls". Như vậy chính lệnh admin kiểu `whoami`, `cat` là thứ phân biệt được, còn kẻ tấn công cẩn thận có thể né. — [ReplicaWatcher NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)

### Inferences
- Audit log của Kubernetes (sự kiện `pods/exec`) cho nhãn nguồn gốc của mỗi process exec: user, command. Có thể dùng nhãn này để (a) gom process exec vào lớp calibration riêng (D4) và (b) giải thích alert. Nhưng **không được** dùng nó để bỏ qua alert: MITRE coi việc lạm dụng lệnh quản trị container (`kubectl exec`, `docker exec`) là một kỹ thuật tấn công. DET0065 là chiến lược phát hiện cho nó ([MITRE DET0065](https://attack.mitre.org/detectionstrategies/DET0065/)).
- Bộ đối chứng đề xuất (suy luận) cho campaign live, giữ đúng đường `kubectl exec`:
  1. `getpid` (đã có).
  2. Các lệnh có sẵn trong image: `ls`, `cat /etc/os-release`, `ps`, `env`, `id`, `sh -c 'echo'`.
  3. Một interpreter (`python3 -c pass` hoặc `node -e 0`) nếu image có.
  4. Health check thật của workload (lệnh của exec probe).
  5. Một binary Go nhỏ (runtime khác, burst khoảng hàng trăm đến hàng nghìn syscall).

  Đo FPR theo từng loại, báo cáo tách khỏi FPR của workload steady-state.
- Kết quả hiện tại của Pulse (đối chứng bị gắn cờ 86–95 %) thật ra khớp với dự báo của văn liệu (ReplicaWatcher, Falco). Có thể trình bày đây là phép đo định lượng đầu tiên cho một hạn chế mà các bài khác chỉ thừa nhận bằng lời. Đây là đánh giá về khả năng đóng góp, không phải kết quả đo.

### Gaps
- Không tìm được dataset công khai nào có lớp "benign exec/admin session" gắn nhãn trên syscall. LID-DS 2021, CB-DS (CHIDS) và ADFA-LD đều không mô tả lớp này. Dataset Kubernetes misuse (AINA 2024) chỉ có network flow ([Kaggle](https://www.kaggle.com/datasets/yigitsever/misuse-detection-in-containers-dataset), theo mô tả trên trang).
- Không có số FPR công bố cho cron, trình quản lý gói hay exec probe trong container.
