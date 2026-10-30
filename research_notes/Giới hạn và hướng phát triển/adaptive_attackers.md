# Kẻ tấn công thích nghi, né tránh (evasion) và đánh giá độ bền cho bộ phát hiện xâm nhập container dựa trên syscall (Sentinel Pulse)

Ghi chú nghiên cứu, viết ngày 30/10/2026. Quy ước: **[Đo]** = kết quả đo trong bài báo/thí nghiệm; **[Tuyên bố]** = tác giả/vendor khẳng định, không kèm số đo; **[Suy luận]** = suy luận của người viết ghi chú, chưa kiểm chứng. Các nguồn PDF chính (Wagner & Soto, Tan et al., Kruegel et al., Goyal et al., ReplicaWatcher, Apruzzese et al.) đã được tải về và đọc toàn văn bằng `pdftotext`; số liệu dưới đây trích trực tiếp từ đó.

## 1. Mimicry và evasion chống bộ phát hiện syscall: mỗi công trình đã đo gì?

### Takeaway
Từ 2002 đến nay, mọi công trình tấn công nghiêm túc đều cho thấy bộ phát hiện chỉ nhìn tên/thứ tự/tần suất syscall có thể bị né với tỷ lệ gần 100 % nếu kẻ tấn công biết mô hình bình thường (Wagner & Soto: 0 mismatch; Goyal et al. 2023: 100 % trên 5 Prov-HIDS). Cái giá phải trả là kẻ tấn công phải bỏ bớt mục tiêu (không mở shell, chỉ ghi file) hoặc độn thêm hành vi bình thường. Hướng hiện đại (io_uring "Curing" 2025) né hẳn lớp syscall, nhưng vẫn phải gọi `io_uring_setup`/`io_uring_enter`.

### Cited Findings

**Wagner & Soto, ACM CCS 2002, "Mimicry Attacks on Host-Based Intrusion Detection Systems"** — [PDF](https://people.eecs.berkeley.edu/~daw/papers/mimicry.pdf)
- [Đo] Mục tiêu là pH 0.17 (dẫn xuất từ hệ của Forrest/stide) trên Red Hat 5.0, kernel 2.2.19. pH làm chậm mỗi syscall 2^m đơn vị thời gian, với m = số subtrace độ dài 6 không khớp trong 128 syscall gần nhất. pH được huấn luyện trên wuftpd (wu-2.4.2-academ[BETA-15]) — [PDF](https://people.eecs.berkeley.edu/~daw/papers/mimicry.pdf)
- [Đo] Exploit gốc `autowux.c` (lỗi format string "site exec" của wuftpd) gồm 15 syscall: `setreuid(0,0), dup2(1,2), mkdir("sh"), chroot("sh"), 9 × chdir(".."), chroot("/"), execve("/bin/sh")`. Tìm kiếm tự động trên tích automaton A × M cho thấy A ∩ M = ∅: không có cách độn nào cứu được, vì cơ sở dữ liệu bình thường không có đường nào dẫn tới `dup2()`, `mkdir()` hay `execve()` — [PDF](https://people.eecs.berkeley.edu/~daw/papers/mimicry.pdf)
- [Đo] Đổi mục tiêu (bỏ shell, thêm tài khoản root backdoor vào file mật khẩu) thành `setreuid, chroot, chdir, chroot, open, write, close, exit`, chèn thêm "no-op" thì tìm được chuỗi tàng hình. Chạy lại chuỗi này qua stide trên cùng database cho **0 mismatch**, nên chuỗi thành công với mọi ngưỡng "locality frame count" của pH. Tìm chuỗi này chỉ mất "vài giờ khám phá tương tác", và thuật toán chạy dưới 1 giây (A có vài nghìn trạng thái) — [PDF](https://people.eecs.berkeley.edu/~daw/papers/mimicry.pdf)
- [Tuyên bố/hạn chế tự nêu] Tác giả chưa biên dịch chuỗi thành exploit thật. Họ chỉ thử 1 exploit, 1 ứng dụng, 1 OS, và không thử pH 0.18 (cửa sổ 9) — [PDF](https://people.eecs.berkeley.edu/~daw/papers/mimicry.pdf)
- [Tuyên bố] Khuyến nghị: theo dõi cả đối số và mã lỗi của syscall, giữ database bình thường "càng tối thiểu và chính xác càng tốt", **mọi bài đề xuất IDS mới cần phân tích độ an toàn trước evasion**, và công bố mã nguồn — [PDF](https://people.eecs.berkeley.edu/~daw/papers/mimicry.pdf)

**Tan, Killourhy & Maxion, RAID 2002, "Undermining an Anomaly-Based Intrusion Detection System Using Common Exploits"** — [PDF](https://www.cs.cmu.edu/~maxion/pubs/TanKillourhyMaxion02.pdf)
- [Đo] stide trượt cửa sổ kích thước DW. Stide chỉ phát hiện được một *minimal foreign sequence* (MFS) khi DW ≥ kích thước MFS. Đây là "vùng mù" có thể đo được bằng bản đồ phát hiện (detection map) trên dữ liệu tổng hợp — [PDF](https://www.cs.cmu.edu/~maxion/pubs/TanKillourhyMaxion02.pdf)
- [Đo] Khi chưa sửa, exploit `traceroute` và `passwd` bị phát hiện ở mọi DW từ 1 đến 15, vì chúng sinh ra syscall lạ (foreign symbol, MFS kích thước 1). Muốn tàng hình, exploit không được sinh `setuid`, `setgid`, …. Mỗi lần sửa exploit, MFS tăng dần 1 → 2 → 3…, và với DW = 6 (giá trị phổ biến trong tài liệu) thì MFS ≥ 7 là vô hình. Theo bài, với dữ liệu traceroute "không thể" đẩy lên đúng MFS = 7, nhưng phần kết luận khẳng định cả hai exploit đã được giấu khỏi stide — [PDF](https://www.cs.cmu.edu/~maxion/pubs/TanKillourhyMaxion02.pdf)
- [Đo/phương pháp] Đóng góp về phương pháp: xác định trước vùng mù của detector trên dữ liệu tổng hợp, rồi sửa exploit thật để rơi đúng vào vùng mù đó — [PDF](https://www.cs.cmu.edu/~maxion/pubs/TanKillourhyMaxion02.pdf)

**Kruegel, Kirda, Mutz, Robertson & Vigna, USENIX Security 2005, "Automating Mimicry Attacks Using Static Binary Analysis"** — [PDF](https://www.usenix.org/legacy/events/sec05/tech/full_papers/kruegel/kruegel.pdf)
- [Đo] Bài nhắm vào các monitor "gray-box" kiểm tra cả program counter và cấu hình call stack tại mỗi syscall. Công cụ phân tích tĩnh nhị phân x86 dùng symbolic execution để tìm lệnh có thể chuyển hướng control flow, nhờ vậy kẻ tấn công lấy lại quyền điều khiển sau mỗi syscall và phát từng syscall trong đúng ngữ cảnh. Kết quả: khai thác thành công **3 chương trình dễ tổn thương**, né được các monitor tối tân lúc đó, và phân tích thêm 3 ứng dụng thực để kiểm tra tính áp dụng — [PDF](https://www.usenix.org/legacy/events/sec05/tech/full_papers/kruegel/kruegel.pdf)

**Parampalli, Sekar & Johnson, ASIACCS 2008, pp. 156–167, "A practical mimicry attack against powerful system-call monitors"** — [Crossref](https://api.crossref.org/works/10.1145/1368310.1368334); [abstract](https://researchconnect.stonybrook.edu/en/publications/a-practical-mimicry-attack-against-powerful-system-call-monitors/)
- [Tuyên bố, từ abstract] "Persistent interposition attacks" chỉ cần kỹ năng hacker thông thường. Chúng yếu hơn mimicry cổ điển (không lấy được root shell) nhưng đủ cho mục tiêu tội phạm như thu thập thông tin lén lút. Chúng né được các monitor "I/O-data-oblivious", nhóm bao gồm nhiều IDS black-box và gray-box — [abstract](https://researchconnect.stonybrook.edu/en/publications/a-practical-mimicry-attack-against-powerful-system-call-monitors/)
- Tôi chưa đọc được toàn văn, nên không có số đo cụ thể (xem Gaps).

**Goyal, Han, Wang & Bates (NDSS 2023), "Sometimes, You Aren't What You Do: Mimicry Attacks against Provenance Graph Host Intrusion Detection Systems"** — [PDF](https://gangw.cs.illinois.edu/ndss23-mimicry.pdf)
- [Đo] Bài thử 5 Prov-HIDS: StreamSpot, Unicorn, ProvDetector, Pagoda và một Full Graph Autoencoder (kiểu SIGL). Trên hơn 100 mẫu đồ thị tấn công (dữ liệu công khai), tỷ lệ né đạt **100 %** với mọi hệ, **không cần sửa hành vi tấn công**, chỉ cần nhúng các cấu trúc con lành tính vào đồ thị. Né được cả ensemble nhiều Prov-HIDS, và cách này khả thi trong demo tấn công thật — [PDF](https://gangw.cs.illinois.edu/ndss23-mimicry.pdf)
- [Đo] Kỹ thuật adversarial tổng quát RL-S2V chạy **7 ngày** mà không tạo được mẫu né nào, kể cả với StreamSpot. Nghĩa là tấn công dựa trên hiểu biết miền (domain-specific) mạnh hơn hẳn tấn công gradient/RL tổng quát — [PDF](https://gangw.cs.illinois.edu/ndss23-mimicry.pdf)
- [Tuyên bố] Nguyên nhân: mã hóa "unweighted" (mọi sự kiện trong cửa sổ có trọng số như nhau) và chuẩn hóa điểm trên toàn đồ thị khiến việc độn hành vi lành tính kéo điểm bất thường xuống. Đề xuất giảm thiểu: phân loại ở mức hạt mịn hơn (node/edge/subgraph) thay vì toàn đồ thị — [PDF](https://gangw.cs.illinois.edu/ndss23-mimicry.pdf)

**Adversarial ML trên chuỗi API/log (2018–2021)**
- [Tuyên bố] Rosenberg et al., RAID 2018: tấn công black-box tạo chuỗi API call cộng đặc trưng tĩnh, vẫn giữ chức năng malware. Tấn công hiệu quả với nhiều classifier (biến thể RNN, DNN, SVM) nhờ transferability. Kèm framework GADGET để biến đổi binary mà không cần mã nguồn — [arXiv 1707.05970](https://arxiv.org/abs/1707.05970). Abstract không có tỷ lệ né cụ thể.
- [Tuyên bố] LAM (Log Anomaly Mask, ACM CODASPY 2021): nhiễu loạn log streaming theo thời gian thực, sửa tối thiểu để né cả các mô hình deep learning tối tân phát hiện bất thường log — [ACM DL](https://dl.acm.org/doi/10.1145/3422337.3447833)

**Né tầng syscall: io_uring "Curing" (ARMO, 24/04/2025)** — [ARMO blog](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security); [GitHub armosec/curing](https://github.com/armosec/curing)
- [Đo, theo vendor] Rootkit PoC chạy hoàn toàn qua io_uring (có từ Linux 5.1). Nó lấy lệnh từ C2 và thực thi thao tác file/mạng mà không gọi các syscall tương ứng. Lúc viết bài có 61 opcode io_uring — [ARMO](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security)
- [Đo, theo vendor] Falco "mù" kể cả với rule tùy biến. Tetragon bỏ sót với một số policy mẫu dựa trên syscall hook, nhưng bắt được nếu người dùng tự cấu hình kprobe/LSM hook. Microsoft Defender for Endpoint (Linux) không phát hiện đọc file, EICAR, XMRig hay kết nối mạng uy tín thấp, dù có hay không có io_uring; chỉ FIM thấy được sửa file — [ARMO](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security)

### Inferences
- [Suy luận] Theo khung của Tan et al., **tripwire của Pulse tương đương stide với DW = 1** (chỉ bắt foreign symbol), còn các bin cặp syscall băm tương đương DW = 2 (có va chạm hash). Một kẻ tấn công chỉ dùng syscall và cặp syscall đã có trong reference thì nằm hoàn toàn trong vùng mù của hai thành phần này. Khi đó chỉ còn nhánh tần suất (ExtraTrees + support) chống đỡ.
- [Suy luận] Bài học của Wagner & Soto áp dụng trực tiếp: kẻ tấn công thực tế sẽ bỏ `execve` shell, vì trong container `execve` của binary mới rất dễ lộ. Pulse đã thấy điều này: tiến trình mới vô hại bị gắn cờ khoảng 90 %. Thay vào đó, họ thực hiện mục tiêu (đọc secret, ghi file, gửi mạng) bằng chính tiến trình bị chiếm và các syscall mà workload vốn dùng (`openat/read/write/sendto`).
- [Suy luận] Goyal et al. cho thấy mã hóa "đếm đều trong cửa sổ" dễ bị pha loãng bởi hoạt động lành tính được độn thêm. Vector 249 chiều của Pulse (đếm + rolling stats) có cùng tính chất.
- [Suy luận] Curing vẫn phải gọi `io_uring_setup` và `io_uring_enter`. Với workload không dùng io_uring trong reference, **tripwire của Pulse sẽ bắt được** ngay lần đầu, miễn là eBPF của Pulse đếm mọi syscall ID chứ không chỉ 29 syscall có tên. Điều này cần kiểm chứng trên lab.

### Gaps
- Chưa đọc được toàn văn Parampalli et al. 2008, nên thiếu số đo.
- Không tìm thấy bài nào (2018–2026) đo né adversarial trên **LID-DS** hoặc trên HIDS syscall dạng LSTM/transformer với số liệu cụ thể. Extended abstract arXiv 1803.09171 (LSTM branch models chống mimicry) chưa được kiểm chứng nội dung.
- Không có tỷ lệ né cụ thể cho Rosenberg et al. (chỉ có abstract).

## 2. Tấn công chậm (low-and-slow), pha loãng tần suất và bộ tích lũy dài hạn

### Takeaway
Các detector theo cửa sổ (kể cả ReplicaWatcher) đều thừa nhận rằng chia nhỏ tấn công theo thời gian sẽ né được từng cửa sổ. Bộ tích lũy kiểu CUSUM hoặc **conformal test martingale** (rất hợp vì Pulse đã có p-value conformal) có thể gom bằng chứng yếu qua nhiều cửa sổ, nhưng có chi phí độ trễ và vẫn có thể bị né bằng chiến lược on-off.

### Cited Findings
- [Đo] ReplicaWatcher thử tấn công rải theo thời gian (kill chain 4 pha: trinh sát, chuẩn bị, exfiltration, dọn dẹp; 8 lệnh mỗi pha; 1–6 lệnh mỗi snapshot; 3,690 snapshot). Pha dọn dẹp **né được với 3 lệnh đơn lẻ** (xóa file, xóa history). Tỷ lệ phát hiện tăng theo số lệnh mỗi snapshot. Exfiltration bị bắt hết, nhưng tác giả nói rõ kết quả "chỉ đúng với cài đặt exfiltration của chúng tôi (wget, curl)" — [NDSS 2024 PDF](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Đo/phương pháp] ReplicaWatcher dùng *cumulative detection probability* qua các snapshot: P(cml_Sn) kết hợp P(cml_Sn−1) với xác suất phát hiện tại Sn, giả định các snapshot độc lập. Mỗi pha dài 60 s, gồm 2 snapshot. Kịch bản "lén hơn" là 1 lệnh rồi nghỉ 1 snapshot — [NDSS 2024 PDF](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Tuyên bố] Kết luận của tác giả: tấn công né được ngưỡng "bị giới hạn về lượng hoạt động có thể làm mà không bị phát hiện" — [NDSS 2024 PDF](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Tuyên bố] CUSUM tích lũy log-likelihood ratio theo thời gian và chỉ báo động khi bằng chứng tích lũy đủ cao. Vì vậy kẻ tấn công có thể dùng chiến lược **on-off** (tấn công, nghỉ, lặp lại) để giữ thống kê thấp. Bài cho rằng tấn công tương tự áp dụng được cho mọi detector dựa trên CUSUM — [arXiv 1803.00128](https://arxiv.org/pdf/1803.00128)
- [Phương pháp] Quickest-detection dùng Average Detection Delay (ADD) và biến thể worst-case SADD (thời điểm bắt đầu tấn công xấu nhất) làm thước đo — [arXiv 2101.01466](https://arxiv.org/pdf/2101.01466)
- [Lý thuyết] Conformal (power) martingale: M_n = ∏ ε·p_i^(ε−1). Mỗi bước chỉ cần p-value mới nhất, không cần lưu lịch sử. Ho (ICML 2005) dùng ε = 0.92 và báo cáo phải cần khoảng 100–200 điểm mới bác bỏ được tính khả hoán ở α = 0.05, tức phát hiện tức thời "gần như không thể" — [Ho, ICML 2005](https://dev.icml.cc/Conferences/2005/proceedings/papers/041_AMartingale_Ho.pdf)
- [Lý thuyết] Ngưỡng Ville cho cận báo động sai *anytime*: λ = 100 ⇒ xác suất báo động sai ≤ 1 % trên toàn luồng — [nonconform, arXiv 2605.13642](https://arxiv.org/pdf/2605.13642)
- [Đo/phương pháp] Inductive conformal martingale cho change-point detection chỉ giả định i.i.d. và được so với oracle có tri thức tham số không chính xác — [Volkhonskiy et al., arXiv 1706.03415](https://ar5iv.arxiv.org/html/1706.03415)

### Inferences
- [Suy luận] Với Pulse: cửa sổ 0.5 s và luật "2 cửa sổ liên tiếp" là bộ lọc tức thời. Recall giảm xuống 79 % ở 1 hành động/s cho thấy đúng hiện tượng pha loãng mà ReplicaWatcher mô tả. Đề xuất chạy **song song** một bộ tích lũy dài hạn trên p-value conformal sẵn có, theo một trong hai cách: (a) CUSUM trên −log p với độ lệch k và có reset; (b) power/mixture martingale có "trần" (ví dụ Shiryaev–Roberts hoặc reset khi M < 1). Giữ nguyên đường báo động nhanh (<2–3 s) cho tấn công mạnh. Đường tích lũy chỉ thêm recall cho tấn công chậm, với mục tiêu độ trễ riêng (ví dụ ≤30–60 s), và báo cáo hai mức độ trễ tách biệt.
- [Suy luận] Rủi ro của cách này: (1) giả định khả hoán/độc lập bị vi phạm do tự tương quan giữa các cửa sổ, nên số báo động sai thực tế phải đo trên các run benign dài, không tin vào cận Ville; (2) kẻ tấn công on-off với chu kỳ dài hơn cửa sổ nhớ của bộ tích lũy vẫn né được, nên thí nghiệm phải quét tham số chu kỳ on-off.
- [Suy luận] Nếu tách được tiến trình hay cgroup, có thể dùng thêm một bộ đếm "lượng hoạt động bất thường tích lũy trên mỗi tiến trình mới" (budget tích lũy). Cách này buộc kẻ tấn công chậm phải trả giá bằng tổng thời gian, giống lập luận "bounded activity" của ReplicaWatcher.

### Gaps
- Không tìm thấy bài nào về HIDS syscall/container đo CUSUM hoặc martingale với tấn công low-and-slow cùng ràng buộc độ trễ cỡ giây. Các nguồn tìm được thuộc smart grid, CAN bus, DoS mạng.
- Không xác minh được cận độ trễ tối ưu bậc nhất của CUSUM (≈|log α|/I) bằng nguồn gốc trong lượt tìm này.

## 3. Né các công cụ runtime security (Falco, Tetragon, Tracee) và phản hồi của vendor

### Takeaway
Có ba lớp bypass đã được công bố: (1) **TOCTOU** đối số syscall (Phantom attack, DEF CON 29, Falco/Tracee; CVE-2021-33505); (2) **đường không qua syscall hook** (io_uring "Curing" 2025); (3) đặt rule sai mức trừu tượng (đường dẫn, tên tiến trình). Phản hồi của vendor là chuyển sang hook LSM/kprobe (KRSI). Riêng Isovalent phủ nhận rằng Tetragon "phụ thuộc syscall".

### Cited Findings
- [Tuyên bố] Phantom attack (Rex Guo và cộng sự, DEF CON 29, 2021) là một họ tấn công né giám sát syscall Linux. Chương trình user mode "không cần đặc quyền hay capability đặc biệt" để né một cách tin cậy, do cài đặt tracing không an toàn. Demo trên Falco (Sysdig) và Tracee (Aqua). Trang talk tham chiếu CVE-2021-33505 — [infocondb DEF CON 29](https://infocondb.org/con/def-con/def-con-29/phantom-attack-evading-system-call-monitoring)
- [Tuyên bố, nguồn thứ cấp] CVE-2021-33505: engine phát hiện của Falco bị vượt qua bằng một chương trình thay đổi đối số của syscall đang thực thi; đã sửa ở Falco 0.29.1 — [ocve.arawa.fr](https://ocve.arawa.fr/cve/CVE-2021-33505) (trang NVD không tải được nội dung khi kiểm tra).
- [Tuyên bố] Talk tiếp theo "Trace me if you can: Bypassing Linux Syscall Tracing" (Guo & Zeng) phân tích TOCTOU trong framework tracing syscall của kernel. Talk cho thấy có thể chèn độ trễ thực thi syscall lớn để TOCTOU tin cậy kể cả khi bật seccomp/SELinux/AppArmor, không cần đồng bộ thời gian chính xác. Demo trên Falco (VM, container, GKE) và pdig trên AWS Fargate — [DEF CON forum](https://forum.defcon.org/node/241839)
- [Đo, theo vendor] Curing/io_uring: Falco mù và maintainer "phản hồi nhanh", đang làm plugin dùng LSM hook eBPF. Tetragon bắt được khi cấu hình kprobe/LSM, và đội Tetragon không coi đây là lỗ hổng. Microsoft không phản hồi. SentinelOne xác nhận không bị ảnh hưởng — [ARMO](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security)
- [Tuyên bố] Liz Rice (Isovalent) phản bác rằng Tetragon "relies on syscall monitoring" và trỏ tới một blog post của đội — [CSO Online](https://www.csoonline.com/article/3971170/proof-of-concept-bypass-shows-weakness-in-linux-security-tools-claims-israeli-vendor.html)
- [Tuyên bố] Khuyến nghị của ARMO: giám sát việc dùng io_uring bất thường ở ứng dụng vốn không dùng (có thể sinh false positive); dùng KRSI (eBPF trên LSM hook) như hướng bền vững dài hạn; tìm hook point thay thế (kprobe truy cập file) nhưng phải ổn định qua các phiên bản kernel — [ARMO](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security)
- [Đo] Tổng quan hệ thống về bảo mật dựa trên eBPF: 96.2 % (52/54) nghiên cứu không xét đến lỗ hổng của chính eBPF; độ bền adversarial ML là một khoảng trống được nêu rõ — [arXiv 2608.27511](https://arxiv.org/pdf/2608.27511)
- [Tuyên bố] ReplicaWatcher loại khỏi phạm vi "các tấn công vượt qua hoặc không lộ ở giao diện syscall" — [NDSS 2024 PDF](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)

### Inferences
- [Suy luận] Pulse chỉ **đếm syscall ID** chứ không đọc đối số, nên TOCTOU đối số (Phantom) không làm Pulse "nhìn sai". Đổi lại, Pulse cũng không bao giờ thấy nội dung đối số, và đây chính là lớp "I/O-data-oblivious monitor" mà Parampalli et al. nhắm tới.
- [Suy luận] Lỗ hổng thực sự của Pulse trước io_uring nằm ở **phần thân hoạt động**: sau khi thiết lập, các thao tác đọc/ghi/mạng đi qua SQE và không sinh thêm syscall riêng. Một workload *vốn đã dùng* io_uring (một số DB/proxy hiện đại) sẽ có `io_uring_enter` trong reference, nên tripwire không giúp được. Biện pháp phòng thủ khả thi và miễn phí: (a) tripwire coi `io_uring_setup` là ID nhạy cảm, luôn báo dù có replica discount; (b) gắn thêm kprobe hoặc tracepoint `io_uring:io_uring_submit_req` (tracepoint này có trong kernel mainline) để đếm opcode io_uring như "syscall ảo"; (c) dùng seccomp RuntimeDefault của Kubernetes. Cần kiểm tra lại profile RuntimeDefault của containerd/Docker trên lab có chặn `io_uring_*` hay không (chưa xác minh, xem Gaps).
- [Suy luận] Kẻ tấn công cũng có thể tắt hoặc làm quá tải chính agent eBPF (mất sự kiện ring buffer). Cần thêm tín hiệu "heartbeat / tỷ lệ drop" vào báo cáo, nhưng thí nghiệm này nằm ngoài phạm vi theo memory "không test hạ tầng".

### Gaps
- Không đọc được slide/video Phantom, nên thiếu cơ chế chi tiết của v1/v2 và năm của talk "Trace me if you can".
- Không tìm thấy blog post chính thức của Isovalent về io_uring, cũng như bằng chứng Falco đã phát hành plugin LSM (tính đến 10/2026).
- Không xác minh được profile seccomp mặc định nào (Docker, containerd, Kubernetes RuntimeDefault) chặn `io_uring_setup`.
- Lượt tìm về bypass Falco bằng symlink/đường dẫn bị công cụ tìm kiếm từ chối, nên không có nguồn trích dẫn cho mục này.

## 4. Tấn công đồng loạt mọi replica (collusion) chống detector so sánh replica/peer

### Takeaway
ReplicaWatcher (NDSS 2024) **giả định thẳng trong threat model** rằng kẻ tấn công không thể tấn công đồng thời và giống hệt nhau mọi replica. Họ chỉ phản bác bằng lập luận thực tiễn (phải biết số replica, có HPA, có traffic lành tính chen vào, có round-robin), không có thí nghiệm. Replica discount của Pulse có cùng điểm yếu, và còn nặng hơn vì nó *xóa* bằng chứng thay vì chỉ so sánh.

### Cited Findings
- [Đo] ReplicaWatcher: precision trung bình 91.08 %, recall 98.35 % trên các kịch bản tấn công của họ; triển khai 4 replica mỗi microservice; ngưỡng thống nhất ε = 0.3 — [NDSS 2024 PDF](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Tuyên bố – threat model] "We also assume that attackers cannot initiate an identical attack on all replicas, simultaneously. While such an attack is theoretically possible, its practical execution is challenging and requires an attacker to have full knowledge of the target system. Furthermore, such a massive attack would unavoidably leave traces that approaches orthogonal to ours can spot, e.g., via network traffic." — [NDSS 2024 PDF](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Tuyên bố – Discussion] Có hai cách né. (1) Tác động đồng thời mọi replica với cùng input, nhưng việc này cần biết số replica (thường thay đổi theo HPA); traffic lành tính đồng thời làm nhiễu việc phân phối tấn công; dùng sticky session có thể làm lộ pattern nhưng "vẫn có thể bị né bằng IP/phiên khác nhau". (2) Chia tấn công thành các giai đoạn dưới ngưỡng, nhưng khó biết ngưỡng chính xác và khó đảm bảo mọi giai đoạn tới cùng replica do round-robin — [NDSS 2024 PDF](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Tuyên bố] Hạn chế được tác giả thừa nhận: (a) brute-force bị Ingress round-robin rải "đều" qua các replica nên che khuất, và hướng giải là theo dõi tần suất syscall; (b) multi-cluster gây dị biệt và độ trễ; (c) phải giả định mọi replica cùng phiên bản code và rollout đồng thời, trong khi rolling update phá giả định này — [NDSS 2024 PDF](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)

### Inferences
- [Suy luận] Trong kịch bản của Pulse (tấn công qua `kubectl exec`, tức kẻ tấn công đã có credential API), tấn công mọi replica **rất rẻ**: liệt kê pod theo label rồi `exec` song song, không cần route qua load balancer. Lập luận "khó thực hiện" của ReplicaWatcher (vốn giả định tấn công qua mạng công khai) **không chuyển sang** threat model của Pulse.
- [Suy luận] Phòng thủ khả thi cho replica discount:
  1. Chỉ discount các syscall ID đã có trong **reference/lịch sử trước đó** của workload, không discount ID mới xuất hiện đồng thời ở mọi replica. Tripwire nên ưu tiên hơn discount.
  2. Phát hiện **đồng bộ bất thường**: nhiều replica cùng có một sự kiện hiếm (ví dụ tiến trình mới, `execve` một binary lạ) trong cửa sổ cỡ vài giây là tín hiệu tấn công, không phải bằng chứng lành tính. Điều này đặc biệt đúng nếu không có rollout hay đổi image trong khoảng đó; có thể kiểm tra qua Kubernetes API (generation/ReplicaSet hash).
  3. Giới hạn trần discount, ví dụ không bao giờ hạ điểm xuống dưới một mức sàn khi mọi replica đều lệch khỏi reference.
  4. Đối chiếu sự kiện `exec` qua audit log của API server (miễn phí, có sẵn trong Kubernetes). Đây là tín hiệu "orthogonal" mà ReplicaWatcher nhắc tới.
- [Suy luận] Rolling update là nguồn false positive hoặc false negative tự nhiên cho cả hai hệ. Nên tách riêng thành một điều kiện trong thí nghiệm.

### Gaps
- Không tìm thấy công trình nào **đo thực nghiệm** tấn công đồng loạt mọi replica chống detector peer-comparison, hoặc đề xuất phòng thủ có số liệu. Đây là khoảng trống mà Pulse có thể lấp.

## 5. Thiết kế thí nghiệm kẻ tấn công thích nghi: protocol tối thiểu nhưng đáng tin

### Takeaway
Các bài nghiêm túc (Wagner & Soto, Tan et al., Goyal et al., ReplicaWatcher §VI-H) đều làm ba việc: (1) khai báo rõ tri thức và khả năng của kẻ tấn công cho từng thành phần; (2) giữ nguyên **mục tiêu tấn công có thể kiểm chứng** trong khi biến đổi cách thực hiện; (3) báo cáo tỷ lệ phát hiện theo **ngân sách của kẻ tấn công** (độ dài độn, tốc độ, số lệnh/snapshot), chứ không báo cáo một con số duy nhất. Apruzzese et al. bổ sung yêu cầu mô hình hóa chi phí.

### Cited Findings
- [Tuyên bố – position] Nên dùng thuật ngữ *perfect / limited / zero knowledge* cho tri thức của kẻ tấn công, và chỉ rõ áp dụng cho thành phần nào của hệ ML. Quyền truy cập phải ghi chính xác (read/write) cho từng thành phần. Threat model phải gắn với chi phí, vì kẻ tấn công thực tế có mục tiêu rộng hơn việc phá một mô hình — [Apruzzese et al., SaTML 2023, arXiv 2212.14315](https://arxiv.org/abs/2212.14315)
- [Tuyên bố] Bằng chứng thực tế cho thấy kẻ tấn công thật dùng chiến thuật đơn giản (đoán, heuristic thô) thay vì tính gradient — [Apruzzese et al.](https://arxiv.org/abs/2212.14315)
- [Đo] Tấn công dựa trên tri thức miền mạnh hơn tấn công adversarial tổng quát: 100 % so với 0 mẫu sau 7 ngày RL-S2V — [Goyal et al. NDSS 2023](https://gangw.cs.illinois.edu/ndss23-mimicry.pdf)
- [Phương pháp] Wagner & Soto kiểm chứng tính tàng hình bằng cách chạy chuỗi qua chính detector (stide, 0 mismatch) và ghi rõ hạn chế (chưa biên dịch exploit, 1 exploit) — [PDF](https://people.eecs.berkeley.edu/~daw/papers/mimicry.pdf)
- [Phương pháp] Tan et al. lập "detection map" của detector trên dữ liệu tổng hợp trước, rồi sửa exploit thật để rơi vào vùng mù — [PDF](https://www.cs.cmu.edu/~maxion/pubs/TanKillourhyMaxion02.pdf)
- [Phương pháp] ReplicaWatcher quét cường độ 1–6 lệnh/snapshot, 3 snapshot mỗi tổ hợp, báo cáo detection rate theo cường độ và cumulative detection probability qua kill chain — [NDSS 2024 PDF](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Phương pháp] Goyal et al. đo "chi phí né" bằng độ phức tạp biến đổi đồ thị và công bố mã nguồn cùng mẫu adversarial làm benchmark — [PDF](https://gangw.cs.illinois.edu/ndss23-mimicry.pdf)

### Inferences — protocol đề xuất cho Pulse (tất cả là [Suy luận], công cụ miễn phí)

**Threat model (bảng tri thức theo thành phần):**

| Mức | Tri thức | Khả năng | Mô tả |
|---|---|---|---|
| A0 | zero | `kubectl exec` vào 1 pod | baseline hiện tại (5 fixture) |
| A1 | limited: biết Pulse dùng tripwire + đếm syscall, không biết reference | như A0 | tránh binary/syscall "lạ" hiển nhiên: dùng tiện ích có sẵn trong image, không `execve` công cụ mới |
| A2 | perfect với reference của workload (profile syscall ID, cặp, phân phối tần suất) | như A0 | chỉ dùng ID và cặp đã có; điều tốc độ (rate) |
| A3 | perfect + biết luật 2 cửa sổ và cửa sổ 0.5 s | như A0 | low-and-slow, on-off với chu kỳ quét |
| A4 | như A2 | `exec` song song vào **mọi** replica | tấn công replica discount |
| A5 | như A2 | độn mimicry: một luồng phụ trong cùng container phát lại histogram syscall bình thường | pha loãng tần suất |
| (A6) | như A2 | io_uring: thực hiện mục tiêu qua liburing (curing PoC) | né tầng syscall; chỉ chạy nếu kernel lab và seccomp cho phép |

**Mục tiêu tấn công cố định, có thể kiểm chứng** (giữ semantics, như Wagner & Soto): (G1) đọc một Secret được mount và gửi ra ngoài tới một listener trong cluster; (G2) ghi persistence (sửa file cấu hình hoặc cron trong container); (G3) trinh sát (liệt kê `/proc`, mạng). Mỗi lần chạy ghi lại "goal achieved?" để loại các lần né nhưng tấn công thất bại.

**Biến ngân sách** (quét lưới): tốc độ hành động r ∈ {1, 0.5, 0.2, 0.1, 0.033} hành động/s; tỷ lệ độn p ∈ {0, 1×, 5×, 20×} syscall bình thường trên mỗi syscall tấn công; chu kỳ on-off; số replica bị tấn công k/N.

**Thước đo:**
- Recall theo cấp độ attempt và time-to-detect (median, p95), tách đường nhanh và đường tích lũy.
- FPR/giờ trên benign đo ở **cùng cấu hình** detector (không chỉnh ngưỡng sau khi xem tấn công).
- Đường cong recall theo ngân sách (r, p, k/N) và "ngân sách tối thiểu để né" (ví dụ tốc độ lớn nhất mà recall < 50 %).
- Tỷ lệ goal achieved.
- Khoảng tin cậy bootstrap trong file .md (theo quy tắc báo cáo của dự án).

**Quy trình:**
1. Đóng băng mô hình và ngưỡng, rồi đăng ký trước (pre-register) lưới tham số và tiêu chí.
2. Chạy A0–A5 trên cùng workload, mỗi ô ≥ 10–30 lần.
3. Sau đó bật từng phòng thủ: tích lũy martingale/CUSUM; replica discount có điều kiện (không discount ID mới, phát hiện đồng bộ); tripwire `io_uring_setup`. Chạy lại để đo "trước và sau" phòng thủ.
4. Thử **kẻ tấn công thích nghi với phòng thủ** (theo tinh thần Wagner & Soto và Apruzzese): ví dụ on-off với chu kỳ dài hơn bộ nhớ của bộ tích lũy, hoặc tấn công replica xen kẽ.
5. Công bố script tấn công làm benchmark (như Goyal et al.).

**Công cụ miễn phí:** `kubectl`, bash/busybox có sẵn trong image, Python để sinh luồng độn từ histogram reference, `liburing` hoặc PoC `armosec/curing` (GitHub, mã mở) cho A6, `strace`/`bpftrace` để kiểm chứng chuỗi syscall thực tế của tấn công trước khi chạy trên Pulse (tương tự cách Wagner & Soto chạy chuỗi qua stide).

### Gaps
- Không tìm thấy bài nào về HIDS container/syscall có protocol adaptive-attacker đầy đủ (nhiều mức tri thức + đường cong ngân sách + goal-achieved) để làm khuôn mẫu trực tiếp. Protocol trên ghép từ các bài khác lĩnh vực (provenance, ReplicaWatcher, position paper).
- Chưa đọc toàn văn Arp et al. ("Dos and Don'ts of ML in Computer Security", USENIX Security 2022) và Pierazzi et al. (problem-space attacks, S&P 2020). Đây là hai nguồn thường được trích cho ràng buộc "problem-space" (giữ chức năng, chống tiền xử lý), cần đọc trước khi viết phần phương pháp trong luận văn.
