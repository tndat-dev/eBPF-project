# Provenance, process lineage và ngữ cảnh khởi chạy: phương pháp tách process mới vô hại khỏi process độc hại (container/host IDS)

Ghi chú nghiên cứu, ngày 30/10/2026. Ký hiệu: **[Đo]** = tác giả tự đo; **[Đo độc lập]** = nhóm khác chạy lại; **[Tuyên bố]** = tác giả nói nhưng không kèm số đo; **[Tài liệu]** = tài liệu công cụ. Phần "Inferences" là suy luận của tôi cho Pulse, không phải số đo. Các paper đã tải về và grep trực tiếp từ PDF (pdftotext), trừ chỗ ghi "qua tóm tắt tìm kiếm".

Không lặp lại: CHIDS, số precision/recall của ReplicaWatcher và các tín hiệu argument-level đã có trong `research_notes/Cải thiện Pulse trên LID DS/improvement_techniques.md`.

## 1. Provenance-graph IDS (UNICORN, ProvDetector, Kairos, FLASH, MAGIC, NODLINK, ORTHRUS, R-CAID, ThreaTrace, ShadeWatcher, Velox, CAPTAIN): xử lý process mới vô hại thế nào, FP và latency trên dataset nào, cái nào chạy online cỡ giây

### Takeaway
Mọi PIDS anomaly-based đều coi hoạt động của ứng dụng mới vô hại là bất thường. Kairos tự nhận như vậy (mọi FP trên E5-ClearScope ngày 17/5 do `screencap`, một app không có trong train). Trên host thật khoảng 65 % log là "chưa biết". Khi chạy lại độc lập ở mức node, phần lớn hệ thống có hàng nghìn đến hàng trăm nghìn FP. Hai cách giảm FP có số đo là phân cụm các node bất thường sau ngưỡng (ORTHRUS: 0–23 FP mỗi dataset DARPA, FPR ≤ 1 % trên dữ liệu công nghiệp) và retrain/feedback từ FP. Chỉ CAPTAIN (rule + tag propagation, buffer 0) và Velox (chấm điểm từng edge, khoảng 2.400 edge/s) xử lý từng sự kiện. NODLINK gom 10 s, còn Kairos/FLASH/MAGIC/ORTHRUS chạy theo cửa sổ hoặc batch từ vài phút đến vài giờ.

### Cited Findings

**Process mới vô hại là nguồn FP chính (đều trên dữ liệu DARPA/doanh nghiệp, không có container)**
- [Đo] Kairos (IEEE S&P 2024): "KAIROS assigns high reconstruction errors to novel activities of new applications that were introduced only in the test data… albeit non-malicious. This is an example of concept drift." Trên E5-ClearScope ngày 17/5/2019 (cửa sổ 15 phút): không retrain thì TP 6, TN 87, FP 2, FN 0, precision 0,750. Retrain bằng FP của ngày 15/5 thì FP 0, precision 1,000. Tác giả viết "all the FPs are caused by the behavior of screencap, which does not appear in the training data". Tác giả cũng cảnh báo retrain có thể phá giả định threat model (attacker có thể poison). — [Kairos, arXiv 2308.05034](https://arxiv.org/pdf/2308.05034)
- [Đo] Kairos, Bảng 5 (đã chỉnh, đơn vị là cửa sổ 15 phút): Manzoor/StreamSpot FP 0/475; E3-THEIA 1 FP/217 cửa sổ benign; E3-CADETS 1/175; E3-ClearScope 2/114; E5-THEIA 1/174; E5-CADETS 0/238; E5-ClearScope 5/222; OpTC 6/1216. Recall 1,000 ở mọi dataset. — [Kairos](https://arxiv.org/pdf/2308.05034)
- [Đo] Xiao et al. 2026 (Tsinghua + Tencent Keen Lab, preprint) đánh giá trên dữ liệu công nghiệp gồm khoảng 5.000 terminal Windows (ETW) và khoảng 10.000 cloud host Linux (Auditlog sửa đổi). Kết quả: "over 96% of processes in the DARPA-E3 datasets have less than 20% of unknown logs, whereas in reality, the ratio is about 65% and about 20% of processes have totally unknown logs". Tác giả kết luận "there will always be unknown benign activities". — [Xiao et al., arXiv 2603.22982](https://arxiv.org/pdf/2603.22982)
- [Đo độc lập] Cùng bài, FPR mức node của 5 PIDS (bảng I–VII). ORTHRUS 0,0000–0,0101 ở mọi setting. Kairos 0,04–0,95. MAGIC 0,19–0,99. FLASH 0,03–0,83. NODLINK 0,03–0,84. Ở tấn công đào coin thật, số FP là MAGIC 116.374, FLASH 9.668, ORTHRUS 9, Kairos 28.302, NODLINK 39.830. Trên một terminal "luôn thay đổi", ORTHRUS < 1 %, Kairos < 12 %, các hệ khác > 23 %. — [arXiv 2603.22982](https://arxiv.org/html/2603.22982)
- [Đo độc lập] Cùng bài: FP của NODLINK chủ yếu do "semantic changes" (đổi tên file, tham số command line, IP). Một bộ lọc hậu kỳ dùng Louvain gom các process có hoạt động giống nhau và coi process lặp lại thường xuyên là FP. Bộ lọc này giảm FPR của NODLINK "from about 25% to about 10%", và số community phải xem chỉ bằng khoảng 1/3 số FP. — [arXiv 2603.22982](https://arxiv.org/pdf/2603.22982)
- [Đo] ORTHRUS (USENIX Security 2025) ghi nhận: khi phần mềm mới được triển khai hoặc cập nhật, số FP tăng nên phải retrain. Tác giả coi đây là việc của tương lai vì "lack of dedicated datasets". — [ORTHRUS, USENIX Sec 2025](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf)

**Số FP mức node khi chạy lại độc lập (ORTHRUS, Bảng 10–11, DARPA E3/E5, cùng một framework)**
- [Đo độc lập] E3-CADETS (68 node độc hại, khoảng 268k node): ORTHRUS-full TP 25 / FP 23 (precision 0,52); ORTHRUS-ano 10/0; Kairos 0/9; ThreaTrace 61/252.117; SIGL 0/80; MAGIC 63/79.766; FLASH 13/2.381. E3-THEIA: ORTHRUS-full 48/11 (precision 0,81); MAGIC 115/394.906; FLASH 22/32.082; ThreaTrace 88/671.883. E5-THEIA: ORTHRUS-full 13/2 (0,87); FLASH 43/295.729. Thời gian test trên cả tập: ORTHRUS 52 phút 31 giây (E3-CADETS) đến 6 giờ 29 phút (E5-THEIA); FLASH 8 giờ 52 phút đến 105 giờ; MAGIC 13 giờ 01 phút trên E3-CADETS (GPU A100). — [ORTHRUS](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf)
- [Đo độc lập] ORTHRUS giải thích: các hệ trước "assign[] similar anomaly scores" cho node độc hại và node lành. ThreaTrace, FLASH và MAGIC gắn cờ cả một vùng lớn quanh tấn công, còn Kairos gắn cờ node "occurring concurrently with attacks". ORTHRUS giảm FP bằng K-Means trên các node đã vượt ngưỡng, nên không cần chỉnh ngưỡng tay. — [ORTHRUS](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf); mô tả K-Means theo [Bilot et al., USENIX Sec 2025](https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf)
- [Đo độc lập] Bilot et al. "Sometimes Simpler is Better" (USENIX Security 2025) cài lại 8 PIDS trong một framework (PIDSMaker) và tìm ra 9 điểm yếu (SC1–SC9). Một mạng neural đơn giản (Velox) đạt mức SOTA trên 8/9 dataset DARPA. Kết quả E3-CADETS (TP/FP ở lần chạy tốt nhất): Velox 8/0, ORTHRUS 10/0, R-CAID 2/0, Kairos 0/8, NODLINK 50/55k, MAGIC 68/144k. E3-CLEARSCOPE thì khó với mọi hệ: Velox 1/913, ORTHRUS 1/399, R-CAID 15/169. — [Bilot et al.](https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf)
- [Đo độc lập] Cùng bài: R-CAID (IEEE S&P 2024) "transforms provenance graphs into a pseudo-graph, connecting each node to its root cause", tức là gắn mỗi node với tổ tiên gốc, rồi phát hiện bằng độ lệch so với cụm (K-Means + MAD). Đây là PIDS gần nhất với ý tưởng "đưa lineage vào embedding". R-CAID không open-source nên Bilot cài lại. — [Bilot et al.](https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf)

**Số tự báo cáo của các hệ cổ điển (lưu ý: các số này không giữ được khi chạy lại ở trên)**
- [Đo] UNICORN (NDSS 2020, cổ điển): DARPA CADETS precision 0,98 / recall 1,0; ClearScope 0,98 / 1,0; THEIA 1,0 / 1,0 (mức graph). NODLINK đo ở môi trường production của Sangfor và cho biết UNICORN sinh "seven times more false positives on the graph level and three orders of magnitude more false positives on the node level". — [UNICORN arXiv 2001.01525](https://arxiv.org/pdf/2001.01525); [NODLINK arXiv 2311.02331](https://arxiv.org/pdf/2311.02331)
- [Đo] ProvDetector (NDSS 2020, cổ điển): học một mô hình path hiếm riêng cho từng chương trình. Precision 0,952–0,965, recall 0,965–1, F1 trung bình 0,974 trên malware tàng hình (Windows). NODLINK đánh giá throughput của ProvDetector "falls short of industrial requirements". — [ProvDetector](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24167-paper.pdf); [NODLINK](https://arxiv.org/pdf/2311.02331)
- [Đo] ShadeWatcher (IEEE S&P 2022): FPR 0,332 % trên TRACE (2.405 FP/724.236) và 0,137 % trên tập mô phỏng. Feedback từ analyst (263 mẫu) hạ FPR xuống 0,096 % rồi 0,083 %. Dự đoán 792.333 tương tác mất 8,16 s. Kairos cho biết một phần quan trọng của ShadeWatcher là proprietary. — [ShadeWatcher](https://jun-zeng.github.io/file/shadewatcher_paper.pdf); [Kairos](https://arxiv.org/pdf/2308.05034)
- [Đo] MAGIC (USENIX Security 2024) tự báo cáo FPR trung bình 0,15 %, 569 cảnh báo sai trên Trace (khoảng 40/ngày, 24/ngày nếu dùng 2 tầng). Tác giả nói self-supervised embedding "effectively handle unseen system entities". Kết quả chạy lại độc lập ở trên mâu thuẫn mạnh với số này: 79.766 FP trên E3-CADETS và FPR 0,19–0,99 trên dữ liệu công nghiệp. — [MAGIC arXiv 2310.09831](https://arxiv.org/pdf/2310.09831); trái với [ORTHRUS](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf) và [arXiv 2603.22982](https://arxiv.org/html/2603.22982)
- [Đo] SIGL (USENIX Security 2021) là trường hợp gần nhất với "phần mềm mới vô hại": mô hình hoá graph cài đặt của từng installer. Đạt accuracy 96 % trên 625 installer độc hại và "outperforming similar systems… by up to 87% in precision and recall". Cách này cần sẵn graph cài đặt lành của chính installer đó. Khi chạy lại trong ORTHRUS, SIGL có 0 TP trên E3-CADETS và E3-THEIA. — [SIGL](https://www.usenix.org/system/files/sec21-han-xueyuan.pdf); [ORTHRUS](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf)

**CAPTAIN (NDSS 2025): rule-based nhưng học tham số, chạy streaming**
- [Đo] CAPTAIN dùng gradient descent trên một framework tag propagation khả vi để học ngưỡng cho node, edge và cảnh báo, chỉ từ dữ liệu train lành. Trung bình giảm cảnh báo sai "over 90% (11.49x)" so với PIDS rule-based truyền thống. Trên TRACE (E3): MORSE có 22.500 sự kiện báo sai (0,434 %), ShadeWatcher 2.405 (0,332 %), CAPTAIN 1.099 (0,0212 %), và cả ba phát hiện đủ tấn công. CPU dưới 10 %. — [CAPTAIN, NDSS 2025](https://www.ndss-symposium.org/wp-content/uploads/2025-822-paper.pdf)

**Latency/độ trễ phát hiện có số**
- [Đo] CAPTAIN, Bảng VI. Buffer time (phút:giây) là thời gian phải chờ gom dữ liệu trước khi phát hiện: Kairos 15:00, FLASH 57:49 (TRACE) và 82:52 (CADETS), NODLINK 00:10, MORSE 0, CAPTAIN 0. Đây là độ trễ do thiết kế, chưa tính thời gian tính toán. — [CAPTAIN](https://www.ndss-symposium.org/wp-content/uploads/2025-822-paper.pdf)
- [Đo] NODLINK chạy online, "detect[s] anomalies every Δ (Δ = 10 in our implementation) seconds". Một host thật sinh trung bình 40 sự kiện/s; giả định 500 host thì cần 20.000 sự kiện/s. — [NODLINK](https://arxiv.org/pdf/2311.02331)
- [Đo] Kairos chia cửa sổ 15 phút. Cửa sổ trung vị có 57K edge và tính mất 11,6 s; cửa sổ dưới 10K edge mất khoảng 1 s hoặc ít hơn. Tốc độ khoảng 11K edge/s (StreamSpot khoảng 14K). Tác giả dẫn nghiên cứu trước cho biết hệ capture provenance "typically generates fewer than 10K edges per second". — [Kairos](https://arxiv.org/pdf/2308.05034)
- [Đo độc lập] Bilot (SC9): "in KAIROS, detection is conducted at fixed intervals, such as every 15 minutes". Velox thì "processes events individually", CPU tối đa 107 % (một core) và khoảng 5 % khi rảnh. Paper ghi "approximately 41 ms per edge, or roughly 2,400 edges/s". Hai con số này tự mâu thuẫn, vì 41 ms/edge chỉ tương ứng khoảng 24 edge/s. Đỉnh tải trong các dataset là 1.832 edge/s (E5-CADETS). — [Bilot et al.](https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf)
- [Đo độc lập] Xiao et al.: thời gian tăng tuyến tính theo kích thước graph. FLASH nhanh nhất: test mất 4,33 s với graph khoảng 6×10^5, trên GPU A100, chưa tính thời gian dựng graph. — [arXiv 2603.22982](https://arxiv.org/html/2603.22982)
- [Tuyên bố] ThreaTrace tự nhận "real-time system", nhưng khi chạy lại có FP rất lớn (252.117 trên E3-CADETS). — [ThreaTrace arXiv 2111.04333](https://arxiv.org/pdf/2111.04333); [ORTHRUS](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf)

### Inferences
- Kairos (screencap), Xiao et al. (65 % log chưa biết) và ORTHRUS (phần mềm mới làm tăng FP) cùng xác nhận vấn đề của Pulse ("bắt được process mới chạy" chứ không phải độc hại). Các tác giả đều xếp đây là concept drift chưa giải được. Không PIDS nào trong danh sách có cơ chế tách process mới lành khỏi process mới độc hại ngay lần đầu thấy mà không cần feedback.
- Có hai cơ chế có số đo, đều không cần nhãn tấn công:
  1. Gom và phân cụm các thực thể bất thường sau ngưỡng: ORTHRUS dùng K-Means, Xiao et al. dùng Louvain (FPR 25 % → 10 %). Bất thường lặp lại nhiều lần hoặc giống nhau thì bị coi là lành.
  2. Retrain hoặc allow-list từ FP đã được xác nhận: Kairos 2 → 0 FP, ShadeWatcher 0,137 % → 0,083 %.

  Áp vào Pulse, cơ chế (1) có rủi ro: trong campaign, mỗi loại tấn công cũng lặp lại qua nhiều trial nên cũng thành cụm lớn. Phải phân cụm theo ngữ cảnh workload (container/pod), không gộp chung qua các trial.
- Bài học đáng giá nhất cho thiết kế: chuyển từ chấm điểm cả container sang chấm điểm từng process (node-level), như NODLINK, ORTHRUS và Velox. ORTHRUS chỉ ra rằng chấm điểm theo cửa sổ thời gian làm hệ gắn cờ mọi thứ "xảy ra cùng lúc" với bất thường. Vector 0,5 s theo container của Pulse có đúng tính chất đó: syscall của process exec mới bị trộn vào hồ sơ của container.
- Về latency, chỉ những thiết kế kiểu CAPTAIN (tag propagation, buffer 0) hoặc Velox (chấm từng edge) hợp với ngân sách ≤ 3 s. Kairos, ORTHRUS, MAGIC và FLASH ở dạng hiện tại cần cửa sổ hoặc batch hàng phút đến hàng giờ và cần GPU.

### Gaps
- Không có PIDS nào trong danh sách được đánh giá trên container/Kubernetes hoặc với lưu lượng `kubectl exec`. Mọi số liệu ở đây đến từ DARPA TC/OpTC, StreamSpot hoặc host doanh nghiệp.
- Chưa lấy được số tự báo cáo của FLASH và R-CAID từ paper gốc; chỉ dùng số chạy lại của Bilot và ORTHRUS.
- Bài Goyal et al. (NDSS 2023, mimicry attack lên PIDS) chỉ được biết qua phần Bilot nhắc lại: các hệ SOTA "exhibit at least partial robustness". Chưa đọc paper gốc.
- Con số latency/edge của Velox tự mâu thuẫn trong paper, cần đối chiếu với repo PIDSMaker (nhánh `velox`).

## 2. Alert triage / giảm báo nhầm trên provenance (NoDoze, Swift, OmegaLog, RapSheet, DepImpact, ATLAS, các hệ kế nhiệm 2024–2026)

### Takeaway
Các hệ triage giảm 82–98 % cảnh báo sai, nhưng mỗi hệ có điều kiện riêng:
- NoDoze (84 % hoặc 86 %) và RapSheet (bỏ 97,8 % TPG sai ở ngưỡng giữ 100 % TP) chạy offline, mất khoảng 10 s và 54 s mỗi cảnh báo khi được ép chạy streaming.
- Carbon Filter (2024) chỉ dùng ngữ cảnh khởi chạy (command line, cặp đường dẫn cha-con). Nó lọc 82 % cảnh báo sai mà phân loại nhầm ≤ 0,1 % cảnh báo độc hại, với 0,18–2 ms mỗi cảnh báo. Đổi lại cần lịch sử cảnh báo rất lớn và nhãn từ analyst.
- DepImpact và ATLAS là công cụ điều tra sau cảnh báo, không phải bộ lọc chạy online.

### Cited Findings
- [Đo] NoDoze (NDSS 2019, cổ điển): chấm điểm mỗi edge trong graph phụ thuộc nhân quả của một cảnh báo theo tần suất sự kiện liên quan từng xảy ra trong doanh nghiệp, rồi lan truyền điểm. Theo bản PDF: "we estimate that our system decreases the volume of false alarms by 84%". Trang NDSS ghi 86 %, trên cùng tập 364 cảnh báo ở NEC Labs. Hai phiên bản không khớp nhau. — [NoDoze, trang NDSS](https://www.ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage) (qua tóm tắt tìm kiếm; chưa đọc được PDF)
- [Đo] RapSheet (IEEE S&P 2020): gom cảnh báo EDR (Symantec) thành Tactical Provenance Graph và chấm điểm theo thứ tự thời gian của các tactic MITRE. Có 58.096 cảnh báo trong thí nghiệm, gồm APT3, APT29 và một vụ trộm dữ liệu do red team tạo. "When we set a threshold… that captures 100% of true positives, we can remove 97.8% of false TPGs… At this threshold, RapSheet has a 2.2% FPR." AUC của TPG-seq là 0,99. Skeleton graph giảm lưu trữ log tới 87 %. — [RapSheet, S&P 2020](https://par.nsf.gov/servlets/purl/10146533)
- [Đo] Carbon Filter (VMware Carbon Black, arXiv 2024, "Submitted to KDD 2024"). Tác giả cho rằng có thể triage cảnh báo bằng "processes' immediate (not historic) execution context in the form of the causal initiator of the process", thường là command line, kèm "parent-child process paths". Phương pháp: hash TLSH command line, gom cụm, tra ANN, phát hiện ngoại lai trong cụm, và dùng mô hình KDE theo tần suất command line ở mức thiết bị, tổ chức và toàn cầu. Dữ liệu: hơn 288 triệu cảnh báo, 10.000+ cảnh báo có nhãn chuyên gia. Kết quả: "filter out 82% of false alerts while mis-classifying 0.1% or less of malicious alerts", SNR tăng 6 lần, 54,5 % trong 102 triệu cảnh báo train rơi vào 1.638 cụm. — [Carbon Filter arXiv 2405.04691](https://arxiv.org/pdf/2405.04691)
- [Đo] Carbon Filter, Bảng 6, thời gian mỗi cảnh báo khi NoDoze và RapSheet được chỉnh để chạy streaming: Carbon Filter (linear) 0,002 s, NoDoze 10,23 s (chậm hơn 5.064 lần), RapSheet 53,98 s (chậm hơn 26.723 lần). Dùng ANN thì 0,18 ms mỗi cảnh báo (index 16K) và 0,76 ms (index 100K), tức khoảng 5.566 cảnh báo/s. Trên ATLASv2 (train ngày 1–4, test ngày 5): AUC Carbon Filter 0,94, NoDoze 0,60, RapSheet 0,90. Tác giả lưu ý không chấm được điểm bất thường trên ATLASv2 vì thiếu lịch sử tần suất. — [Carbon Filter](https://arxiv.org/pdf/2405.04691)
- [Tuyên bố] Carbon Filter mô tả thực hành trong ngành: "EDR products assess the reputation of a running process, considering… the reputation of the process's primary executable and its parent process", và sensor "monitor for the introduction of new executable content". — [Carbon Filter](https://arxiv.org/pdf/2405.04691)
- [Đo] DepImpact (USENIX Security 2022): rút graph phụ thuộc từ khoảng 1.000.000 edge xuống khoảng 234 edge (nhỏ hơn 4611 lần) mà vẫn giữ chuỗi tấn công, hiệu quả hơn 106 lần so với các kỹ thuật causality khác. Dữ liệu: 150 triệu sự kiện audit và DARPA TC. Đây là công cụ điều tra backward/forward sau khi đã có cảnh báo. — [DepImpact](https://www.usenix.org/system/files/sec22-fang.pdf)
- [Đo] ATLAS (USENIX Security 2021): dựng lại các bước tấn công với precision trung bình 91,06 %, recall 97,29 %, F1 93,76 %. Đây là mô hình sequence học có giám sát (cần chuỗi tấn công để train) và phục vụ điều tra. — [ATLAS](https://www.usenix.org/system/files/sec21-alsaheel.pdf)
- [Đo] ORTHRUS liệt kê NoDoze và Swift chấm điểm theo "frequency of related events", PrioTracker theo "rarity and fanout", DepImpact theo "timing, data flow amount, and node degree". — [ORTHRUS](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf)
- [Đo] CAPTAIN (xem mục 1) cũng có thể xem là kế nhiệm theo hướng giảm báo nhầm của hệ rule-based: giảm 11,49 lần so với MORSE, chạy streaming. — [CAPTAIN](https://www.ndss-symposium.org/wp-content/uploads/2025-822-paper.pdf)

### Inferences
- Trong nhóm triage, Carbon Filter gần Pulse nhất: nó chỉ dùng ngữ cảnh khởi chạy và tần suất ngữ cảnh đó, không duyệt lịch sử provenance, và đủ nhanh cho ngân sách ≤ 3 s. Nhưng trong campaign của Pulse, binary đối chứng và binary tấn công có ngữ cảnh khởi chạy giống hệt nhau (`kubectl exec`, binary mới, cùng danh tính), chỉ khác đường dẫn hoặc tên. "Tần suất command line" vì vậy chỉ tách được nếu một binary đã được thấy (và được xác nhận lành) trước đó. Đó là allow-list cần nhãn, không phải phát hiện.
- RapSheet đạt mức tách cao nhờ có nhiều cảnh báo theo chuỗi kill-chain. Các tấn công của Pulse là probe một bước (mprotect churn, setns sai, seccomp probe...), nên không có chuỗi để chấm. Hướng này không áp dụng được.
- NoDoze và DepImpact có thể dùng cho RCA service hiện có (xếp hạng process nghi ngờ trong evidence tree), không dùng cho đường cảnh báo ≤ 3 s.

### Gaps
- Chưa tải được bản đầy đủ của Swift (USENIX Sec 2020) và OmegaLog (NDSS 2020); URL thử đều hỏng. Không có số của hai hệ này trong ghi chú.
- Con số NoDoze (84 % hay 86 %) chưa đối chiếu được với PDF gốc.
- Không tìm thấy bài triage 2024–2026 nào đánh giá trên container hoặc cảnh báo từ `kubectl exec`.

## 3. Đặc trưng lineage và ngữ cảnh khởi chạy (chuỗi cha/tổ tiên, nguồn exec, đường dẫn binary, binary có thuộc image không, hash, user/capability): ai dùng để allow-list hoặc chấm điểm process mới, số liệu thế nào

### Takeaway
Các công cụ mở (Falco, Tetragon, KubeArmor, NeuVector) đều có sẵn tín hiệu lineage và drift, đọc được ngay tại thời điểm exec:
- Falco: `proc.is_exe_upper_layer`, `proc.aname[n]`, `proc.tty`, `container_entrypoint`.
- Tetragon: `in_init_tree`, `binary_properties`, `ancestors`.
- KubeArmor: `fromSource`.
- NeuVector: process profile và Zero-drift.

Không công cụ nào công bố FP/recall đo được. Trong tài liệu học thuật, hai hệ ProvDetector và SIGL học mô hình theo từng chương trình/installer, còn R-CAID gắn mỗi node với tổ tiên gốc. Cả hai hướng đều cần đã từng thấy chương trình đó, hoặc chỉ tách được khi chuỗi tổ tiên khác nhau.

### Cited Findings
- [Tài liệu] Falco rule "Drop and execute new binary in container" (CRITICAL) có điều kiện `spawned_process and container and proc.is_exe_upper_layer=true and not container.image.repository in (known_drop_and_execute_containers) and not known_drop_and_execute_activities`. Định nghĩa trường: "'true' if this process' executable file is in upper layer in overlayfs". — [falco_rules.yaml](https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml); [Falco supported fields](https://falco.org/docs/reference/rules/supported-fields/)
- [Tài liệu] Falco "Terminal shell in container" (NOTICE) có điều kiện `spawned_process and container and shell_procs and proc.tty != 0 and container_entrypoint`. Macro `container_entrypoint` là `(not proc.pname exists or proc.pname in (runc:[0:PARENT], runc:[1:CHILD], runc, docker-runc, exe, docker-runc-cur, containerd-shim, systemd, crio, conmon))`. Nghĩa là process có cha trực tiếp là runtime được coi là điểm vào, và đó chính là dấu hiệu của `kubectl exec`/`docker exec`. Phần ngoại lệ `user_expected_terminal_shell_in_container_conditions` mặc định là `never_true`, người dùng phải tự viết allow-list. — [falco_rules.yaml](https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml)
- [Tài liệu] Các trường lineage và ngữ cảnh khác của Falco:
  - Tổ tiên theo cấp: `proc.aname[n]`, `proc.aexepath[n]`, `proc.apid[n]`; đường dẫn cha: `proc.pexepath`.
  - Nhóm và phiên: `proc.vpgid`, `proc.is_vpgid_leader`, `proc.sid`, `proc.is_sid_leader`; terminal: `proc.tty` ("0 for processes without a terminal").
  - Thuộc tính file thực thi: `proc.is_exe_writable`, `proc.is_exe_from_memfd`, `proc.exe_ino.ctime`, `proc.exe_ino.mtime`.
  - `container.start_ts`.
  - Các trường healthcheck/liveness/readiness đã deprecated, khuyên dùng plugin `k8smeta`.

  — [Falco supported fields](https://falco.org/docs/reference/rules/supported-fields/)
- [Tài liệu] Tetragon, message `Process`:
  - `in_init_tree`: "If set to true, this process is containerized and is a member of the process tree rooted at pid=1 in its PID namespace."
  - `ProcessExec.ancestors`: "Ancestors of the process beyond the immediate parent."
  - `binary_properties` (chỉ có trong ProcessExec), gồm `setuid`, `setgid`, `privileges_changed`, và `file` cho trường hợp binary "was deleted from the file system". `InodeProperties.links`: "If zero means the file is only in memory".
  - `Process.flags` thì "for debugging purposes only and should not be considered a reliable source".
  - Không có trường nào cho biết binary nằm ở overlayfs upper layer hay không thuộc image.

  — [Tetragon gRPC API reference](https://tetragon.io/docs/reference/grpc-api/)
- [Tài liệu] Tetragon có export filter `in_init_tree`, mô tả là "Filter containerized processes based on whether they are descendants of the container's init process", dùng để tìm process đưa vào qua `docker exec`/`kubectl exec`. Ngoài ra có filter `ancestor_binary_regex`. — [Tetragon events docs](https://tetragon.io/docs/concepts/events/)
- [Tài liệu] Tetragon 1.2 thêm cách theo dõi tổ tiên process trực quan hơn, không còn dựa vào giá trị PID. — [Tetragon 2024 in review](https://cilium.io/blog/2024/12/31/tetragon-2024-year-in-review) (qua tóm tắt tìm kiếm)
- [Tài liệu] NeuVector có hai chế độ baseline:
  - Zero-drift (mặc định tới 5.6.0) "automatically allows only processes which originate from the parent process that is in the original container image". Chế độ này không cần học.
  - Basic (mặc định từ 5.6.1) áp dụng rule process/file học ở chế độ Discover. Ở Monitor thì cảnh báo, ở Protect thì chặn.
  - Process đáng ngờ dựng sẵn (ví dụ nmap) "will NOT be learned".
  - Liveness probe được tự động cho phép.
  - Tài liệu không nói gì về `kubectl exec`.

  — [NeuVector process rules](https://open-docs.neuvector.com/policy/processrules)
- [Tài liệu] KubeArmor có trường `fromSource` (đường dẫn tuyệt đối của binary nguồn/cha) nằm dưới `process.matchPaths`, dùng để giới hạn rule process theo binary cha. — [KubeArmor policy spec (mirror)](https://portrait.gitee.com/mirrors/KubeArmor/blob/main/getting-started/security_policy_specification.md) (bản mirror, nên kiểm tra lại docs chính thức)
- [Đo] Học thuật: ProvDetector dùng một mô hình riêng cho mỗi chương trình (precision 0,952–0,965). SIGL dùng một mô hình riêng cho mỗi installer (accuracy 96 %). R-CAID nối mỗi node với root cause (tổ tiên gốc) trong embedding. Cả ba đều giả định đã thấy chương trình/installer lành từ trước, hoặc giả định chuỗi tổ tiên mang thông tin. — [ProvDetector](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24167-paper.pdf); [SIGL](https://www.usenix.org/system/files/sec21-han-xueyuan.pdf); [Bilot et al. mô tả R-CAID](https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf)
- [Tuyên bố] Carbon Filter: command line và cặp cha-con đủ để phân biệt nguồn cảnh báo sai với hoạt động thực sự đáng ngờ, ngay cả khi cảnh báo do cùng một chương trình sinh ra (số đo ở mục 2). — [Carbon Filter](https://arxiv.org/pdf/2405.04691)

### Inferences
- Với campaign hiện tại, lineage không tách được tấn công khỏi đối chứng. Cả hai có cùng `in_init_tree=false`, cùng cha là runtime/shim, cùng nguồn `kubectl exec`. Nếu cả hai được chép vào bằng cùng cách thì `proc.is_exe_upper_layer` cũng như nhau. Đây là điểm cần nói thẳng trong thesis: thiết kế campaign đã cố ý giữ ngữ cảnh khởi chạy giống nhau, nên mọi phương pháp chỉ dựa vào ngữ cảnh sẽ cho kết quả ngẫu nhiên trên cặp này.
- Lineage vẫn có giá trị theo ba cách, đều làm được bằng Tetragon sẵn có:
  1. **Khoanh vùng (scoping):** dùng `exec_id` và `in_init_tree` để gán cảnh báo của cửa sổ cho đúng process exec mới, rồi chấm điểm vector syscall riêng của process đó (theo TGID/exec_id, không theo container). Đây là bản Pulse của bài học node-level ở mục 1. Nó tách được tác động của binary đối chứng chỉ gọi getpid khỏi nhiễu nền.
  2. **Mức ưu tiên (prior):** drift (binary ở upper layer hoặc binary bị xoá/memfd: `links=0`, `proc.is_exe_from_memfd`) là prior mạnh trong thực tế. Falco xếp CRITICAL, nhưng chưa có số đo.
  3. **Phân tầng đánh giá:** báo riêng kết quả cho process `in_init_tree=true` (tấn công từ bên trong ứng dụng, ví dụ RCE) và process exec từ ngoài. Khi đó tỉ lệ cờ trên binary lành ở nhóm exec là "chi phí của chính sách exec", không trộn vào FPR của workload.
- Muốn tách tấn công khỏi đối chứng trên cùng ngữ cảnh thì phải dựa vào hành vi của chính process mới, sau khi đã trừ phần "prologue" chung của mọi exec (loader, ld.so mmap/mprotect). Thí nghiệm exec-aware novelty của Pulse đã cho thấy cách này đủ với syscall hiếm nhưng chưa đủ với mprotect/seccomp, vì chúng chồng lên prologue. Có thể thử một hồ sơ "process mới lành điển hình", học từ một tập binary lành chạy qua `kubectl exec` trong dữ liệu calibration (ls, cat, env, sleep, ps, binary đối chứng). Cách này chỉ cần dữ liệu lành và tương tự ý tưởng SIGL (mô hình hoá "cài/chạy phần mềm lành"). Chưa có nguồn nào đo cách này.

### Gaps
- Không tìm thấy số đo FP/recall công khai cho Falco "Drop and execute new binary", Tetragon `in_init_tree` hay NeuVector Zero-drift.
- Không xác nhận được cờ cấu hình nào bật `ancestors` trong Tetragon (tài liệu API có trường này nhưng không ghi cờ).
- Chưa tìm thấy paper học thuật nào dùng hash file, capability hoặc user làm đặc trưng chấm điểm process mới trong container và có số đo.

## 4. Ngữ cảnh riêng Kubernetes: nối sự kiện container với audit log (ai chạy `kubectl exec`, danh tính/service account), image/admission manifest, so sánh replica (ReplicaWatcher) và đánh giá hoạt động exec quản trị/debug lành

### Takeaway
Kubernetes chưa (tính đến tài liệu KEP hiện có) đưa được danh tính người gọi `kubectl exec` xuống runtime:
- KEP-6035 đề xuất truyền audit ID qua biến môi trường `KUBERNETES_EXEC_AUDIT_ID` và trường CRI `ExecRequest.envs` (alpha dự kiến ở v1.37).
- Security Profiles Operator hiện đã làm được điều tương tự bằng mutating webhook cộng log enricher.
- Ghép theo thời gian sẽ hỏng khi các phiên exec chồng nhau.
- ReplicaWatcher tự thừa nhận rằng "execing into a pod for debugging" có thể bị phân loại là bất thường.

Không có bài nào đánh giá có số đo trên lưu lượng exec quản trị lành.

### Cited Findings
- [Tài liệu] KEP-6035 "Exec session identity propagation" nêu vấn đề: API server "authenticates the caller and records their identity in the audit log, but this information is never forwarded to the kubelet or the container runtime". Cơ chế đề xuất: API server thêm `?env=KUBERNETES_EXEC_AUDIT_ID=<value>`, kubelet chuyển qua trường CRI mới `ExecRequest.envs`, và runtime tiêm vào môi trường của process exec. KEP cũng thêm `PodExecOptions.Env` và cờ `kubectl exec --env`. Trạng thái: "ALPHA Implementable", alpha v1.37, beta v1.38, stable v1.39, với feature gate `ExecEnvVar` và `ExecRequestID`. KEP nêu rõ Falco và Tetragon có thể đọc biến này lúc exec để ghép (join) với audit log, nhưng giá trị chỉ là "correlation hint, not a security assertion" và chưa chống giả mạo. — [KEP-6035](https://www.kubernetes.dev/resources/keps/6035/)
- [Tài liệu] Theo tóm tắt tìm kiếm KEP-6035, ghép theo thời gian giữa audit log và sự kiện runtime "only works when sessions do not overlap". Cộng đồng Falco đã nêu vấn đề này ở falcosecurity/falco#2895. — [KEP-6035](https://www.kubernetes.dev/resources/keps/6035/)
- [Tài liệu] Security Profiles Operator (CNCF blog 7/10/2025): "By default, kubectl exec doesn't pass user authentication (user) details into the exec session". SPO dùng mutating webhook để "inject the request UID from the Kubernetes API server as an environment variable into the session". Enricher JSON chạy trong DaemonSet, đọc `/var/log/audit/audit.log` và lấy cmdline/env từ `/proc/<pid>` (eBPF chỉ là nguồn phụ, chưa cấu hình được). Log có timestamp, executable, arguments, UID/GID, syscall. Tài liệu không có số latency; SPO chỉ log việc tạo process và xử lý bất đồng bộ. — [CNCF blog SPO](https://www.cncf.io/blog/2025/10/07/auditing-user-activity-in-pods-and-nodes-with-the-security-profiles-operator/)
- [Tuyên bố] ReplicaWatcher (NDSS 2024), phần Deployment Challenges:
  - Về hoạt động hiếm: "some rare tasks such as activities related to DevOps and maintenance (e.g., execing into a pod for debugging), might diverge from the microservice's standard function, and thus can be classified as anomalies."
  - Về rolling update: hệ dùng readiness probe để tạm loại các replica đang tạo hoặc xoá.

  Đây chỉ là thừa nhận, không có thí nghiệm. — [ReplicaWatcher](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Đo] CAShift (FSE 2025) là benchmark phát hiện bất thường từ log trong cloud dưới "normality shift", gồm 20 kịch bản tấn công. Mọi phương pháp LAD đều giảm hiệu năng, "up to 34%". Tác giả thử ba cách continual learning và thấy "promising" nhưng nhạy với cấu hình. Abstract không nêu metric cụ thể. — [CAShift arXiv 2504.09115](https://arxiv.org/abs/2504.09115)
- [Tài liệu] KubeGuard (arXiv 2509.04191) thu provenance bằng SPADE/CLARION (biết namespace) và ánh xạ process/socket sang pod/service bằng metadata cluster. Mục đích là hardening cấu hình, không phải phát hiện xâm nhập. — [KubeGuard](https://arxiv.org/pdf/2509.04191) (qua tóm tắt tìm kiếm)

### Inferences
- Có hai cách lấy ngữ cảnh "ai đã exec" mà không cần chờ KEP-6035:
  1. Dùng SPO webhook (tiêm request UID làm biến môi trường), rồi để Tetragon đọc biến đó qua process args/env hoặc một kprobe policy.
  2. Ghép theo thời gian với audit log của API server.

  Cách (2) chỉ tin được khi các phiên không chồng nhau. Điều này đúng với campaign tuần tự của Pulse, nhưng không đúng ở production.
- Có danh tính rồi cũng không giải quyết được câu hỏi khoa học của thesis. Trong threat model, kẻ tấn công dùng `kubectl exec` với credential bị đánh cắp có cùng danh tính hợp lệ, nên chặn theo danh tính chỉ là chính sách vận hành (cho admin exec đi đường triage riêng). Nếu đưa vào thì phải báo cáo tách riêng, giống quy ước tách rule khỏi ML.
- So sánh replica (ReplicaWatcher) gặp đúng vấn đề của Pulse ở chiều ngược lại: exec debug vào một replica làm replica đó lệch khỏi các replica còn lại. Vì thế nó không giúp tách exec lành khỏi exec độc hại.

### Gaps
- Không tìm thấy bài nào (học thuật hay công nghiệp) đo FP/recall trên lưu lượng `kubectl exec` quản trị/debug lành trong Kubernetes.
- Không có số latency từ lúc ghi audit log đến lúc join với sự kiện runtime (audit backend có thể gom batch; chưa kiểm chứng).
- Chưa tìm thấy bài nào dùng image manifest hoặc SBOM/admission để chấm điểm process mới có số đo. Falco/NeuVector chỉ dùng "binary ở upper layer" hoặc "cha nằm trong image" làm rule.

## 5. Cái nào cho kết luận trong khoảng 1–2 s sau exec trên pipeline eBPF/Tetragon, cái nào cần phút hoặc batch offline

### Takeaway
Ra kết luận được trong 1–2 s sau exec:
- Các tín hiệu có sẵn trong sự kiện exec (Tetragon `in_init_tree`, `parent`/`ancestors`, `binary_properties`; Falco upper-layer/memfd/tty/entrypoint).
- Các thiết kế streaming từng sự kiện: tag propagation kiểu CAPTAIN (buffer 0), chấm từng edge kiểu Velox (khoảng 2.400 edge/s, một core), tra ngữ cảnh kiểu Carbon Filter (0,18–2 ms mỗi cảnh báo).

Cần hàng phút đến hàng giờ: NODLINK (batch 10 s), Kairos (cửa sổ 15 phút), FLASH (buffer 58–83 phút), MAGIC/ORTHRUS (test hàng giờ trên GPU), NoDoze/RapSheet (10–54 s mỗi cảnh báo khi ép streaming). DepImpact và ATLAS là công cụ điều tra offline.

### Cited Findings
- [Tài liệu] Tetragon `process_exec` mang sẵn `exec_id` (duy nhất toàn cluster), `parent`, pod/container/image, `in_init_tree`, `binary_properties` và `ancestors`. Các trường này có ngay trong một sự kiện, không cần dựng graph. — [Tetragon events](https://tetragon.io/docs/concepts/events/); [Tetragon gRPC API](https://tetragon.io/docs/reference/grpc-api/)
- [Đo] Buffer time theo CAPTAIN Bảng VI: CAPTAIN/MORSE 0; NODLINK 10 s; Kairos 15 phút; FLASH 57:49–82:52. — [CAPTAIN](https://www.ndss-symposium.org/wp-content/uploads/2025-822-paper.pdf)
- [Đo độc lập] Velox chấm từng edge, CPU tối đa khoảng 1 core; số latency mỗi edge bị ghi không nhất quán (xem mục 1). — [Bilot et al.](https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf)
- [Đo] Kairos mất khoảng 1 s cho mỗi cửa sổ dưới 10K edge và 11,6 s cho cửa sổ 57K edge, nhưng chỉ chạy khi cửa sổ 15 phút đóng. — [Kairos](https://arxiv.org/pdf/2308.05034)
- [Đo] Carbon Filter tra ANN mất 0,18 ms mỗi cảnh báo (index 16K); NoDoze 10,23 s và RapSheet 53,98 s mỗi cảnh báo (khi được chỉnh sang streaming). — [Carbon Filter](https://arxiv.org/pdf/2405.04691)
- [Đo] RapSheet có đo CDF thời gian phản hồi khi dựng TPG (Hình 9), nhưng tôi chưa trích được số. — [RapSheet](https://par.nsf.gov/servlets/purl/10146533)
- [Đo] ShadeWatcher dự đoán 792.333 tương tác trong 8,16 s, nhưng đó là theo batch. — [ShadeWatcher](https://jun-zeng.github.io/file/shadewatcher_paper.pdf)
- [Đo độc lập] Thời gian test trên cả tập dữ liệu (ORTHRUS Bảng 10–11, GPU A100): ORTHRUS 41 phút đến 6,5 giờ; Kairos 16 phút đến 10 giờ; MAGIC 36 phút đến 13 giờ; FLASH 5,5 đến 105 giờ. — [ORTHRUS](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf)

### Inferences
- Các bổ sung làm được trong ≤ 3 s, xếp theo chi phí tăng dần (đều miễn phí, dùng Tetragon đang chạy):
  1. **Gắn ngữ cảnh exec vào cảnh báo:** ghép cảnh báo ML của container với `exec_id` của process exec gần nhất có `in_init_tree=false`. Chỉ là phép join trong bộ nhớ, latency cỡ ms. Bước này không giảm cờ trên binary lành, nhưng cho phép báo cáo "cảnh báo do exec từ ngoài" tách khỏi "cảnh báo trong cây init".
  2. **Chấm điểm theo từng process:** giữ vector syscall theo TGID cho mỗi process exec mới trong eBPF (map theo pid), chấm điểm process đó với ngưỡng conformal riêng cho nhóm "process exec mới lành". Nhóm này được calibrate bằng tập binary lành chạy qua `kubectl exec`, không cần nhãn tấn công. Cách này vẫn giữ luật 2 cửa sổ × 0,5 s, nên latency không đổi.
  3. **Tra tần suất ngữ cảnh kiểu Carbon Filter:** dùng hash binary hoặc đường dẫn + cha + pod, tra ở mức ms. Chỉ có ích khi binary đã được thấy trước, và cần cơ chế xác nhận lành để tránh tự học luôn tấn công lặp lại.
- Các hướng sau không hợp với đường cảnh báo ≤ 3 s, nên chỉ dùng cho RCA service: PIDS GNN theo cửa sổ (Kairos, ORTHRUS, MAGIC, FLASH), triage duyệt lịch sử (NoDoze, RapSheet), và DepImpact/ATLAS.
- Ước tính (chưa đo): bước 2 chỉ hơn persistence rule (T = 5 s, p95 6,5 s) nếu hồ sơ "process mới lành" tách được mprotect churn và seccomp probe khỏi prologue của loader. Dữ liệu exec-aware novelty hiện có của Pulse cho thấy đây là chỗ khó nhất.

### Gaps
- Không có số đo công khai về latency từ kernel tới userspace cho sự kiện `process_exec` của Tetragon hay cho rule Falco (cần tự đo trên lab nếu dùng).
- Chưa kiểm chứng được Velox chạy trên CPU thường (mọi số đo của Bilot đều trên GPU GA100, dù suy luận chỉ cần CPU).
- Không có PIDS streaming nào được đánh giá ở mức độ hạt 0,5 s hay trên tấn công một bước kiểu syscall probe như campaign của Pulse.
