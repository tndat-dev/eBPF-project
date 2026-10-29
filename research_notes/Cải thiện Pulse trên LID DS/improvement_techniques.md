# Kỹ thuật nâng tỉ lệ phát hiện của HIDS dựa trên system call vượt mức đếm tần suất, và khả năng chạy live bằng eBPF trên Kubernetes

Phạm vi: khảo sát có nguồn (web, chỉ nguồn miễn phí), as-of 29/10/2026. Mỗi số đều lấy từ trang/PDF đã mở thật, có ghi URL. Nhãn dùng trong file:
- **[Đo]**: số đo do tác giả công bố trong bảng/kết quả của chính bài.
- **[Tuyên bố]**: nhận định hoặc tuyên bố định tính của tác giả, không có số đi kèm, hoặc là abstract.
- **[Snippet]**: chỉ thấy qua đoạn trích của công cụ tìm kiếm, CHƯA mở được toàn văn (403/Cloudflare). Chưa kiểm chứng.
- Mục "Inferences" là suy luận của người viết, không phải kết quả đo.

Bối cảnh Pulse (do coordinator cung cấp, không phải nguồn web): trên LID-DS 2021 Pulse phát hiện 77,3 % bản ghi tấn công với 3,0 % bản ghi normal báo nhầm; STIDE (7-gram, any-mismatch) đạt 100 % / 60,8 %. Pulse trượt chủ yếu ở exploit chạy trong chính process dịch vụ: Heartbleed (CVE-2014-0160), ZipSlip, Rails CVE-2019-5418, nginx CVE-2017-7529, Juice-Shop.

Lưu ý so sánh: các bài dưới đây dùng dataset, đơn vị đánh giá (bản ghi, chuỗi, sự kiện, cụm báo động liên tiếp) và cách chọn ngưỡng khác nhau. Không so sánh trực tiếp con số giữa các bài với 77,3 % / 3,0 % của Pulse nếu không ghi rõ.

## 1. Đặc trưng dựa trên argument và return value (đường dẫn file, '..', file nhạy cảm, mã lỗi, số byte, metadata socket)

### Takeaway
Bằng chứng mạnh nhất cho container là CHIDS (El Khairi et al., CCSW 2022). CHIDS kết hợp ba tín hiệu: syscall chưa thấy, argument chưa thấy, và tần suất. Trên tập 13 kịch bản do nhóm ReplicaWatcher (NDSS 2024) dựng, CHIDS đạt precision 0,97–1,00 và recall 0,96–1,00. Trên cùng tập, mô hình chỉ dùng tần suất (CDL) có recall dưới 0,5 ở nhiều kịch bản, còn STIDE-BoSC có precision chỉ 0,50–0,70. Các bài cổ điển (Tandon & Chan 2003, Mutz et al. 2007) cũng cho thấy argument bắt được những tấn công mà sequence bỏ sót. Thư viện LID-DS đã có sẵn building block `ReturnValue` và `PathEvilness`, nhưng tôi không tìm được bài nào công bố số đo của hai block này trên LID-DS 2021.

### Cited Findings
- [Tuyên bố] Báo cáo LID-DS 2021 lập luận rằng argument và return value (số byte ghi, file descriptor, chuỗi đường dẫn, flag, số byte đọc/ghi, mã lỗi) cần được HIDS dùng. Lý do: theo Wagner, mimicry attack có thể giả dạng chuỗi syscall lành tính nhưng không giả được argument và return value. Bảng 1 của báo cáo chấm LID-DS-2021 có đủ arguments, thread info, timestamps, data buffers và network data (điểm 1 ở mỗi mục). — [Grimmer et al., Dataset Report: LID-DS 2021, CRITIS 2022 / LNCS 13723](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf)
- [Đo, mã nguồn] Thư viện LID-DS (commit `5b8e414`, 29/08/2026) có các building block sau:
  - `return_value.py`: chuẩn hóa return value (`res`) của từng syscall theo giá trị lớn nhất thấy lúc train, trả -1 nếu không phải số nguyên hoặc syscall chưa thấy lúc train.
  - `path_evilness.py`: khi train, dựng cây mọi đường dẫn file lấy từ tham số `fd`/`in_fd`/`out_fd` có tag `<f>`. Khi chạy, trả 0 cho đường dẫn đã biết và trả 1/height cho đường dẫn lạ, tức điểm luôn nằm trong (0,1).
  - Ngoài ra còn `flags.py`, `unknown_flags.py`, `filedescriptor.py`, `path_length.py`, `time_delta.py`, `thread_change_flag.py`.

  — [LID-DS repo, algorithms/features/impl](https://github.com/LID-DS/LID-DS/tree/5b8e4143301240c705b09dacbff3a49d72c08fcf/algorithms/features/impl), cụ thể [return_value.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/algorithms/features/impl/return_value.py) và [path_evilness.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/algorithms/features/impl/path_evilness.py)
- [Tuyên bố] Hình 1 của báo cáo LID-DS 2021 minh họa một pipeline: n-gram (n=3) của syscall đã embedding, ghép với return value, rồi đưa vào autoencoder. Đây chỉ là ví dụ minh họa, báo cáo không có số đo cho pipeline này. — [LID-DS 2021 report](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf)
- [Snippet] CHIDS (El Khairi, Caselli, Knierim, Peter, Continella; CCSW 2022; DOI 10.1145/3560810.3564266) mô hình syscall bằng đồ thị theo ngữ cảnh. Autoencoder được train trên ba đặc trưng: syscall chưa thấy, argument chưa thấy và tần suất syscall. Abstract nêu: 2 dataset, 20 kịch bản tấn công, 11.700 trace normal và 1.980 trace tấn công; tác giả tuyên bố CHIDS vượt các công cụ SOTA với overhead hợp lý. Toàn văn trên ACM trả 403/Cloudflare, nên tôi không kiểm được loại argument cụ thể và số đo gốc. — [UT research record](https://research.utwente.nl/en/publications/contextualizing-system-calls-in-containers-for-anomaly-based-intr/), [DOI](https://doi.org/10.1145/3560810.3564266)
- [Đo] ReplicaWatcher (NDSS 2024, cùng nhóm tác giả CHIDS) chạy lại CHIDS, CDL (autoencoder chỉ dùng vector tần suất) và STIDE-BoSC. Tập dữ liệu: 1.000 trace normal và 100 trace tấn công mỗi kịch bản, mỗi trace 30 s, 13 kịch bản. Ngưỡng giữ nguyên như bài gốc của từng phương pháp. Kết quả Bảng IV:
  - **CHIDS (γ=1,4)**: precision 0,9729–1,0000, recall 0,9600–1,0000 trên cả 13 kịch bản. Ví dụ CVE-2018-3760 (cũng là kịch bản có trong LID-DS) đạt P=R=1,0.
  - **CDL (chỉ tần suất)**: recall rất thấp ở nhiều kịch bản: CVE-2018-3760 0,10; CVE-2019-19518 0,22; CVE-2017-14849 0,20; CWE-434 0,06; CWE-78 0,02; CVE-2014-6271 0,10. Tác giả viết rằng CDL "chỉ phát hiện được tấn công gây tần suất syscall bất thường".
  - **STIDE-BoSC (mismatch=10)**: recall 0,82–1,00 nhưng precision 0,50–0,70. Tác giả mô tả FPR khoảng 60 %, do các BoSC chưa thấy vẫn xuất hiện trong hoạt động bình thường.

  — [El Khairi et al., ReplicaWatcher, NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Đo] Cũng trong bài ReplicaWatcher, phương pháp không cần train (so sánh giữa các replica) đạt precision trung bình 91,08 % và recall 98,35 % trên 13 kịch bản. Bộ đặc trưng của nó có cả argument: syscall thực thi và syscall thất bại, nhóm syscall, latency, tần suất truy cập file, thư mục/tên file khác nhau (đường dẫn ≤3 cấp thư mục), buffer size của read/recvfrom, IP/port client, process/command/argument/executable/cwd. Tác giả ghi nhận recall thấp hơn ở path traversal (CVE-2018-3760). — [ReplicaWatcher NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Đo] Zhou et al. 2026 (Mathematics 14(6):991) gắn eBPF vào LSM hook `security_file_open`, dựng lại đường dẫn bằng cách đi ngược cây dentry, lấy PID/PPID/inode/flags và gửi lên qua ring buffer. Container ID được đọc từ `/proc/[pid]/cgroup` ở user space. Đường dẫn được chia 3 mức rủi ro rồi mã hóa thành 6 đoạn. Mô hình là attention-autoencoder, ngưỡng μ+nσ với n=2 tốt nhất. Kết quả: recall 82,0 %, FPR 0,79 %, MCC 0,852, tốt hơn Isolation Forest, OC-SVM và LOF. Tập dữ liệu nhỏ: 5 h normal (~18.000 sự kiện) để train; 90 phút test chứa 15 sự kiện container escape (CVE-2022-0492, CVE-2022-48699, CVE-2022-0811, mỗi loại 5 lần); một host; kernel 6.5. Tác giả tự nêu đây là hạn chế. — [Zhou et al. 2026, PDF](https://mdpi-res.com/d_attachment/mathematics/mathematics-14-00991/article_deploy/mathematics-14-00991.pdf), [DOI](https://doi.org/10.3390/math14060991)
- [Đo] Tandon & Chan 2003 dùng DARPA 1999 (Solaris BSM, 51 tấn công trong 2 tuần). Ở mức 10 báo nhầm/ngày:
  - t-stide, phương pháp sequence tốt nhất, phát hiện 2 probe, 5 DoS, 5 R2L, 5 U2R, 1 Data, 1 Data-U2R, tổng 19.
  - A-LERAD (luật học trên argument) phát hiện 1 probe, 6 DoS, 10 R2L, 5 U2R, 3 Data, 2 Data-U2R, tổng 27.
  - M-LERAD (sequence + argument) có cùng số phát hiện với A-LERAD. Tác giả kết luận rằng "thông tin sequence là thừa" khi đã có argument, và argument tốt hơn ở mức báo nhầm thấp.

  — [Tandon & Chan, Learning Rules from System Call Arguments and Sequences for Anomaly Detection](https://cs.fit.edu/~pkc/papers/dmsec03tandon.pdf)
- [Đo] Mutz, Robertson, Vigna, Kemmerer 2007 dùng 4 mô hình argument kế thừa từ dòng ESORICS 2003: string length (bất đẳng thức Chebyshev), character distribution (χ²), structural inference (Markov + state merging) và token finder (thử nghiệm kiểu Kolmogorov-Smirnov). Ngưỡng của mỗi cặp (context, syscall) bằng max anomaly score trên tập threshold-learning cộng thêm 20 %. Dữ liệu là 64 ngày audit của daemon root trên 10 host: 39 ngày train, 7 ngày lấy ngưỡng, 18 ngày phát hiện. FP rate theo sự kiện là 2,89×10⁻⁴ khi không dùng calling context và 1,09×10⁻⁴ khi có context, tức tốt hơn khoảng 2,7 lần, trung bình 34 báo động/ứng dụng/ngày. Với exploit rootshell, mô hình có context bắt được `execve` bất thường còn mô hình không có context thì không. Với exploit sửa dữ liệu (format string, ghi đè PLT), tác giả viết rằng IDS dựa trên sequence sẽ không phát hiện. — [Mutz et al., Exploiting Execution Context for the Detection of Anomalous System Calls, RAID 2007](https://sites.cs.ucsb.edu/%7Evigna/publications/2007_mutz_robertson_vigna_kemmerer_context.pdf)
- [Snippet] Kruegel, Mutz, Valeur, Vigna, "On the Detection of Anomalous System Call Arguments", ESORICS 2003, LNCS tr. 326–343. PDF tải về dùng font Type3, không trích được chữ, nên tôi không lấy được số. — [iSecLab record](https://iseclab.org/publications/kruegel2003on_the/)
- [Đo] Fournier, Aloise, Costa 2023 cho language model học trên tên syscall cùng các argument có nghĩa tự thân (ret, procname, entry/exit) và timestamp. Dataset riêng gồm hơn 2 triệu web request. Kết quả AuROC (Bảng III):

  | Hành vi mới | 4-gram | Transformer |
  |---|---|---|
  | Connection | 51,5 | 97,8 |
  | CPU | 0,9 | 94,8 |
  | IO | 98,6 | 100 |
  | OPcache | 65,2 | 99,1 |
  | Socket | 22,6 | 99,9 |
  | SSL | 50,5 | 99,7 |

  Lưu ý: ngưỡng được chọn để cực đại F-score trên tập validation có chứa novelty, nên kết quả lạc quan. — [Fournier et al., arXiv 2309.02206](https://arxiv.org/pdf/2309.02206)
- [Snippet] Guo 2024, "Intrusion Detection Based on Complete System Call Information" (ICDSAI 2024; Crossref xác nhận tên bài, hội nghị và ngày 24/05/2024): autoencoder trên toàn bộ thông tin syscall, gồm cả process name và thread ID, đánh giá trên LID-DS với 13 kịch bản. Snippet nêu accuracy trung bình 96,8 % và F1 97,7 %. Trang ACM trả 403, chưa kiểm chứng. — [ACM DL](https://dl.acm.org/doi/10.1145/3677892.3677893)

### Inferences
- Các kịch bản Pulse trượt đều để lại dấu vết ở mức argument hoặc return value, dù tổng số syscall gần như không đổi. Dấu vết dự kiến dưới đây suy từ README kịch bản LID-DS, chưa đo:
  - **Heartbleed**: over-read heartbeat ([README](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2014-0160/README.md)), nên dự kiến các phản hồi `write`/`sendto` có số byte (return value) lớn bất thường.
  - **ZipSlip**: ghi đè `../../etc/passwd` ([README](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/ZipSlip/README.md)), nên dự kiến xuất hiện `openat` với O_CREAT/O_WRONLY vào một đường dẫn ngoài cây thư mục lúc train.
  - **CVE-2019-5418**: đọc `/etc/passwd` ([README](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2019-5418/README.md)), nên dự kiến có một lần open file nhạy cảm chưa thấy lúc train.
  - **nginx CVE-2017-7529**: integer overflow trong range filter gây rò rỉ ([README](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/CVE-2017-7529/README.md)), nên dự kiến số byte đọc/ghi bất thường, chủ yếu đọc cache file.
  - **Juice-Shop**: nhiều lỗ hổng web khác nhau ([README](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios/Juice-Shop/README.md)). Không đoán được một dấu hiệu chung.
- Từ đó, ba đặc trưng rẻ nhất có thể thêm vào vector 0,5 s của Pulse, theo thứ tự ưu tiên:
  1. **Path novelty**: số lần open vào đường dẫn hoặc tiền tố thư mục chưa thấy lúc train, kèm cờ "file nhạy cảm" và cờ "có '..' hoặc nằm ngoài cwd/webroot". Tương đương `PathEvilness` của LID-DS hoặc "argument chưa thấy" của CHIDS.
  2. **Histogram log2 của return value** cho read/write/sendto/recvfrom/pread64/sendfile theo từng container (ví dụ 16 bucket).
  3. **Số lần lỗi theo nhóm errno** (ENOENT, EACCES, EPERM, khác), tương đương "failed syscalls" của ReplicaWatcher.
- Bằng chứng trên cho thấy argument novelty thường bổ sung cho tần suất chứ không thay thế: CHIDS mạnh nhất khi kết hợp cả ba. Cách hợp lý cho Pulse là thêm những đặc trưng này vào nhánh support/tripwire, không thay thế ExtraTrees.

### Gaps
- Chưa mở được toàn văn CHIDS (ACM 403/Cloudflare) và luận án PhD của El Khairi ([UT record](https://research.utwente.nl/en/publications/training-less-anomaly-based-intrusion-detection-in-containerized-/), PDF 403). Vì vậy chưa biết CHIDS dùng những argument nào, kết quả gốc trên hai dataset ra sao, và một trong hai dataset có phải LID-DS 2021 không.
- Không tìm được bài nào công bố số đo của `ReturnValue` hoặc `PathEvilness` trên LID-DS 2021 theo từng kịch bản, kể cả Heartbleed, ZipSlip, CVE-2019-5418.
- Không tìm được bài Zhou nào khác với `security_file_open`. Bài Zhou 2026 ở trên là bài khớp, nhưng nó đánh giá container escape, không phải exploit web chạy trong process dịch vụ.
- Kruegel 2003: không trích được số (PDF dùng font Type3).

## 2. Mô hình sequence và graph (n-gram/STIDE có ngưỡng, system call graph, LSTM/Transformer, sequence theo thread) so với mô hình tần suất, và hành vi báo nhầm

### Takeaway
Sequence tách theo thread (thread-aware) là cải tiến có bằng chứng trực tiếp nhất trên LID-DS và đúng với kịch bản Heartbleed. Trên LID-DS 2019, bật thread information nâng DR của Heartbleed từ 0,00 lên 0,95 với STIDE và từ 0,01 lên 0,95 với SCG. STIDE "any-mismatch" báo nhầm rất nhiều (khoảng 60 % FPR theo ReplicaWatcher, khớp với 60,8 % Pulse đo được). Nhưng khi STIDE có ngưỡng bằng max điểm validation trên cửa sổ trượt, FA trung bình chỉ còn 61,5 cụm báo động mỗi kịch bản. LSTM/Transformer chưa có bằng chứng rõ là vượt n-gram có ngưỡng trên LID-DS.

### Cited Findings
- [Đo] Grimmer, Kaelble, Rahm (EISA 2021) chạy grid search hơn 30.000 cấu hình của 7 thuật toán trên LID-DS 2019 (10 kịch bản, mỗi kịch bản khoảng 1.021 bản ghi normal và 116 bản ghi tấn công). Chia dữ liệu: 200 normal để train, 50 normal để validation, phần còn lại để test. Kết quả trung bình (Bảng 5, cấu hình tốt nhất có thread information, TI):
  - STIDE (n=5, l=1000): DR 0,986, FA 61,5
  - BOSC: DR 0,986, FA 110,4
  - SCG (n=5, l=10): DR 0,895, FA 29,1
  - MLP: DR 0,789, FA 4,2
  - AE: DR 0,622, FA 2,2
  - CNN: DR 0,702, FA 20,0
  - SVM: DR 0,595, FA 42,7

  FA ở đây là số cụm báo động liên tiếp (alarm liền nhau tính là 1), không phải tỉ lệ bản ghi. — [Grimmer et al., Improving Host-based Intrusion Detection Using Thread Information](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- [Đo] Cùng bài, theo từng kịch bản (Bảng 6–8):
  - **Heartbleed (2014)**: STIDE không TI DR 0,00 / FA 3, có TI DR 0,95 / FA 44. SCG không TI 0,01 / 33, có TI 0,95 / 25. DR tốt nhất không dùng TI cho kịch bản này chỉ là 0,06 (MLP), có TI là 0,95 (STIDE n=9, l=10).
  - **ZipSlip**: STIDE có TI DR 1,00 / FA 1; SCG có TI 1,00 / 0.
  - **CVE-2019-5418**: AE (W2) DR 1,00 / FA 0, có hoặc không TI.
  - **CVE-2017-7529**: hầu hết thuật toán đạt 0,97–0,99.

  Tác giả: TI cải thiện DR ở 6/7 thuật toán, còn FA thì lẫn lộn (cải thiện ở SCG, MLP, CNN, AE). — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- [Đo, mã nguồn] Implementation SCG trong LID-DS có tham số `thread_aware=True`, `thread_wise_graphs` và các chế độ chấm điểm `probability`, `frequency`, `confidence`, `2-tuple`, `3-tuple`. STIDE trong LID-DS là tập n-gram đã thấy ("normal database"). — [scg.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/algorithms/decision_engines/scg.py), [stide.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/algorithms/decision_engines/stide.py)
- [Đo] Báo cáo LID-DS 2021: baseline STIDE (n=7, cửa sổ tổng w=100) có F-score thấp hơn, DR thấp hơn và báo nhầm nhiều hơn trên bản 2021 so với bản 2019. Tác giả kết luận bản 2021 "khó hơn một chút". Số liệu cụ thể chỉ có trong Hình 2, không trích được dạng chữ. — [LID-DS 2021 report](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf)
- [Đo] Grimmer et al. (System Call Graphs, trên ADFA-LD):
  - Biến thể STIDE II đạt DR khoảng 80 % với FAR khoảng 18 %, hoặc DR 90 % với FAR 24 %.
  - Ở FAR dưới 1 %, cấu hình tốt nhất (n=4, ngưỡng 0,2) chỉ đạt DR 18,9 % với FAR 0,7 %.
  - Tác giả kết luận đồ thị xác suất n-gram "theo kịp" STIDE nhưng chưa vượt.

  — [Grimmer et al., Intrusion Detection on System Call Graphs](https://dbs.uni-leipzig.de/file/Intrusion-Detection-on-System-Call-Graphs.pdf)
- [Đo] Bảng IV của ReplicaWatcher: STIDE-BoSC (mismatch=10) có recall 0,82–1,00 nhưng precision 0,4983–0,7016; tác giả mô tả FPR khoảng 60 %. — [ReplicaWatcher NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Đo] Kim et al. (LSTM system-call language model, ADFA-LD): ensemble đề xuất đạt AUC 0,928, so với 0,890 khi lấy trung bình và 0,859 khi bỏ phiếu. Ba bộ phân loại LSTM vượt kNN và k-means. — [Kim et al., LSTM-based System-call Language Modeling and Robust Ensemble Method](https://www.covert.io/research-papers/deep-learning-security/LSTM-based%20System-call%20Language%20Modeling%20and%20Robust%20Ensemble%20Method%20for%20Designing%20Host-based%20Intrusion%20Detection%20Systems.pdf)
- [Đo] Fournier et al. 2023: LSTM ngang hoặc tốt hơn Transformer ở 3/6 hành vi mới. Attention của Transformer chủ yếu nằm dọc đường chéo, tức phụ thuộc cục bộ. 4-gram thất bại ở 5/6 hành vi, trừ IO. — [arXiv 2309.02206](https://arxiv.org/pdf/2309.02206)
- [Tuyên bố] Yu & Kim 2021 dùng LSTM Anomaly Filter học các mẫu khớp/không khớp lặp lại của detector n-gram để dập báo nhầm lặp lại. Tác giả tuyên bố phát hiện slow HTTP attack mà không có báo nhầm. Thí nghiệm nhỏ, không dùng LID-DS. — [arXiv 2104.05571](https://arxiv.org/pdf/2104.05571)
- [Tuyên bố] Một luận văn thạc sĩ cài Transformer (stacked decoder, mô hình ngôn ngữ trên n-gram) bằng thư viện LID-DS. README không có bảng kết quả. — [LID-DS-TF](https://github.com/tinsaye/LID-DS-TF)

### Inferences
- Pulse đã băm cặp syscall liên tiếp theo thread vào 64 bin, nhưng đó là đếm cặp (n=2) có va chạm băm, khác với kiểm tra tập n-gram dài (n=5–9) chính xác theo thread. Kết quả Heartbleed trên LID-DS 2019 (0,00 lên 0,95) cho thấy chính chuỗi dài theo thread mới phân biệt được.
- Gợi ý cụ thể là thêm "thread-aware STIDE có ngưỡng" làm nhánh thứ ba: tập hash các 5–7-gram theo TID, chấm bằng số lần mismatch trong cửa sổ, ngưỡng lấy từ validation. Đây là suy luận, chưa đo trên LID-DS 2021.
- Ước lượng thô từ Bảng 5 (LID-DS 2019): STIDE có TI với FA trung bình 61,5 cụm trên khoảng 771 bản ghi normal test, tức nhiều nhất khoảng 8 % bản ghi normal có báo nhầm (61,5/771). Con số thật có thể thấp hơn vì một bản ghi có thể chứa nhiều cụm. So với 60,8 % của STIDE any-mismatch Pulse đo được, ngưỡng cửa sổ chính là thứ biến STIDE thành một đối thủ thực tế. Chưa kiểm trên LID-DS 2021.
- Kết quả thread-info là lạc quan, vì "cấu hình tốt nhất" được chọn trong hơn 30.000 cấu hình dựa trên kết quả test. Khi tái lập cho Pulse cần cố định cấu hình trước khi test, đúng tinh thần "no tuning" của Pulse.

### Gaps
- Không tìm được bảng kết quả có nguồn của LSTM/Transformer trên LID-DS 2021 theo từng kịch bản.
- Bài thread-info dùng LID-DS 2019 (10 kịch bản, không có Juice-Shop). Chưa thấy bản lặp lại trên LID-DS 2021.

## 3. Ngưỡng và hiệu chỉnh (ngưỡng theo kịch bản trên validation split, luật báo động liên tiếp, phát hiện thêm được bao nhiêu ở cùng mức báo nhầm)

### Takeaway
Cách làm chuẩn trên LID-DS là đặt ngưỡng bằng max điểm bất thường trên phần validation normal của từng kịch bản, và gộp các báo động liền nhau thành một. Mutz et al. dùng max + 20 % cho từng cặp (context, syscall). Không tìm được bài nào định lượng riêng phần DR tăng thêm nhờ hiệu chỉnh theo kịch bản ở cùng mức báo nhầm. Bằng chứng gián tiếp: ở ngưỡng chặt, nhiều detector còn dư địa (AUC cao nhưng recall thấp).

### Cited Findings
- [Đo, phương pháp] Grimmer et al. 2021 dùng max anomaly score trên phần validation normal làm ngưỡng "để tránh overfit so với dùng dữ liệu train". Alarm liền nhau chỉ tính là 1. Mốc tấn công lùi 2 s (t_attack − 2 s) vì nhãn thời gian không chính xác. — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- [Đo, mã nguồn] `MaxScoreThreshold` trong LID-DS lưu điểm cao nhất thấy trên validation và báo động khi điểm lớn hơn giá trị đó. `performance_measurement.py` đếm cụm false positive liên tiếp (`cfp`) và chỉ tính một true alarm cho mỗi bản ghi exploit. — [max_score_threshold.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/algorithms/features/impl/max_score_threshold.py), [performance_measurement.py](https://github.com/LID-DS/LID-DS/blob/5b8e4143301240c705b09dacbff3a49d72c08fcf/algorithms/performance_measurement.py)
- [Đo] Mutz et al. 2007: ngưỡng của mỗi cặp (context C, syscall s) bằng max score trên tập threshold-learning 7 ngày, cộng 20 %. — [RAID 2007](https://sites.cs.ucsb.edu/%7Evigna/publications/2007_mutz_robertson_vigna_kemmerer_context.pdf)
- [Đo] Zhou et al. 2026: ngưỡng μ+nσ. Khi tăng n từ 1 lên 2, recall giữ ở mức cao, FPR giảm mạnh và MCC đạt đỉnh ở n=2. Ở n=2,5 recall giảm. — [Zhou et al. 2026](https://mdpi-res.com/d_attachment/mathematics/mathematics-14-00991/article_deploy/mathematics-14-00991.pdf)
- [Tuyên bố] ReplicaWatcher dùng ngưỡng đồng nhất (ε=0,3) cho mọi kịch bản. Precision thấp hơn ở PHP-LFI, CWE-434 và CVE-2014-6271, recall thấp hơn ở path traversal CVE-2018-3760. Tác giả cho rằng AUC cao cho thấy ngưỡng theo kịch bản sẽ cải thiện đáng kể. — [ReplicaWatcher NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Đo] Kozachok et al. 2026 dùng LID-DS-2021, 6 kịch bản, Isolation Forest và SGD-OCSVM, ngưỡng hiệu chỉnh theo FPR mục tiêu. Ở FPR mục tiêu 0,05, detector gộp cho CWE-307 đạt F1 0,6976 (precision 0,8994, recall 0,5698). CWE-89 và CWE-434 có F1 ≤ 0,21. Tác giả nhấn mạnh rằng cần báo cáo FPR đã hiệu chỉnh mới trung thực. — [arXiv 2606.22581](https://arxiv.org/abs/2606.22581)
- [Đo] Tandon & Chan 2003 báo cáo theo số báo nhầm/ngày (1, 5, 10, 50, 100). Ở 1 và 5 báo nhầm/ngày, M-LERAD và t-stide phát hiện số tấn công tương đương; khác biệt chỉ rõ ở 10 báo nhầm/ngày. — [Tandon & Chan 2003](https://cs.fit.edu/~pkc/papers/dmsec03tandon.pdf)
- [Đo] Kim et al.: ensemble nhiều bộ phân loại theo ngưỡng (hàm leaky-ReLU) giảm FAR và đạt AUC 0,928, so với 0,890 khi lấy trung bình. — [Kim et al.](https://www.covert.io/research-papers/deep-learning-security/LSTM-based%20System-call%20Language%20Modeling%20and%20Robust%20Ensemble%20Method%20for%20Designing%20Host-based%20Intrusion%20Detection%20Systems.pdf)

### Inferences
- Ngưỡng của Pulse (p < 5×(0,05/30) ≈ 0,0083, hai cửa sổ liên tiếp) là ngưỡng cố định chung, đã hiệu chỉnh conformal, và nghiêm hơn quy ước LID-DS (max-validation theo từng kịch bản). Để so sánh công bằng với văn liệu, nên báo cáo thêm một chế độ thứ hai, "max-validation theo kịch bản", trên 50 bản ghi validation, song song với chế độ "no-tuning" hiện tại. Ghi rõ đây là hai chế độ khác nhau.
- Luật hai cửa sổ liên tiếp giúp giảm báo nhầm, nhưng có thể làm mất các exploit một phát trong process (đọc `/etc/passwd` một lần). Gợi ý: cho các tín hiệu "novelty rời rạc" (path mới, syscall mới, n-gram theo thread mới) báo ngay ở cửa sổ đầu như tripwire, còn luật hai cửa sổ chỉ áp cho nhánh tần suất. Đây là suy luận.
- Báo cáo song song "DR ở FPR cố định theo bản ghi" (ví dụ 1 %, 3 %, 5 %) như Kozachok et al. sẽ giúp đối chiếu Pulse với STIDE có ngưỡng.

### Gaps
- Không tìm được bài nào đo trên LID-DS 2021 mức DR tăng thêm khi chuyển từ ngưỡng chung sang ngưỡng theo kịch bản ở cùng FPR.
- Chưa tìm được bằng chứng định lượng về tác động của luật N-cửa-sổ-liên-tiếp lên DR trên LID-DS.

## 4. Ensemble / kết hợp detector (tần suất + sequence + argument) và khả năng chạy online/streaming

### Takeaway
Cả văn liệu cổ điển lẫn bài container gần đây đều ủng hộ kết hợp các nguồn tín hiệu khác nhau thay vì làm detector đơn sâu hơn. CHIDS (tần suất + syscall mới + argument mới) vượt cả mô hình chỉ tần suất và mô hình chỉ sequence trên cùng tập. Trên LID-DS 2019, thuật toán tốt nhất thay đổi theo từng kịch bản, nên OR-ensemble của các detector bổ sung nhau có tiềm năng nâng DR nhưng sẽ cộng dồn FA. Các bài này đều dùng thiết kế có thể chạy streaming theo cửa sổ (LID-DS tính điểm trên từng syscall; ReplicaWatcher xử lý 48 pod dưới 2,25 s).

### Cited Findings
- [Đo] ReplicaWatcher Bảng IV: CHIDS (kết hợp ba tín hiệu) có precision 0,97–1,00 và recall 0,96–1,00, cao hơn CDL (chỉ tần suất) và STIDE-BoSC (chỉ sequence) trên cả 13 kịch bản. Lưu ý: người đánh giá cũng là tác giả CHIDS. — [ReplicaWatcher NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Đo] Tandon & Chan 2003: gộp sequence và argument (M-LERAD) phát hiện bằng chỉ argument (A-LERAD) nhưng hội tụ nhanh hơn. Ở 10 báo nhầm/ngày, cả hai hơn t-stide (27 so với 19 trên 51 tấn công). — [Tandon & Chan 2003](https://cs.fit.edu/~pkc/papers/dmsec03tandon.pdf)
- [Đo] Grimmer et al. 2021 (Bảng 8): cấu hình tốt nhất theo từng kịch bản rơi vào các thuật toán khác nhau, như AE cho 2019/EPS/PHP/SQL, STIDE cho 2012/2014/ZIP, CNN cho 2017, MLP cho BF/2018. Các cấu hình Pareto tối ưu là BOSC 1, STIDE 3, SCG 3, MLP 3, AE 3. — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- [Đo] Kim et al.: ensemble 3 LSTM với hàm kết hợp đề xuất đạt AUC 0,928, cao hơn lấy trung bình (0,890) và bỏ phiếu (0,859). Đường ROC nằm trên mọi đường đơn lẻ. — [Kim et al.](https://www.covert.io/research-papers/deep-learning-security/LSTM-based%20System-call%20Language%20Modeling%20and%20Robust%20Ensemble%20Method%20for%20Designing%20Host-based%20Intrusion%20Detection%20Systems.pdf)
- [Đo] Frossi et al. 2009 (DIMVA): kết hợp mô hình argument với Markov chain giảm FPR trên một số ứng dụng. Ví dụ Hybrid IDS có FPR 0 % trên sing, so với 10 % của S2A2DE. Nhưng chi phí cao: tốc độ trung bình của S2A2DE là 8.463 syscall/s, Hybrid IDS 1.067 syscall/s, SOM-S2A2DE 25 syscall/s. — [Frossi et al., Selecting and Improving System Call Models for Anomaly Detection](https://seclab.cs.ucsb.edu/files/publications/Frossi2009Selecting_and.pdf)
- [Đo] ReplicaWatcher: xử lý và phân loại 48 pod (8 microservice × 6 replica) trong dưới 2,25 s, nhờ chisel lọc sự kiện ngay khi nhận và bộ đặc trưng xử lý nhanh. Máy thử là e2-standard-4. — [ReplicaWatcher NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
- [Đo] LIGHT-HIDS (DeepSVDD rút gọn + novelty detector) tuyên bố F1 0,973 so với 0,942 và suy luận nhanh hơn tới 33,77× (brute-force) và 75× (SQL injection). Chưa kiểm được các tập con này có phải LID-DS-2021 không. — [arXiv 2509.13464](https://arxiv.org/pdf/2509.13464)

### Inferences
- Kiến trúc hiện tại của Pulse (ExtraTrees + support + tripwire syscall mới) đã có hai trong ba tín hiệu của CHIDS là tần suất và syscall mới. Thứ còn thiếu là "argument mới" (path, return value, errno). Bổ sung đúng mảnh này là cách gần CHIDS nhất mà không đổi mô hình.
- Gợi ý ensemble cho Pulse theo thứ tự chi phí, đều là suy luận chưa đo:
  1. **Tripwire path novelty**: path/tiền tố thư mục chưa thấy trong reference set của workload, cộng danh sách file nhạy cảm và cờ '..'. Báo ngay ở cửa sổ đầu, không chờ 2 cửa sổ.
  2. **Đặc trưng histogram return value / errno** đưa vào vector 249 chiều; nhánh support tự bắt được giá trị ngoài khoảng.
  3. **Nhánh thread-aware n-gram có ngưỡng**: n=5–7, ngưỡng mismatch theo cửa sổ lấy từ validation.
  4. Kết hợp bằng OR qua Bonferroni (giữ khung conformal hiện có). Cần đo FA cộng dồn trên LID-DS 2021 và trên live soak trước khi kết luận.
- Phải thận trọng với FA cộng dồn: STIDE-BoSC không ngưỡng có FPR khoảng 60 %. Nếu đưa sequence novelty vào như tripwire tuyệt đối, FA của Pulse sẽ tăng vọt. Nó cần ngưỡng đếm theo cửa sổ như bài thread-info.

### Gaps
- Không tìm được bài nào đo ensemble tần suất + sequence + argument trên LID-DS 2021 theo từng kịch bản.
- Chi tiết bên trong CHIDS (đồ thị, ngưỡng γ, độ trễ) chưa kiểm được do không truy cập được toàn văn.

## 5. Khả năng làm trong eBPF: bắt argument (path, return value, byte count) trong kernel với overhead có giới hạn (Tetragon, Falco, Tracee, gộp trong kernel, LSM hook), số liệu latency

### Takeaway
Bắt argument trong kernel là khả thi với overhead đo được thấp cho mạng và process (khoảng 0,5–1,7 % CPU), nhưng cao hơn cho file (khoảng 7–10 %). LSM hook gắn theo cgroup (pre-filter) là cách rẻ nhất và chống được TOCTOU. Gộp trong kernel (đếm hoặc histogram theo container) thay vì đẩy từng sự kiện lên là chìa khóa để giữ mục tiêu dưới 2 s, vì các công cụ đẩy toàn bộ sự kiện bị mất log nhiều và mô hình argument chạy ở user space rất chậm.

### Cited Findings
- [Đo] Houssel et al. 2026 (arXiv 2608.11418) đo overhead là phần trăm thời gian CPU tăng thêm so với baseline không trace, trên Debian 12, Linux 6.1, 24 core. Workload: httperf 50k kết nối, postmark 50k file, shbm 50k lần exec; dịch vụ chạy trong Docker.
  - **Tại vị trí system call, chỉ entry**: tracing (fentry) 0,76 % (network), 8,12 % (file), 1,15 % (process); tracepoint 1,43 / 8,63 / 1,22 %; kprobe 1,66 / 9,10 / 1,30 %.
  - **Tại vị trí LSM, chỉ entry**: tracing 0,82 / 7,01 / 1,04 %; kprobe 1,10 / 8,99 / 1,10 %; LSM 0,89 / 7,27 / 1,13 %.
  - **Khi bắt cả verdict (exit)**: tracing tăng lên 1,22 / 10,01 / 2,04 %, kprobe 1,40 / 12,99 / 2,10 %. LSM vẫn chỉ cần một lần attach nên rẻ nhất.

  — [Houssel et al., A Study of Kernel Telemetry Options for Security-Oriented Provenance](https://arxiv.org/pdf/2608.11418)
- [Đo] Cùng bài, so sánh cách lọc theo container:
  - Pre-filter bằng LSM_CGROUP (kernel ≥6.0) rẻ nhất: 0,69 % (network), 7,89 % (file), 0,45 % (process).
  - Lọc trong chương trình bằng `bpf_get_current_cgroup_id`: tracing 0,81 / 8,43 / 0,57 %. Riêng LSM với process: in 0,85 %, post 1,66 %.
  - Post-filter (lọc ở user space) gấp đôi lượng trace ghi ra.
  - 69 % syscall của Linux 6.14 (282/407) nhận ít nhất một con trỏ user space, nên dễ bị TOCTOU. Tỉ lệ này là 73 % (30/41) với syscall trong signature của Falco và 74 % (14/19) với Tracee. LSM hook đọc argument sau khi đã copy vào kernel nên có tính toàn vẹn mạnh hơn.

  — [arXiv 2608.11418](https://arxiv.org/pdf/2608.11418)
- [Tuyên bố] Cùng bài: "giám sát một tập interface lớn, nặng syscall sinh khối lượng log lớn và mất log đáng kể"; mọi công cụ dựng graph trong macro benchmark đều bỏ phần lớn log. Tracee và Tetragon là hai công cụ duy nhất nhận biết orchestration (pod). — [arXiv 2608.11418](https://arxiv.org/pdf/2608.11418)
- [Đo] Zhou et al. 2026: eBPF gắn `security_file_open` qua kprobe/LSM, dựng lại path bằng đi ngược dentry đến root hoặc mount point, gửi qua ring buffer theo kiểu đẩy sự kiện; container ID ánh xạ ở user space qua `/proc/[pid]/cgroup`. Dưới stress-ng 15 phút, tác giả báo phần CPU user/kernel do eBPF lần lượt khoảng 60 % và 37 %, thấp hơn SystemTap và Perf. Cách định nghĩa hai con số này không rõ trong bài. — [Zhou et al. 2026](https://mdpi-res.com/d_attachment/mathematics/mathematics-14-00991/article_deploy/mathematics-14-00991.pdf)
- [Đo, tài liệu] Tetragon lọc trong kernel theo từng hook bằng selector:
  - Toán tử: `matchArgs` (Equal, NotEqual, Prefix, Postfix, Mask, FileType), `matchReturnArgs` (Equal, NotEqual, Prefix, Postfix; ví dụ bắt open `/etc/shadow` thất bại trả -1), `matchBinaries`, `matchNamespaces`.
  - Giới hạn: tối đa 5 selector/hook, 5 matchArgs/selector, 4 giá trị/matchArgs, prefix tối đa 256 ký tự, postfix 127 ký tự (kernel ≥5.3). Với tập giá trị lớn thì dùng `InMap`/`NotInMap`, chỉ bị giới hạn bởi bộ nhớ.
  - Trang tài liệu không có số đo overhead.

  — [Tetragon docs, Selectors](https://tetragon.io/docs/concepts/tracing-policy/selectors/)
- [Snippet] Falco: buffer mỗi CPU mặc định 8 MB, chỉnh được từ 1 đến 512 MB qua `syscall_buf_size_preset`. Tăng buffer giúp khi bị syscall drop, nhưng buffer quá lớn có thể làm chậm máy. Modern probe cho phép một ring buffer dùng chung cho nhiều CPU. Không có số đo overhead. — [Falco blog, modern eBPF probe 0.35.0](https://falco.org/blog/falco-modern-bpf-0-35-0/) (chỉ qua snippet, chưa mở trang)
- [Đo] Chi phí mô hình argument ở user space theo từng syscall rất lớn: SOM-S2A2DE chỉ đạt 25 syscall/s, Hybrid IDS 1.067 syscall/s, S2A2DE 8.463 syscall/s (phần cứng 2009). — [Frossi et al. 2009](https://seclab.cs.ucsb.edu/files/publications/Frossi2009Selecting_and.pdf)
- [Đo] Mutz et al. 2007 đo được overhead đáng kể khi unwind call stack lúc audit; hình kết quả không trích được thành số. — [RAID 2007](https://sites.cs.ucsb.edu/%7Evigna/publications/2007_mutz_robertson_vigna_kemmerer_context.pdf)

### Inferences
- Thiết kế phù hợp với Pulse (đếm theo container, cửa sổ 0,5 s) là gộp trong kernel, tránh đẩy từng sự kiện:
  - **Return value / byte count**: ở `sys_exit` của read/write/sendto/recvfrom/sendfile, tăng một bucket log2(ret) trong per-CPU map khóa theo cgroup, và một bucket errno khi ret<0. Chi phí ước lượng gần với tracepoint entry/exit trong Houssel (khoảng 1–2 % cho network/process). Nếu Pulse đã gắn sẵn vào điểm syscall exit thì chi phí biên có thể nhỏ hơn; ghi chú này chưa kiểm trong mã Pulse. Chưa đo.
  - **Path**: hook LSM `file_open` (BPF LSM, kernel ≥5.7; nếu cần pre-filter theo cgroup thì LSM_CGROUP, kernel ≥6.0). Trong kernel chỉ băm path (hoặc vài thành phần đầu), tra BPF hash map "path/tiền tố đã thấy" của workload, rồi đếm novel_path / sensitive_path / dotdot vào map theo cgroup. Chỉ khi path mới mới đẩy một sự kiện nhỏ qua ring buffer để giải thích. Chi phí file workload trong Houssel là khoảng 7–8 % ở stress test ghi 50k file. Workload web của Pulse mở file ít hơn nhiều, nên overhead thực tế có thể thấp hơn, nhưng cần đo trên cụm.
- Cả hai đặc trưng đều không thêm vòng lặp người dùng vào đường kernel→alert, vì user space vẫn đọc map mỗi 0,5 s. Vì vậy mục tiêu dưới 2 s vẫn giữ được. Suy luận, chưa đo.
- Thread-aware n-gram trong kernel tốn hơn: cần lưu k syscall cuối theo TID và băm n-gram mỗi syscall. Có thể thử ở user space trên luồng sự kiện đã lấy mẫu hoặc chỉ cho các syscall không phải I/O thường. Cần đo overhead trước.
- Có thể dùng selector `matchArgs` Prefix / `matchReturnArgs` của Tetragon làm tầng rule (ví dụ open `/etc/shadow` hoặc `/etc/passwd`), nhưng giới hạn 4–5 giá trị mỗi selector khiến nó không thay được mô hình path novelty học theo workload. Phần rule nên tách riêng khỏi kết quả ML theo quy ước dự án.

### Gaps
- Không tìm được benchmark overhead có số đo từ nguồn chính cho Tetragon, Falco hay Tracee khi bắt argument. Hình macro benchmark trong Houssel có số nhưng không trích được đáng tin cậy từ dạng chữ.
- Không có số latency kernel→alert cho các thiết kế bắt argument trong kernel. Chưa thấy bài nào đo trên Kubernetes với mục tiêu dưới 2 s.
- Overhead thực tế của LSM `file_open` + `bpf_d_path` trên workload LID-DS/web cần đo trực tiếp trên cụm lab.
