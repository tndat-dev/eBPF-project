# Thiết kế anomaly score cho sự kiện hiếm trong dòng syscall, học từ dữ liệu normal

Ghi chú nghiên cứu, cập nhật 05/11/2026. Quy ước nhãn:
- **[đo]**: kết quả đo trong nguồn, kèm dataset. **[tuyên bố]**: phát biểu của tác giả, định nghĩa hoặc định lý, không phải số đo. **[snippet]**: chỉ đọc abstract hoặc tóm tắt của công cụ tìm kiếm.
- Mục "Inferences" là suy luận của người viết, chưa được đo. Không có thí nghiệm nào được chạy trong đợt này.
- "Pulse dev" là số đo do coordinator cung cấp (development, ngưỡng một cửa sổ theo recording), không kiểm lại ở đây.
- Mô tả exploit lấy từ ghi chú trước trong repo, đã đọc mã LID-DS ở commit `5b8e414`: `research_notes/Cải thiện Pulse trên LID DS/hard_scenarios.md`. Các ghi chú đó không dựa trên recording thật.

## Chuẩn hoá dãy: tổng, trung bình hay thống kê đuôi; vì sao top-10 mean thắng surprise mass?

### Takeaway
Top-10 mean là rank truncated product, còn surprise mass là họ truncated product. Văn liệu không có kết quả tổng quát cho thấy loại nào luôn thắng. Giải thích hợp lý nhất cho kết quả Pulse dev là phân phối null của tổng tăng theo số event trong cửa sổ, còn của top-k thì gần như không; vì vậy không nên bỏ magnitude, mà nên hiệu chỉnh theo kích thước cửa sổ rồi đo lại.

### Cited Findings
- **[đo, Pulse dev]** Top-10 mean đạt 78 % recall ở 0,5 % false alarm; surprise mass đạt khoảng 63 % ở 0,4 %.
- **[tuyên bố]** Truncated product method lấy tích các p-value không vượt ngưỡng τ, với τ = 1 thì trở thành Fisher — [Zaykin et al. 2002](https://brcwebportal.cos.ncsu.edu/zaykin/some/TruncProdMethod.pdf) [snippet]. Rank truncated product cố định số p-value nhỏ nhất k thay vì τ; có biến thể augmented RTP — [Vsevolozhskaya et al. 2019](https://www.frontiersin.org/journals/genetics/articles/10.3389/fgene.2019.01051/full) [snippet].
- **[tuyên bố]** Phân phối RTP gốc chỉ áp dụng khi test độc lập; với test tương quan cần permutation hoặc phân phối fit từ một pha permutation — [Dudbridge & Koeleman 2004](https://pmc.ncbi.nlm.nih.gov/articles/PMC1182021/).
- **[tuyên bố]** Higher criticism dùng `HC* = max √n (i/n − p(i)) / √(p(i)(1 − p(i)))` và tách được hai giả thuyết ở mọi vùng biên độ/độ thưa mà likelihood ratio test tách được, trong mô hình sparse normal means; dưới biên phát hiện thì mọi phương pháp đều thất bại — [Donoho & Jin 2004](https://arxiv.org/pdf/math/0410072).
- **[tuyên bố]** Fast Generalized Subset Scan đổi likelihood thành empirical p-value từ dữ liệu nền (tiệm cận Uniform[0,1] dưới null) rồi quét tập con có quá nhiều p-value nhỏ; tác giả báo tăng detection power và giảm thời gian chạy so với ba phương pháp khác — [McFowland et al. 2013](https://jmlr.org/papers/volume14/mcfowland13a/mcfowland13a.pdf).
- **[đo]** Likelihood thuần có thể bị yếu tố nền chi phối. Likelihood → likelihood ratio: genomics OOD AUROC 0,626 → 0,755; FashionMNIST vs MNIST 0,091 → 0,996 (bản bảng 0,089 → 0,994); CIFAR-10 vs SVHN 0,095 → 0,931. Tỉ lệ số 0 trong ảnh tương quan 0,85 với likelihood. Background model học trên input đột biến ngẫu nhiên, µ ∈ [0,1; 0,2] — [Ren et al. 2019](https://arxiv.org/pdf/1906.02845).
- **[đo]** LSTM language model chấm bằng NLL trung bình theo dãy; trên ADFA-LD đạt 16 % FAR ở 90 % DR. Theo số Creech & Hu mà bài dẫn lại: ELM 13 %, STIDE 23 %, HMM 42 %. Ensemble blend các ngưỡng đạt AUC 0,928, averaging 0,890, voting 0,859 — [Kim et al. 2016](https://arxiv.org/pdf/1611.01726).
- **[đo]** Locality frame count: đếm mismatch trong 20 dãy gần nhất. Với stide, t-stide và HMM đều có ngưỡng đạt TP trung bình 96,9 %, RIPPER 95,3 % (dữ liệu UNM). Tác giả kết luận không phương pháp nào luôn tốt nhất, và chọn luồng dữ liệu quan trọng hơn chọn mô hình — [Warrender et al. 1999](https://homeostasis.scs.carleton.ca/~soma/id-2007w/readings/warrender-models.pdf). pH dùng frame 128 — [Somayaji & Forrest 2000](https://www.usenix.org/legacy/events/sec00/full_papers/somayaji/somayaji_html/node2.html).

### Inferences
- `max(0, −log p − log 100)` là dạng mềm của truncated product. Nó cũng có hình thức của một bước CUSUM với reference k = log 100, nhưng không tích luỹ qua thời gian.
- Lý do top-10 thắng (giả thuyết): tổng trong cửa sổ bận có nhiều event với p dưới 1 %, nên đuôi normal của tổng rất dài và ngưỡng bị kéo lên. Top-10 gần như không phụ thuộc n. Điều này khớp nhận xét của coordinator rằng saturation không phải vấn đề chính của nhánh này.
- Kiểm tra rẻ tiền: vẽ quantile 99,5 % trên normal của cả hai thống kê theo `log2(n)`. Nếu tổng tăng theo n còn top-10 thì không, hãy thử lại surprise mass với ngưỡng theo nhóm n (Mondrian). Cách hiệu chỉnh này thuộc phạm vi ghi chú `tail_and_recording_calibration.md`.
- Không cần chọn một k: dùng vector top-k với k ∈ {1, 3, 10, 30, 100}, lấy p-value thực nghiệm cho từng k, rồi lấy min-p đã hiệu chỉnh. HC trên p-value từng event là thay thế có cơ sở lý thuyết hơn, nhưng event trong một thread tương quan nên chỉ được hiệu chỉnh bằng normal held-out, không dùng công thức tiệm cận.
- Điểm theo context có entropy cao vốn lớn mà không hề bất thường. Có thể thử `s(e) = log p_low(x | ctx ngắn) − log p_high(x | ctx dài)`, tức là ratio giữa hai bậc. Thống kê này phát hiện call phổ biến nhưng lạ trong context dài. Chưa có bài HIDS nào đo; µ-mutation của Ren là cách khác để tạo mô hình nền.

### Gaps
- Không tìm thấy bài HIDS nào so sánh trực tiếp sum, mean, top-k, TPM, HC ở false alarm rất thấp.

## Bậc context và thống kê nào tách từng loại exploit yếu?

### Takeaway
Năm trên sáu kịch bản yếu không chủ yếu là bài toán về bậc context. CVE-2019-5418, Heartbleed và Juice-Shop có dấu vết nằm ở argument, kích thước hoặc return value; CVE-2020-13942 và PHP_CWE-434 cần context theo process, còn CVE-2018-3760 có vẻ cần tích luỹ qua nhiều cửa sổ. Tăng bậc n-gram trên tên syscall khó giải quyết nhóm đầu.

### Cited Findings
- **[đo]** stide bị mù khi cửa sổ ngắn hơn minimal foreign sequence, và MFS ngắn nhất trong dữ liệu Hofmeyr dài 6 là lời giải cho câu hỏi "vì sao 6". Markov detector dùng xác suất có điều kiện không có vùng mù này (dữ liệu tổng hợp và UNM) — [Tan & Maxion 2002](https://cs.fit.edu/~pkc/id/related/tan-ieeesp02.pdf).
- **[đo, định tính]** Cửa sổ phụ thuộc context bằng sparse Markov transducers cùng ngưỡng xác suất vượt stide và t-stide, kể cả khi cùng độ dài cửa sổ (Lincoln Labs và UNM) — [Eskin et al. 2001](https://dl.packetstormsecurity.net/papers/IDS/hids/Modeling-System-Calls-for-IDS.pdf).
- **[đo]** Thread information trên LID-DS **2019**, ô là DR/số false alarm (Table 7 EISA 2021, chép trong `research_notes/Cải thiện ML Pulse LID DS/published_ml_results.md`; PDF gốc trả 403 khi đọc lại đợt này): Heartbleed SCG+TI 0,95/25, MLP+TI 0,01/7; ZipSlip SCG+TI 1,00/0, MLP+TI 0,00/0; CVE-2019-5418 MLP+TI 1,00/0, SCG không TI 0,00/9 — [Grimmer et al. 2021](https://old.dbs.uni-leipzig.de/en/publication/title/improving_host_based_intrusion_detection_using_thread_information).
- **[đo]** STIDE n = 5 chỉ dùng tên syscall, score là tỉ lệ n-gram chưa thấy trên cả recording, LID-DS **2021**, recall/FPR: CVE-2018-3760 0,98/0,005; CVE-2019-5418 0,17/0,041; Heartbleed 0,09/0,012; Juice-Shop 0,12/0,000; CVE-2020-13942 0,00/0,068 — [Gurbuz 2026, Table 7.1](https://doi.org/10.71548/25675), chép từ `strongest_verified_results.md`, không đọc lại ở đây.
- **[đo, Pulse dev]** Recording yếu ở chế độ một cửa sổ: CVE-2019-5418 5/36, Juice-Shop 15/36 (tối đa 25 có footprint), Heartbleed 25/36, CVE-2018-3760 26/37, CVE-2020-13942 29/35, PHP_CWE-434 28/35. Ở phép so sánh "≤ sàn" (8,8 % normal) nhánh tốt nhất đạt CVE-2019-5418 30/36, Heartbleed 26/36, CVE-2018-3760 26/37, Juice-Shop 18/36 (`SENTINEL_PULSE_STATUS.md`, mục ngày 02/11).
- **[tuyên bố]** Cơ chế exploit, từ mã LID-DS: CVE-2019-5418 gửi một `curl` với Accept traversal tới `/etc/passwd` trên route normal cũng dùng; Heartbleed đọc khoảng 8 B rồi ghi khoảng 65 KB trên một socket, còn heartbeat normal 4–16 KB cả hai chiều (kích thước là suy luận từ mã, chưa kiểm trên recording); CVE-2018-3760 gửi hai GET, GET đầu có thể gây exception; CVE-2020-13942 POST `/context.json` chạy `touch /tmp/mvel`; PHP_CWE-434 upload `evil_script.php` chạy `uname`, `id`, `wget`; Juice-Shop là SQLi qua cùng file SQLite — [hard_scenarios.md, mã LID-DS](https://github.com/LID-DS/LID-DS/tree/5b8e4143301240c705b09dacbff3a49d72c08fcf/scenarios).
- **[đo, repo]** Normal của CVE-2020-13942 có khối lượng `pread` rất lớn (9.175.836 trong một đo đạc của dự án) — `research_notes/Cải thiện Pulse trên LID DS/pulse_gap_analysis.md`.

### Inferences

| Kịch bản | Giả thuyết vì sao một cửa sổ yếu | Thống kê nên thử | Bậc context |
|---|---|---|---|
| CVE-2019-5418 | Dãy tên giống route normal; tín hiệu ở path | Trie path theo `proc.name` (mục sau); token `(syscall, path-class)` trong language model | Thấp (0–2) cho path; n-gram tên không giúp |
| Heartbleed | Dãy gần như heartbeat normal | `log(bytes_out) − log(bytes_in)` theo fd/connection với mật độ liên tục đuôi nặng; max write theo connection | Trạng thái fd, không phải n-gram |
| Juice-Shop | Dấu vết rất ít ở mức syscall | Mô hình offset `pread` theo file; giao thoa ghi challenge-solve; báo recall trên mẫu số 25 | Trạng thái file; khả năng có trần thật |
| CVE-2018-3760 | STIDE cả recording đạt 0,98 nên dấu vết có vẻ rải qua nhiều cửa sổ hoặc tỉ lệ nhỏ | Tích luỹ surprise có quên (CUSUM, LFC) qua 2–4 cửa sổ, trong ngân sách độ trễ ≤3 s | 5–7 trên tên, thread-aware |
| CVE-2020-13942 | Normal lớn và nhiễu; STIDE theo tỉ lệ bị pha loãng (0,00/0,068) | Chấm theo `proc.name` hoặc thread group rồi lấy max; `P(exec con given process cha)`; không dùng mẫu số toàn cửa sổ | Theo process |
| PHP_CWE-434 | Exec ngắn, có thể rơi ngoài cửa sổ mạnh nhất | Như trên cộng `P(extension given thư mục)` cho `.php` trong thư mục upload | Theo process và path |

- Đề xuất "bậc" chung: thay vì chọn một n, ghi nhận **độ sâu khớp dài nhất** (longest matching context) cho mỗi event theo kiểu PPM, rồi học phân phối độ sâu trên normal. Đây là phiên bản sequence của độ sâu lệch trong path. Nó phân biệt "lệch ở bậc 7 nhưng khớp bậc 6" với "lệch ngay từ bậc 2", và thay thế số đếm unseen 7-gram viết tay.
- Số đếm unseen 7-gram (hàng trăm so với tối đa khoảng 90) có thể thành thống kê học được: `k` unseen trong `n` event, kiểm định theo negative binomial có rate và độ phân tán fit trên normal held-out, theo từng scenario/process. Khi đó không còn ngưỡng cố định.
- Mâu thuẫn cần ghi rõ: CVE-2019-5418 đạt 1,00 trên 2019 nhưng 0,17 trên 2021 (khác dataset, khác mô hình); Heartbleed SCG+TI 0,95 trên 2019 có 25 false alarm. Không được xem các số 2019 là dự báo cho 2021.

### Gaps
- Không có nguồn nào đo I/O size cho Heartbleed hoặc đo per-scenario theo bậc context trên LID-DS 2021.
- Cơ chế theo từng kịch bản chưa được kiểm trên recording trong đợt này; cần bảng event có surprise cao nhất của từng recording bị miss.

## Mô hình chuỗi và smoothing: PPM, CTW, Sequence Memoizer, HMM và ảnh hưởng của discount

### Takeaway
Witten-Bell không phải lựa chọn mạnh theo bằng chứng NLP. Kneser-Ney và hierarchical Pitman-Yor (HPY) cho xác suất tốt hơn ở count thấp, và cơ chế của chúng có ý nghĩa trực tiếp cho việc phân bậc. Tuy vậy, mọi so sánh này đo bằng cross-entropy trên văn bản, không phải bằng recall ở false alarm thấp, nên phải đo lại.

### Cited Findings
- **[đo]** Trên corpus WSJ/NAB với 4-gram và 5-gram, Kneser-Ney và kneser-ney-mod luôn tốt nhất; `witten-bell-backoff`, Katz và abs-disc-interp xấp xỉ hoặc kém baseline, trừ ở tập dữ liệu lớn nhất. Interpolated vượt backoff ở count thấp khác 0 vì bậc thấp giúp xác định discount — [Chen & Goodman 1999](https://u.cs.biu.ac.il/~yogo/courses/mt2016/papers/chen-goodman-99.pdf).
- **[đo]** Perplexity trigram trên 14 triệu từ: IKN 116,7; MKN 113,6; HPYLM 114,3; HPYCV 113,2; Dirichlet phân cấp 140,5. IKN là suy luận xấp xỉ của HPY; discount trung bình phụ thuộc count (Hình 2) — [Teh 2006](https://aclanthology.org/P06-1124.pdf).
- **[tuyên bố]** PPM-C có `P(escape|s) = |Σs| / (|Σs| + Σ N(sσ))`, cùng dạng với λ của Witten-Bell trong Chen & Goodman. Witten & Bell nhận xét không có lý do nguyên tắc cho cơ chế escape nào — [Begleiter et al. 2004](https://arxiv.org/pdf/1107.0051).
- **[đo]** De-CTW 3,02 và PPM-C 3,03 bit/ký hiệu trên Calgary Corpus, không khác biệt có ý nghĩa thống kê; hai thuật toán này dẫn đầu dự đoán chuỗi ở protein, văn bản và nhạc, nhưng một biến thể LZ thắng phân loại protein — [Begleiter et al. 2004](https://arxiv.org/pdf/1107.0051).
- **[đo]** Slide deck của nhóm Hamou-Lhadj (login, xlock của UNM; Firefox của nhóm) cho thấy chi phí FP khác nhau lớn: login, stide (cửa sổ 6 và 10) 40 %, HMM 40 %, KSM 0 %; xlock, stide 1,5 %, HMM 0 %; Firefox, stide 44,6 % và 49,2 %, HMM 1,4 %, KSM 0,6 % — [AHLS deck 2013](https://ahls.dorsal.polymtl.ca/system/files/AHLS%20-%20SBA%20Presentations%20(2013-12-10).pdf). Đây là slide, không phải bài báo.
- **[đo, repo]** LSTM thư viện LID-DS tốn 20–25 phút mỗi epoch trên kịch bản vừa, dự kiến 12–15 CPU-giờ, vượt trần 8 CPU-giờ của protocol (`SENTINEL_PULSE_STATUS.md`).

### Inferences
- **Vì sao đáng thử KN/HPY ngoài chuyện cross-entropy.** Bậc thấp nhất của KN dùng số context khác nhau mà call đã xuất hiện, không phải số lần xuất hiện. Một call xuất hiện ở nhiều context thì rẻ khi gặp ở context mới; call chỉ sau một context rất hẹp thì đắt. Đây là phân bậc thật cho sequence.
- Discount phụ thuộc count, và tỉ lệ discount trên count lớn nhất ở count thấp, nên n-gram count 1–3 có thể nằm ở vùng điểm giữa "phổ biến" và "chưa thấy" thay vì gần bằng "phổ biến".
- Thứ tự thử: HPY xấp xỉ (hoặc KN) → PPM có exclusion → De-CTW. HMM và Sequence Memoizer đầy đủ để sau: HMM không thắng rõ trong Warrender và tốn huấn luyện; Sequence Memoizer không được đọc đợt này.

### Gaps
- Không tìm thấy bài HIDS nào đo ảnh hưởng của smoothing lên recall ở false alarm thấp. Đây cũng là đóng góp mới khả dĩ cho paper.
- Sequence Memoizer (Wood 2009), PPMII/SEE (Shkarin), Lee & Stolfo, Sekar, Hubballi và Khreich 2017 không đọc được toàn văn hoặc tìm không ra đợt này. Tìm PPMII/SEE trả về kết quả không liên quan.

## Per-thread, per-process và mô hình neural làm teacher

### Takeaway
Bằng chứng ủng hộ context theo thread và process là thật, nhưng không đồng đều giữa kịch bản và loại mô hình. Đưa return value và tên process vào token có số đo dương. Teacher LSTM khả thi về lý thuyết nhưng chưa có nguồn nào chứng minh chưng cất xuống bảng đếm cho HIDS.

### Cited Findings
- **[đo]** EISA 2021 trên LID-DS 2019: trung bình SCG 0,14/22,0 → 0,90/29,1 khi thêm TI; MLP 0,40/12,5 → 0,79/4,2; AE 0,63/30,1 → 0,62/2,2 (DR/số false alarm) — [Grimmer et al. 2021](https://old.dbs.uni-leipzig.de/en/publication/title/improving_host_based_intrusion_detection_using_thread_information), qua `published_ml_results.md`.
- **[đo]** Thêm argument vào embedding tăng LSTM và Transformer tới 11,3 % trên language modeling — [Fournier et al. 2021](https://arxiv.org/pdf/2103.06915). Đây là metric ngôn ngữ trên trace của họ, không phải phát hiện xâm nhập.
- **[đo]** Mô hình argument theo call stack giảm false positive khoảng 2,7 lần so với không context; không context: 12.956/44.796.054 event = 2,89 × 10⁻⁴ (10 host, 64 ngày) — [Mutz et al. 2007](https://sites.cs.ucsb.edu/%7Evigna/publications/2007_mutz_robertson_vigna_kemmerer_context.pdf).

### Inferences
- Giữ per-thread cho sequence, nhưng tách token chứa thread mới theo `proc.name` để process mới không bắt đầu từ context rỗng. Backoff nên là `thread → proc.name → scenario`.
- Token hợp nhất `(syscall, success/errno-class, log2-size-class)` trong language model sẽ biến errno và I/O thành một phần xác suất có điều kiện thay vì nhánh multinomial riêng. Chi phí là alphabet lớn hơn và dữ liệu thưa hơn; đó là lý do cần KN/HPY.
- Teacher: dùng LSTM/Transformer offline trên một số kịch bản để **ước lượng trần**, không phải để triển khai. Nếu teacher không tách được các kịch bản yếu thì dừng hướng tăng độ phức tạp sequence.

### Gaps
- Không tìm thấy kết quả chưng cất neural next-call xuống bảng đếm cho syscall, cũng không tìm thấy Transformer NLL trên LID-DS 2021 có số theo kịch bản.

## Mô hình count/categorical thưa: vì sao tree không thấy và nên dùng gì?

### Takeaway
ExtraTrees với corruption kiểu swap/scale gần như không có ví dụ âm cho sự kiện thưa, nên việc không thấy một sự kiện hiếm là kết quả của reference distribution chứ không chỉ của thuật toán. Dirichlet-multinomial cấp cửa sổ và G-test là hai ứng viên chính vì chúng dùng cả những item đã thấy. ECOD/HBOS giữ độ nhạy theo từng feature nhưng vẫn có sàn thực nghiệm.

### Cited Findings
- **[tuyên bố]** Anomaly có thể định nghĩa qua density level so với reference measure, và học được như phân loại giữa dữ liệu và mẫu từ reference; việc lấy mẫu nhân tạo chỉ có lý nếu sampling plan được chọn tốt — [Steinwart et al. 2005](https://jmlr.org/papers/volume6/steinwart05a/steinwart05a.pdf).
- **[tuyên bố]** Noise nên gần dữ liệu, nếu không bài toán phân loại quá dễ và không học được cấu trúc — [Gutmann & Hyvärinen 2010](https://proceedings.mlr.press/v9/gutmann10a/gutmann10a.pdf).
- **[đo]** Negative sampling kèm RF hoặc NN có AUC cao hơn đáng kể trên benchmark 4–36 chiều và dữ liệu thiết bị thật, không phải dữ liệu thưa — [Sipple 2020](https://arxiv.org/pdf/2007.10088). Artificial anomalies giúp mô hình bắt hơn 77 % lớp intrusion chưa biết (dữ liệu mạng DARPA) — [Fan et al. 2004](https://doi.org/10.1007/s10115-003-0132-7) [snippet]; không kiểm chứng được việc họ dùng giá trị hiếm khi sinh mẫu.
- **[đo]** ECOD xếp hạng nhất trong 11 baseline trên 30 benchmark, AUC cao hơn 2 %, AP cao hơn 5 % so với hạng hai — [Li et al. 2022](https://arxiv.org/pdf/2201.00382).
- **[đo]** Không phương pháp unsupervised nào tốt hơn có ý nghĩa thống kê; hiệu năng phụ thuộc loại anomaly. HBOS, COPOD, ECOD, NB nhanh nhất vì xử lý từng feature độc lập — [ADBench, Han et al. 2022](https://arxiv.org/pdf/2206.09426).
- **[đo]** HS-Trees trên dữ liệu 3–10 chiều: HTTP 0,982–0,996; SMTP 0,740–0,875 — [Tan et al. 2011](https://www.ijcai.org/Proceedings/11/Papers/254.pdf). xStream không khác biệt có ý nghĩa với baseline ở chế độ tĩnh, nhưng hỗ trợ feature mới qua hashing — [Manzoor et al. 2018](https://www.andrew.cmu.edu/user/lakoglu/pubs/18-kdd-xstream.pdf).
- **[tuyên bố]** Likelihood ratio phù hợp cho sự kiện hiếm hơn giả định chuẩn, kể cả với mẫu nhỏ — [Dunning 1993](https://aclanthology.org/J93-1003.pdf).
- **[đo]** MIDAS dùng chi-squared giữa count hiện tại và lịch sử trên Count-Min Sketch để phát hiện burst: DARPA 4,5 triệu cạnh, MIDAS-R AUC 0,95, AP 0,97, MIDAS AP 0,95, so với baseline AP 0,75 — [Bhatia et al. 2020](https://arxiv.org/pdf/1911.04464).
- **[đo]** Dirichlet compound multinomial mô hình burstiness tốt hơn multinomial về perplexity và phân loại trên ba tập văn bản — [Madsen et al. 2005](https://mlanthology.org/icml/2005/madsen2005icml-modeling) [snippet].

### Inferences
- **Vì sao tree không thấy:** swap giữ nguyên marginal nên bin bằng 0 vẫn là 0; scale nhân 0 vẫn bằng 0. Reference gần như không có khối lượng ở "bin thưa có một event". Thêm vào đó, ExtraTrees chỉ tách được khi feature đó được chọn ngẫu nhiên ở một nút.
- **Corruption mới:** cộng 1–k event vào bin chọn theo phân phối nghịch với độ phổ biến, với k theo log-uniform. Giữ swap/scale cho phần cấu trúc. Rủi ro: nếu chỉ cộng vào bin chưa thấy thì tree đơn thuần học lại novelty, nên phải trộn cả bin hiếm đã thấy và quan sát bằng các phép thử ở mục novelty.
- **G-test cửa sổ:** `G = 2 Σ O_i ln(O_i / (n p_i))`. Ví dụ tính tay: item đã thấy p = 0,02, n = 1000, O = 200 đóng góp `200 ln 10 ≈ 460`, còn một item mới p = 10⁻⁶, O = 1 chỉ đóng góp `ln 1000 ≈ 6,9`. Surprise mass cho item đầu đúng bằng 0 ở mọi O, vì `−ln 0,02 ≈ 3,9 < ln 100 ≈ 4,6`.
- Như vậy **tỉ lệ 83 % và 100 % khối lượng từ item chưa thấy có thể một phần do chính sàn `log 100`**: statistic không thể nhìn thấy item có p ≥ 1 %. Nên đo lại tỉ lệ này với G-test trước khi kết luận file và errno chỉ có thông tin novelty.
- **Dirichlet-multinomial thay cho G thuần.** Normal bursty sẽ làm G thuần báo nhầm. Với α_i học trên cửa sổ normal, chi phí lần gặp k + 1 của item i là `−log((α_i + k)/(A + m))`. Hàng trăm lần mở cùng một file mới chỉ tốn gần bằng vài lần, còn hàng trăm file mới khác nhau tốn hàng trăm lần. Đây là phân bậc theo độ đa dạng, học từ dữ liệu.
- **Poisson-Gamma/NB theo bin** là bản rút gọn chạy nhanh khi bin độc lập. Zero-inflated chỉ đáng dùng khi NB fit kém rõ ràng ở bin có nhiều cửa sổ bằng 0.
- **ECOD/HBOS** giữ độ nhạy vì một bin không bị các feature khác che, nhưng ECDF có sàn: mọi giá trị vượt max training gần như cùng tail probability. Nên là baseline nhanh, không phải đích cuối.

### Gaps
- Không tìm thấy nghiên cứu HIDS đo Dirichlet-multinomial, NB theo bin, hay corruption cho sự kiện thưa. Không có nguồn nào đo trực tiếp Isolation Forest hay Mondrian trên count thưa kiểu syscall; tìm kiếm chỉ trả về tài liệu thư viện và kinh nghiệm thực hành về one-hot.

## Giữ thông tin file path mà không va chạm hash

### Takeaway
Trie path theo process với xác suất escape học được cho từng nút, thêm mô hình chính tả làm base measure, là thiết kế phù hợp nhất với yêu cầu "điểm phân bậc". PathEvilness của LID-DS dùng cùng cấu trúc trie nhưng công thức viết tay, nên là baseline để so sánh.

### Cited Findings
- **[tuyên bố, mã nguồn]** `PathEvilness` bằng 0 nếu path đã thấy, ngược lại bằng `1/(depth(tổ tiên sâu nhất đã biết)+1)`; không dùng count, không theo process — [LID-DS source](https://raw.githubusercontent.com/LID-DS/LID-DS/master/algorithms/features/impl/path_evilness.py).
- **[tuyên bố]** Kruegel/Mutz: string length dùng `p(l) = σ²/(l−µ)²` (Chebyshev); character distribution dùng biến thể χ²; structural inference theo lớp ký tự; token finder là tập đóng — [Mutz et al. 2006](https://sites.cs.ucsb.edu/~chris/research/doc/tissec06_syscall.pdf), qua `argument_feature_encoding.md`.
- **[đo]** 25/25 buffer-overflow trên `eject`, `fdformat`, `ffbconfig`, `ps`, không false alarm trên bốn chương trình đó; 14 trên `ftpd`, 8 trên `sendmail`, 17 trên `telnetd` (MIT Lincoln Lab 1999) — cùng nguồn.
- **[đo, định tính]** Symbol SOM nhận ra độ tương tự của path tạm nên không báo nhầm, trong khi FSA-DF gắn cờ hơn 1000 syscall lành tính trên `proftpd` — [Frossi et al. 2009](https://seclab.cs.ucsb.edu/files/publications/Frossi2009Selecting_and.pdf), qua `argument_feature_encoding.md`.
- **[tuyên bố]** Nested Pitman-Yor nhúng mô hình chính tả ký tự HPY làm base measure của mô hình từ, nên từ mới có xác suất khác nhau tuỳ cách viết, không dùng một hằng số unknown — [Mochihashi et al. 2009](https://aclanthology.org/P09-1012.pdf).

### Inferences
Đặc tả đề xuất, theo cặp `(proc.name, lớp truy cập R/W/stat)`:

`P(path) = Π_d P(c_d | prefix_d)`, với mỗi nút là một Pitman-Yor:

`P(c | u) = (c_uc − d·t_uc)/(θ_u + c_u) + ((θ_u + d·t_u)/(θ_u + c_u)) · P(c | parent(u))`

`parent(u)` lùi theo chuỗi `(proc, prefix) → (mọi proc, prefix) → base measure ký tự`.

Điểm này phân bậc nhờ ba nguồn thực sự học được:
1. **Churn theo thư mục:** thư mục tạm có nhiều giá trị mới nên escape cao và thành phần mới rẻ; `/etc` ổn định nên đắt.
2. **Vị trí lệch:** lệch gần gốc phải trả nhiều nút hiếm hơn, nhưng mức phạt học từ dữ liệu thay vì `1/(depth+1)`.
3. **Chính tả:** `*.php` trong thư mục upload hoặc tên giống file hệ thống có xác suất khác tên tạm ngẫu nhiên.

Hai lưu ý: base measure ký tự có thể cho tên lành tính như `passwd` điểm thấp hơn chuỗi ngẫu nhiên, nên cần đo trên thực tế thay vì giả định chiều tác động. Và cần chuẩn hoá các phần ngẫu nhiên hoặc pid trong path trước khi đếm. Nhánh này nên so sánh với PathEvilness và với hashed bins hiện tại.

### Gaps
- Không có kết quả đo mô hình Pitman-Yor hoặc Dirichlet-tree cho path syscall. Thiết kế trên là chuyển giao từ NLP, chưa được kiểm chứng.

## Khi nào density biến thành novelty rule, và điều gì làm nó phân bậc?

### Takeaway
Với một estimator chỉ dựa trên count của ký hiệu, mọi item chưa thấy nhận cùng một xác suất, nên nó là novelty rule theo cấu trúc, và smoothing tốt hơn không thay đổi được điều đó. Muốn phân bậc giữa các item mới phải có thông tin ngoài count (context, cấu trúc, đặc trưng), và tiêu chí chấp nhận phải đo khả năng xếp hạng thay vì tỉ lệ khối lượng từ item chưa thấy.

### Cited Findings
- **[tuyên bố]** Natural estimator gán cùng xác suất cho mọi ký hiệu xuất hiện cùng số lần; biến thể Good-Turing đơn giản cách estimator natural tốt nhất tối đa KL `(3+o(1))/n^(1/3)` — [Orlitsky & Suresh 2015](https://proceedings.neurips.cc/paper_files/paper/2015/file/d759175de8ea5b1d9a2660e45554894f-Paper.pdf).
- **[tuyên bố]** Prior phân cấp của Friedman & Singer giả định các outcome quan sát được chỉ là tập con nhỏ của toàn bộ alphabet — [NIPS 1998](https://collaborate.princeton.edu/en/publications/efficient-bayesian-parameter-estimation-in-large-discrete-domains/) [snippet].
- **[tuyên bố]** LERAD ước lượng xác suất novel event của mỗi rule bằng `p = r/n` (số giá trị khác nhau trên số quan sát), mượn từ nén dữ liệu — [Tandon & Chan 2007](https://cs.fit.edu/~pkc/papers/kdd07.pdf). Mô hình phi dừng: bỏ qua tần suất, chỉ dùng lần xuất hiện cuối và thời gian từ anomaly trước — [Tandon 2008](https://cs.fit.edu/media/TechnicalReports/cs-2008-01.pdf).
- **[đo]** A-LERAD (syscall, return value, error status, argument) bắt 10/13/17 attack ở 5/10/20 false alarm mỗi ngày trên DARPA BSM; 10 false alarm mỗi ngày tương ứng dưới 0,1 % trên ROC — [Tandon 2008, Table 4.2](https://cs.fit.edu/media/TechnicalReports/cs-2008-01.pdf). Nhưng `open` return value, `open` error status và `fcntl` error status gây false alarm mà không bắt được attack nào (Table 4.5, qua `argument_feature_encoding.md`).
- **[tuyên bố]** Tan & Maxion phân biệt common, rare (≤ 0,5 %) và foreign; Warrender định nghĩa rare < 0,001 % — [Tan & Maxion 2002](https://cs.fit.edu/~pkc/id/related/tan-ieeesp02.pdf), [Warrender et al. 1999](https://homeostasis.scs.carleton.ca/~soma/id-2007w/readings/warrender-models.pdf).
- **[đo, Pulse dev]** Khối lượng cửa sổ tấn công từ item chưa thấy: file 83 %, errno 100 %. Chủ dự án không chấp nhận các nhánh này.

### Inferences
**Ba cơ chế phân bậc thật:**
1. **Base measure có cấu trúc:** `P(mới) = escape(context) × G0(item)`. G0 khác nhau theo item (mục path).
2. **Xác suất mới học theo workload và context:** `r/n` hoặc Good-Turing theo từng nút, thay vì một hằng số toàn cục. Vì recording là cụm, không phải mẫu độc lập, nên nên ước lượng theo số **recording** chứa item (leave-one-recording-out), không theo số event. Ý tưởng dựa trên tần suất xuất hiện theo mẫu này chưa được kiểm nguồn đợt này.
3. **Đo cả phần đã thấy:** G-test hoặc Dirichlet-multinomial lấy tín hiệu từ count của item đã thấy.

**Giới hạn trung thực:**
- Với errno, alphabet nhỏ và cặp `(syscall, errno)` chưa thấy có rất ít thông tin phụ. Backoff theo `P(errno | mọi syscall)` chỉ phân bậc yếu. Nên đưa errno vào token sequence và đếm theo lớp, không nên xây nhánh riêng. Nếu sau đó tín hiệu vẫn chỉ đến từ cặp chưa thấy, cần báo cáo rằng dữ liệu không chứa thông tin phân bậc nào khác.
- Với kịch bản không có cửa sổ normal held-out nào chứa item mới, mọi ngưỡng đã hiệu chỉnh đều nằm dưới item mới rẻ nhất. Khi đó mô hình học được tương đương với novelty rule trên kịch bản ấy; đổi công thức không sửa được, chỉ có thêm dữ liệu normal biến thiên mới sửa được. Phải đếm và công bố số kịch bản ở trạng thái này.
- Trên I/O size có lối thoát sạch: mô hình liên tục không có ô unseen. Dùng Student-t hoặc mixture trên `log size` theo `(proc, syscall, lớp fd)` và trên ratio out/in theo fd.

**Phép thử chấp nhận cho "điểm phân bậc" (tính trên development):**
1. AUC và recall **chỉ trên các cửa sổ có ít nhất một item chưa thấy** (cả normal lẫn attack). Bằng 0,5 thì score không có giá trị ngoài cờ novelty.
2. Recall ở cùng ngưỡng **chỉ trên cửa sổ không có item chưa thấy**. Gần 0 nghĩa là mô hình không có thông tin nào ngoài novelty.
3. So với chuẩn tham chiếu là số item chưa thấy (và `any-unseen`). Phải vượt có ý nghĩa ở phép thử 1, dùng khoảng tin cậy bootstrap theo recording.
4. Spearman giữa score và số item chưa thấy trên normal, và số mức điểm khác nhau trên cửa sổ tấn công, để phát hiện suy biến.
5. Số kịch bản có tỉ lệ cửa sổ normal chứa item mới bằng 0 (trạng thái nêu trên).

Tỉ lệ khối lượng từ item chưa thấy nên giữ làm chẩn đoán, không làm tiêu chí: một mô hình trie tốt vẫn có thể có tỉ lệ cao trên `/etc/passwd`, nhưng vượt được phép thử 1.

### Gaps
- Không tìm thấy bài nào định nghĩa phép thử tương đương cho HIDS; các phép thử trên là đề xuất của người viết.

## Bằng chứng về loại score đạt false alarm rất thấp ở mức dãy hoặc recording

### Takeaway
Các điểm false alarm thấp nhất có số đo đều đến từ thống kê novelty hoặc đuôi, kết hợp với context, nhưng trên dataset cũ hoặc với cách đếm false alarm khác nhau. Không có bằng chứng đủ so sánh để nói score nào tốt nhất; kết quả 78 % ở 0,5 % của Pulse dev là mốc nội bộ, chưa chạm dữ liệu official.

### Cited Findings
- **[đo]** STIDE n = 5 theo tỉ lệ unseen, LID-DS 2021: CVE-2018-3760 0,98/0,005; Juice-Shop 0,12/0,000 — [Gurbuz 2026](https://doi.org/10.71548/25675), qua `strongest_verified_results.md`.
- **[đo]** MLP+TI trên LID-DS 2019: trung bình 0,79 DR với 4,2 false alarm — [Grimmer et al. 2021](https://old.dbs.uni-leipzig.de/en/publication/title/improving_host_based_intrusion_detection_using_thread_information), qua `published_ml_results.md`.
- **[đo]** Stide n = 4 ngưỡng 0,2 chỉ đạt 18,9 % DR ở 0,7 % FAR; 80 % DR tốn khoảng 18 % FAR (ADFA-LD) — [Grimmer et al., SCG](https://dbs.uni-leipzig.de/file/Intrusion-Detection-on-System-Call-Graphs.pdf). Cùng bài cho một số cấu hình khác, ví dụ DR 90 % ở 24 % FAR.
- **[đo]** LSTM trên KDD98 AUC 0,994, 2,3 % FAR ở 100 % DR; UNM 0,969, 5,5 % FAR ở 99,8 % DR — [Kim et al. 2016](https://arxiv.org/pdf/1611.01726). Hai dataset này cũ và bị chỉ trích ngay trong bài.
- **[đo]** STIDE 2021 khó hơn 2019 theo F-score, DR, false alarm (n = 7, w = 100, trung bình mọi kịch bản); báo cáo chỉ đưa số dưới dạng hình — [Grimmer et al. 2023](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf).

### Inferences
- FAR, FP theo sequence (Warrender), theo event (Mutz), theo ngày (Tandon), số alarm (LID-DS) không quy đổi được với nhau. Mọi bảng so sánh phải giữ nguyên đơn vị.
- Trong khuôn khổ owner, hợp lý nhất là thống kê đuôi có hiệu chỉnh theo kích thước cửa sổ, kết hợp với thành phần tích luỹ ngắn cho kịch bản rải nhiều cửa sổ.

### Gaps
- Không có nguồn nào công bố đường recall ở FAR ≤ 0,5 % theo từng kịch bản cho nhiều loại score trên cùng LID-DS 2021.

## Nên thử gì tiếp, theo thứ tự nào?

### Takeaway
Thử theo thứ tự chi phí tăng dần trên điểm thô đã lưu, rồi mới tới mô hình mới. Mọi bước chỉ dùng development; official đã chấm một lần nên lần chấm kế tiếp phải được khai báo.

### Cited Findings
- **[tuyên bố, repo]** `scripts/analysis/lidds_ml_scores.py` đã lưu điểm thô nhánh và thống kê surprise mass để chọn luật offline; official đã chấm một lần (`SENTINEL_PULSE_STATUS.md`).

### Inferences
1. **Chẩn đoán trên điểm hiện có:** quantile normal theo `log2(n)` cho top-k và mass; năm phép thử ở mục novelty cho file và errno.
2. **Thay đổi thống kê, chưa đổi mô hình:** mass/top-k theo nhóm n; vector top-k với min-p; unseen n-gram count dưới NB học được; tích luỹ 2–4 cửa sổ cho CVE-2018-3760.
3. **I/O liên tục cho Heartbleed:** ratio out/in theo fd. Đây là phép thử rẻ, không có unseen slot.
4. **G-test và Dirichlet-multinomial** cho file và errno, đo lại tỉ lệ 83 %/100 %.
5. **Trie Pitman-Yor theo process** cho CVE-2019-5418 và CVE-2018-3760; so sánh với PathEvilness và hashed bins.
6. **KN/HPY và token hợp nhất** cho language model; so sánh recall ở 0,5 %, không so sánh cross-entropy.
7. **Lineage process** cho CVE-2020-13942 và PHP_CWE-434.
8. **Corruption thưa cho ExtraTrees** chỉ sau các bước trên, và chỉ nếu vẫn cần fusion với tree.
9. **Teacher LSTM** chỉ để ước lượng trần, trên số ít kịch bản, tuân thủ trần RAM của `.234`.

Chỉ số dừng: nếu một bước không tăng recall ở các kịch bản yếu tại 0,5 % false alarm trên development, không đưa vào cấu hình đăng ký.

### Gaps
- Chi phí chạy live (bộ nhớ trie theo process, độ trễ HPY) chưa được ước lượng. Cần đo trước khi xem các bước 5 và 6 là khả thi trong mục tiêu kernel→alert ≤ 3 s.
