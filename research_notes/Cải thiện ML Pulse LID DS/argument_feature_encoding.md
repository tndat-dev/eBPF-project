# Mã hoá argument, return value, I/O size và sequence dài của syscall làm feature cho mô hình ML phát hiện xâm nhập host

Ghi chú nghiên cứu (01/11/2026). Quy ước: "Cited Findings" là sự kiện có nguồn (đọc từ full text nếu không ghi khác); "Inferences" là suy luận/đề xuất của người viết cho Pulse, không phải kết quả đo. Mô tả Pulse (249 feature, ExtraTrees + conformal p-value, các miss Heartbleed / ZipSlip / CVE-2019-5418 / CVE-2017-7529 / Juice-Shop SQLi, và các novelty check viết tay) lấy từ đề bài, không kiểm lại ở đây. Mã nguồn LID-DS đọc từ nhánh `master` của GitHub ngày 01/11/2026.

## 1. Các mô hình argument kinh điển (Kruegel/Mutz/Valeur/Vigna; Tandon & Chan LERAD; Maggi/Matteucci/Zanero; Sekar FSA-DF): feature gì, kết quả gì, bắt được attack nào

### Takeaway
Các mô hình kinh điển đều học **phân phối của từng argument theo từng syscall** (độ dài chuỗi, phân phối ký tự, cấu trúc theo lớp ký tự, tập giá trị liệt kê, cụm path) và đều vượt các mô hình chỉ dùng sequence trên dữ liệu DARPA/MIT LL 1999 và vài exploit thật. Tuy vậy, phần lớn các model con (token finder, A-LERAD, tree path model) **về bản chất là novelty rule "giá trị chưa thấy khi train"**, chỉ được làm mềm bằng xác suất (Chebyshev, χ², SOM, điểm LERAD theo n/r). Return value/errno vừa bắt được attack vừa là nguồn false alarm hàng đầu.

### Cited Findings
**Kruegel, Mutz, Valeur, Vigna (ESORICS 2003) và bản mở rộng Mutz, Valeur, Kruegel, Vigna (ACM TISSEC 9(1):61–93, 2006)**
- Bài ESORICS 2003 "On the Detection of Anomalous System Call Arguments" — [iSecLab listing](https://iseclab.org/publications/kruegel2003on_the/); bản PDF ESORICS bị lỗi font khi trích văn bản nên nội dung dưới đây lấy từ bản TISSEC 2006 mở rộng — [TISSEC 2006 PDF](https://sites.cs.ucsb.edu/~chris/research/doc/tissec06_syscall.pdf); [bib TISSEC 9(1):61–93](https://ftp.math.utah.edu/pub/tex/bib/idx/tissec/9/1/61-93.html).
- **String Length**: học mean µ và variance σ² của độ dài chuỗi argument; khi detect, chỉ chuỗi dài hơn µ bị phạt, p(l) = σ²/(l−µ)² (bất đẳng thức Chebyshev), chuỗi ≤ µ có p = 1; tác giả nói padding không giúp attacker vì tăng độ dài chỉ làm giảm p, và Chebyshev cho "giảm dần xác suất thay vì yes/no" — [Mutz 2006 §4.1](https://sites.cs.ucsb.edu/~chris/research/doc/tissec06_syscall.pdf).
- **String Character Distribution**: lưu phân phối tần suất tương đối của 256 ký tự cho mỗi chuỗi, sắp giảm dần; "idealized character distribution" (ICD) = trung bình các phân phối đã sắp lúc train; detect bằng một biến thể kiểm định Pearson χ² giữa ICD và mẫu — [Mutz 2006 §4.2](https://sites.cs.ucsb.edu/~chris/research/doc/tissec06_syscall.pdf).
- **Structural Inference**: chuỗi được chuyển thành dãy lớp ký tự (digit, uppercase, lowercase; ký tự khác là lớp riêng), gộp lớp lặp liền kề; ví dụ "/etc/passwd" → "slash - lowercase - slash - lowercase"; sau đó suy ra NFA/grammar xác suất (gộp trạng thái kiểu Bayesian model merging) — [Mutz 2006 §4.3, §6](https://sites.cs.ucsb.edu/~chris/research/doc/tissec06_syscall.pdf).
- **Token Finder**: kiểm định (Kolmogorov–Smirnov, theo Lee et al. 2002) xem số giá trị khác nhau có tăng tỉ lệ với số lần gọi (random identifier) hay bão hoà (enumeration); nếu là enumeration thì lưu tập giá trị, giá trị mới trả 0, ngược lại luôn trả 1; dùng chủ yếu cho flags và uid (ví dụ `setuid` với uid root bất thường, `exit` code bất thường) — [Mutz 2006 §4.4, §6](https://sites.cs.ucsb.edu/~chris/research/doc/tissec06_syscall.pdf).
- Kết hợp các model bằng **Bayesian network** theo từng syscall (ví dụ `open`, `execve`: 3 model chuỗi gắn vào argument chuỗi đầu, token finder gắn vào argument số); ngưỡng: root node > 50 % — [Mutz 2006 §5–7](https://sites.cs.ucsb.edu/~chris/research/doc/tissec06_syscall.pdf).
- **Kết quả đo** (MIT Lincoln Lab 1999, train tuần 1 và 3, test tuần 4–5): 25/25 attack buffer-overflow vào `eject` (3), `fdformat` (6), `ffbconfig` (2), `ps` (14) được phát hiện; false alarm 0 trên 4 chương trình đó, 14 trên `ftpd`, 8 trên `sendmail`, 17 trên `telnetd` (tính theo số trace) — [Mutz 2006 Table II](https://sites.cs.ucsb.edu/~chris/research/doc/tissec06_syscall.pdf). So với 4 baseline chỉ dùng sequence (Forrest n-gram, bag of system calls của Kang et al. 2005, k-NN và cluster của Portnoy et al. 2001), tác giả viết hệ của họ "là hệ duy nhất phát hiện mọi attack (không false negative) và có ít false positive nhất trên phần lớn trace" — [Mutz 2006 §7.1, Table III](https://sites.cs.ucsb.edu/~chris/research/doc/tissec06_syscall.pdf) (bảng số chi tiết của Table III chưa trích, xem Gaps).

**Tandon & Chan: LERAD với argument (FLAIRS 2005, IJAIT 15(6):875–892, 2006; luận án Tandon 2008)**
- Ý tưởng: bổ sung "return value, error status và các argument khác" vào biểu diễn syscall, chống mimicry attack chèn syscall giả có argument không hợp lệ — [Tandon & Chan, IJAIT 2006 PDF](https://trevcan.duckdns.org/files/trevor/papers/emintham-Papers/Tandon%2CChan-%20On%20the%20Learning%20of%20System%20Call%20Attributes%20for%20Host-Based%20Anomaly%20Detection.pdf); [DBLP](https://dblp1.uni-trier.de/pid/72/4351.html).
- Các biến thể: S-LERAD (tuple 6 syscall liên tiếp), **A-LERAD** (syscall + return value + error status + argument), M-LERAD (sequence + argument của syscall hiện tại), M*-LERAD (sequence + argument của cả 6 syscall). Rule dạng `(s0 = close) ⇒ a1 ∈ {0x2,…,0x6}` với điểm dựa trên n/r (số mẫu/số giá trị khác nhau) và thời gian từ lần thấy giá trị mới gần nhất; argument vắng mặt được điền NULL để tuple có độ dài cố định — [Tandon 2008, FIT TR-CS-2008-01 §4.2](https://cs.fit.edu/media/TechnicalReports/cs-2008-01.pdf).
- **Kết quả đo (DARPA BSM)**, diện tích dưới ROC tới 1 % false alarm (×10⁻⁴): t-stide 46,79; S-LERAD 39,12; **A-LERAD 60,25**; **M-LERAD 60,46**; M*-LERAD 54,51. Tác giả kết luận argument hữu ích hơn sequence, và sequence gần như "dư thừa" khi đã có argument (A-LERAD ≈ M-LERAD); M*-LERAD tệ nhất vì một argument bất thường kéo theo alarm ở 6 tuple — [Tandon 2008 Table 4.1, §4.3.3](https://cs.fit.edu/media/TechnicalReports/cs-2008-01.pdf).
- **Attack bắt được nhờ return value/errno** (Table 4.4): `guesstelnet` — return value của `ioctl` chưa từng thấy; `guessftp` — open file thất bại; `ftpwrite` — fd không hợp lệ, return value `mmap` không hợp lệ; `ps` — gid bất thường, "inappropriate ioctl for device" (ENOTTY). Tác giả lưu ý anomaly thường **không phản ánh bản chất attack** mà là hành vi sau khi xâm nhập — [Tandon 2008 §4.3.5, Table 4.4](https://cs.fit.edu/media/TechnicalReports/cs-2008-01.pdf).
- **False alarm do return value/errno** (Table 4.5): các attribute gây false alarm hàng đầu gồm `ioctl` argument, `ioctl` return value, `setegid` mask (cũng bắt được attack), và `open` return value, `open` error status, `fcntl` error status, `setpgrp` return value (**không** bắt được attack nào) — [Tandon 2008 Table 4.5](https://cs.fit.edu/media/TechnicalReports/cs-2008-01.pdf).

**Maggi, Matteucci, Zanero (IEEE TDSC 7(4), 2010; listing ghi 2008) và Frossi, Maggi, Rizzo, Zanero (2009)**
- TDSC: IDS không giám sát dựa trên argument và sequence; model anomaly cho từng tham số, **clustering** các lần gọi cùng syscall theo argument để tạo quan hệ giữa các argument, rồi **Markov model** trên các cluster để nắm tương quan thời gian; "không cần tri thức trước" — [abstract, UCSB SecLab](https://seclab.cs.ucsb.edu/publications/maggi2008detecting_intrusions/); bản post-print mở ở [PoliMi repository](https://re.public.polimi.it/handle/11311/578281) (không tải được full text, xem Gaps).
- Frossi et al. 2009 mô tả S²A²DE (hệ của TDSC): mỗi syscall có type, argument (vd. path của `open`), return value và timestamp, nhưng **return value và timestamp tuyệt đối không được dùng**; clustering phân cấp single-linkage theo từng loại syscall vì "`open` được dùng theo những cách rất khác nhau"; mỗi cluster là một trạng thái Markov — [Frossi et al. 2009 PDF §2.2](https://seclab.cs.ucsb.edu/files/publications/Frossi2009Selecting_and.pdf).
- Cải tiến của Frossi 2009: độ dài argument dùng khoảng Gaussian thay vì [min, max] (model gốc cho xác suất 1 trong khoảng, 0 ngoài khoảng); thêm **edge frequency model** để bắt DoS; dùng **Symbol SOM** để đo độ tương tự giữa các path thay cho cây path xác suất — [Frossi 2009 §3](https://seclab.cs.ucsb.edu/files/publications/Frossi2009Selecting_and.pdf).
- Kết quả định tính có liên quan trực tiếp tới "đọc file tuỳ ý": với một attack, FSA-DF báo vì "chưa từng thấy /etc/passwd hay /etc/shadow khi train", còn Hybrid IDS báo vì các path này "rơi vào vùng SOM khác so với lúc train"; với path tạm (`/tmp/log3`) Symbol SOM nhận ra độ tương tự và **không** báo nhầm, trong khi FSA-DF báo nhầm; trên `proftpd`, FSA-DF gắn cờ hơn 1000 syscall lành tính vì path file tạm không có trong train — [Frossi 2009 §4.2](https://seclab.cs.ucsb.edu/files/publications/Frossi2009Selecting_and.pdf).
- FSA-DF (dataflow anomaly detection của nhóm Sekar) được Frossi dùng làm baseline; vi phạm của nó được mô tả là vi phạm "unary relation" (giá trị argument) và "binary relation" (quan hệ giữa argument các syscall) — [Frossi 2009 §4.2](https://seclab.cs.ucsb.edu/files/publications/Frossi2009Selecting_and.pdf).

### Inferences
- Model con nào là novelty rule: Token Finder (tập giá trị đóng), A-LERAD (`a ∈ {tập đã thấy}`), tree path model, FSA-DF unary relation đều tương đương "giá trị mới ⇒ alarm". Chỉ String Length (Chebyshev), Character Distribution (χ²) và Symbol SOM (độ tương tự) cho **điểm liên tục theo khoảng cách** — đây là phần "học" thật sự và là phần nên mượn cho Pulse.
- Bài học false alarm của Tandon (open/fcntl errno gây alarm mà không bắt attack) gợi ý errno nên vào model dưới dạng **tỉ lệ/đếm theo lớp trong cửa sổ** chứ không phải "errno mới ⇒ alarm"; model tần suất của Pulse đã có cơ chế này cho syscall count, có thể mở rộng cho errno.
- Kết quả "A-LERAD ≈ M-LERAD" (sequence dư thừa khi có argument) ủng hộ hướng thêm argument feature hơn là kéo dài n-gram.

### Gaps
- Không trích được bảng FN/FP chi tiết của Mutz 2006 Table III và bảng FPR/FNR (Table 2) của Frossi 2009; chỉ có phát biểu định tính.
- Không tải được full text Maggi TDSC 2010 (repository PoliMi trả HTML); không có số đo của bài này trong ghi chú.
- Không tìm hiểu riêng Sekar et al. (FSA 2001, dataflow 2006) ngoài mô tả gián tiếp trong Frossi 2009.
- Tất cả kết quả trên là trên DARPA/MIT LL 1999 BSM hoặc vài chương trình setuid; không có nguồn nào đánh giá các model này trên LID-DS hay container.

## 2. Biểu diễn tần suất/bag có argument: bag of system calls, syscall+argument token, path tokenization, đếm lớp errno, histogram return value, histogram log2 I/O size, time delta — cái nào có lợi ích đo được

### Takeaway
Biểu diễn bag/tần suất được đo kỹ **chỉ với tên syscall** (BoSC: 100 % TPR, 0,58 % FPR trên một container MySQL bị sqlmap). Với argument, bằng chứng lợi ích đo được chủ yếu đến từ (a) Tandon (A-LERAD > sequence), (b) Fournier et al. 2021 (return value rút gọn thành success/failure + process name, tăng tới 11,3 % trên language model), (c) một bài 2024 trên LID-DS (chỉ có abstract). **Không tìm thấy** nghiên cứu nào đo riêng histogram log2 I/O size hay đếm lớp errno trong cửa sổ cho HIDS.

### Cited Findings
- **Bag of System Calls (BoSC) cho container** (Abed, Clancy, Levy; IEEE Globecom Workshops 2015): trace lấy bằng `strace` **sau khi cắt bỏ argument và return value**; cửa sổ trượt kích thước 10 trong mỗi epoch, đếm số lần mỗi syscall trong cửa sổ → vector; so sánh với cơ sở dữ liệu bag bình thường; alarm khi số mismatch trong epoch vượt Td. Với Td = 0,1S: TPR 100 %, FPR 0,58 % (MySQL container, tấn công sqlmap) — [Abed et al. arXiv 1611.03053](https://arxiv.org/pdf/1611.03053).
- Mutz 2006 mô tả bag of system calls (Kang et al. 2005) là bỏ thứ tự trong n syscall gần nhất, "ít false positive hơn nhưng phải trả bằng nhiều attack bị bỏ sót hơn" — [Mutz 2006 §7.1](https://sites.cs.ucsb.edu/~chris/research/doc/tissec06_syscall.pdf).
- **Return value rút gọn**: Fournier et al. rút return value thành hai giá trị "success" (≥ 0) hoặc "failure" (< 0) và học embedding cho nó cùng tên syscall và entry/exit — [Fournier et al., MSR 2021 §IV.D](https://arxiv.org/pdf/2103.06915).
- **Return value giữ biên độ**: LID-DS `ReturnValue` chuẩn hoá return value theo **max của từng syscall lúc train** (value / max), trả −1 nếu syscall chưa từng có return value khi train hoặc return value không phải số nguyên — [LID-DS return_value.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/features/impl/return_value.py). Với `read`/`write`, return value chính là số byte, nên feature này thực chất là "I/O size chuẩn hoá theo max lúc train".
- **Time delta**: LID-DS `TimeDelta` = khoảng thời gian tới syscall trước đó **cùng thread** (nếu thread_aware), chia cho max delta lúc train — [LID-DS time_delta.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/features/impl/time_delta.py). Fournier et al. đo được timestamp "có ảnh hưởng không đáng kể" tới LSTM; Transformer có lợi từ timestamp nhưng ít hơn từ position — [Fournier et al. 2021 §VI](https://arxiv.org/pdf/2103.06915).
- **Tandon 2008**: A-LERAD (syscall + return value + error status + argument) có AUC tới 1 % FA là 60,25 ×10⁻⁴, so với 39,12 cho S-LERAD (chỉ sequence) — [Tandon 2008 Table 4.1](https://cs.fit.edu/media/TechnicalReports/cs-2008-01.pdf).
- **Thông tin syscall đầy đủ trên LID-DS** (Peng Guo, Proc. 2024 International Conference on Digital Society and Artificial Intelligence): dùng argument, return value, process name, thread ID với autoencoder; báo độ chính xác trung bình 96,8 % trên 13 scenario LID-DS và nói thông tin đầy đủ cải thiện phát hiện — [ACM DL 10.1145/3677892.3677893](https://dl.acm.org/doi/10.1145/3677892.3677893) (**chỉ qua tóm tắt tìm kiếm**, full text bị 403; không biết cách mã hoá, phiên bản LID-DS, hay ablation).

### Inferences
- Với Pulse (cửa sổ 0,5 s, ExtraTrees trên vector tần suất), cách mở rộng tự nhiên nhất là **thêm các block histogram cùng kiểu với block count hiện có**, để model tự học phân phối thay vì so khớp novelty:
  - *errno histogram*: đếm theo (nhóm syscall × lớp errno), ví dụ ENOENT, EACCES/EPERM, EBADF, EINVAL, EAGAIN, EFAULT, khác; cộng tỉ lệ fail/total theo nhóm (file, net, mem). Đây là bản "tần suất" của phát hiện "error status" của Tandon, tránh kiểu alarm "errno mới".
  - *I/O size log2 histogram*: với `read/pread/readv/recv*`, `write/pwrite/writev/send*`, `sendfile`, đếm theo bucket ⌊log2(ret)⌋ (ví dụ 0–20+), cộng max bucket và tổng byte log trong cửa sổ. Heartbleed (đọc/ghi lớn rò bộ nhớ) và CVE-2017-7529 (range/sendfile bất thường) sẽ hiện thành khối lượng ở bucket cao chưa từng có khối lượng lúc train.
  - *path histogram*: đếm hashed theo prefix depth-1 và depth-2 (ví dụ `/etc`, `/etc/passwd` bị cắt ở depth 2), cộng độ sâu path, độ dài path, số path có `..` hoặc nằm ngoài thư mục làm việc.
- Đây là suy luận; không nguồn nào ở trên đo đúng các block này. Việc ExtraTrees trên dữ liệu normal có "học" được bucket cao là bất thường hay không phụ thuộc vào cách tính nonconformity score (xem mục 6).

### Gaps
- Không tìm thấy bài HIDS nào đo lợi ích riêng của histogram log2 I/O size, đếm lớp errno theo cửa sổ, hay hashed path prefix bag.
- Bài Guo 2024 không đọc được full text; con số 96,8 % chưa kiểm được và không rõ có so sánh với/không với return value hay không.

## 3. Feature trong thư viện LID-DS: ReturnValue, TimeDelta, Path, ProcessName, file descriptor, ThreadChangeFlag, W2V; có kết quả công bố so sánh có/không các feature này không

### Takeaway
Thư viện LID-DS có sẵn các building block argument (`ReturnValue`, `TimeDelta`, `PathEvilness`, `PathLength`, `UnknownFlags`, `Flags`, `DataBuffer`, `FileDescriptor`, `ThreadChangeFlag`, `W2VEmbedding`), và pipeline mẫu ghép W2V(syscall) + return value thành n-gram cho autoencoder/LSTM. Nhưng **không tìm thấy kết quả công bố nào đo LID-DS 2021 có so với không có return value/time delta**; kết quả ablation công bố duy nhất là về thông tin thread (EISA 2021). Script LSTM mẫu mặc định `USE_RETURN_VALUE = False`.

### Cited Findings
- Danh sách 53 file trong `algorithms/features/impl` gồm `return_value.py`, `time_delta.py`, `path_evilness.py`, `path_length.py`, `filedescriptor.py`, `flags.py`, `unknown_flags.py`, `data_buffer.py`, `process_name.py`, `thread_change_flag.py`, `w2v_embedding.py`, `ngram.py`, `frequency_vector.py`, `entropy.py`, `positional_encoding.py`… — [LID-DS features/impl](https://github.com/LID-DS/LID-DS/tree/master/algorithms/features/impl).
- `ReturnValue`: train lưu max return value theo từng syscall name; detect trả value/max, −1 nếu syscall chưa có return value lúc train hoặc giá trị không nguyên — [return_value.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/features/impl/return_value.py).
- `PathEvilness`: lúc train dựng **cây thư mục** từ mọi path lấy từ argument `fd`, `in_fd`, `out_fd` có tag `<f>`; lúc detect trả 0 nếu path đã biết hoặc không có path, ngược lại trả **1/(depth của node cha + 1)** tại thành phần path đầu tiên không có trong cây (0 < giá trị ≤ 1; lệch càng gần gốc điểm càng cao) — [path_evilness.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/features/impl/path_evilness.py).
- `PathLength`: độ dài chuỗi fd-path, min-max scale theo train — [path_length.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/features/impl/path_length.py).
- `UnknownFlags`: trả 1 nếu giá trị `flags` chưa thấy lúc train cho syscall đó (hoặc syscall chưa thấy), 0 nếu đã thấy — [unknown_flags.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/features/impl/unknown_flags.py).
- `DataBuffer`: trả buffer `data` (base64-decode với LID-DS 2021) — [data_buffer.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/features/impl/data_buffer.py).
- `ThreadChangeFlag`: 1 nếu n-gram hoàn chỉnh hiện tại có thread id khác n-gram trước — [thread_change_flag.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/features/impl/thread_change_flag.py).
- `W2VEmbedding`: huấn luyện gensim Word2Vec trên các "câu" là n-gram (thread-aware) của một building block đầu vào (mặc định syscall ID), có tuỳ chọn chỉ giữ câu khác nhau (`distinct`); từ chưa thấy nhận vector hằng `unknown_input_value` — [w2v_embedding.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/features/impl/w2v_embedding.py).
- Pipeline LSTM mẫu: `NGRAM_LENGTH = 3`, `EMBEDDING_SIZE = 4`, `USE_RETURN_VALUE = False`, `USE_TIME_DELTA = False`; nếu bật, mỗi phần tử n-gram = W2V(4) + return value + time delta, cộng ThreadChangeFlag — [ids_lstm_main.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/ids_lstm_main.py).
- Extended abstract LID-DS 2021 (CRITIS 2022) minh hoạ building block: W2V của syscall ghép với return value (`read(...) = 64` → (3,1,64)), n-gram n = 3, đưa vào autoencoder; baseline được đánh giá thực tế là biến thể STIDE (n = 7, w = 100) — [CRITIS 2022 extended abstract](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf).
- Thông tin thread: Grimmer, Kaelble, Rahm (EISA 2021, Springer 2022, tr. 159–177) mở rộng 7 thuật toán với/không có thread information; dùng thread information "tăng detection rate và giảm false alarm trong đa số trường hợp" — [Leipzig DBS listing](https://old.dbs.uni-leipzig.de/en/publication/title/improving_host_based_intrusion_detection_using_thread_information) (**qua tóm tắt tìm kiếm**; PDF trả HTML nên chưa đọc bảng số).
- Bài LID-DS 2019 (BSI 2019) viết: "Arguments, timestamps and return values of system calls are promising indicators for HIDS. An example for a vulnerability detectable by arguments of system calls is the 'Zip Slip Vulnerability'. It leads to overwritten files…" — [Grimmer et al., BSI 2019 PDF](https://dbs.uni-leipzig.de/file/BSI-LID-DS.pdf).

### Inferences
- `PathEvilness` và `UnknownFlags` là novelty rule đóng gói thành feature (cây/tập giá trị lúc train). `PathEvilness` vẫn đáng dùng làm **feature liên tục** cho model (độ sâu lệch khỏi cây), khác với rule nhị phân "prefix mới" của Pulse: model có thể học rằng lệch ở depth sâu (file mới trong thư mục quen) là bình thường, còn lệch gần gốc (`/etc/...` từ app Rails) thì hiếm.
- `ReturnValue` chia cho max lúc train cho giá trị > 1 khi I/O lớn hơn mọi lần train (Heartbleed) và giá trị âm khi lỗi; về thông tin nó gần với "I/O size bucket trên max" mà Pulse đang viết tay, nhưng ở dạng liên tục, theo từng syscall.
- Vì LID-DS chưa công bố ablation return value, một ablation "có/không có block argument" trên LID-DS 2021 của Pulse sẽ là đóng góp mới (đây là suy luận từ việc không tìm thấy).

### Gaps
- Không tìm thấy kết quả số công bố cho LSTM/autoencoder LID-DS có so với không có `ReturnValue`/`TimeDelta`/`PathEvilness`.
- Chưa đọc được bảng số của bài thread information (EISA 2021).

## 4. Embedding: word2vec/doc2vec/GloVe trên syscall có argument, tokenization argument cho Transformer — kết quả

### Takeaway
Embedding trên syscall **không có argument** (W2V/GloVe) đã được đánh giá trên LID-DS 2021 nhưng theo kiểu supervised và không có argument. Bằng chứng mạnh nhất cho embedding argument là Fournier et al. 2021: học embedding cho tên syscall, entry/exit, return value (success/failure), process name, và mã hoá sin/cos cho pid/tid/timestamp; tăng tới 11,3 % cho LSTM và Transformer trên language modelling; argument "call-related" có ích hơn "process-related". Không tìm thấy công trình nào (với tên "Syscall2Vec/sys2vec") nhúng path hay buffer cho HIDS và đo trên LID-DS.

### Cited Findings
- Fournier, Aloise, Azhari, Tetreault, "On Improving Deep Learning Trace Analysis with System Call Arguments", MSR 2021: chia argument thành call-related (return value, fd, loại futex, số byte ghi), process-related (process name, tid, pid), time-related (timestamp); phạm vi giới hạn ở các argument chung cho mọi syscall: `ret`, `entry`, `procname`, `tid`, `pid`, `timestamp` — [arXiv 2103.06915 §III](https://arxiv.org/pdf/2103.06915).
- Nguyên tắc mã hoá: argument "có nghĩa tự thân" (procname, ret, entry) → **learned embedding**; argument chỉ có nghĩa trong ngữ cảnh trace (pid, tid, timestamp) → **encoding sin/cos kiểu Vaswani** (hàm không đơn ánh nên có thể va chạm; chia x cho một hằng để điều khiển chu kỳ) — [Fournier §IV.A–B](https://arxiv.org/pdf/2103.06915).
- Kết hợp: embedding call-related (sysname + entry + ret) được **cộng**, các nhóm được **nối** (concat) — [Fournier §IV.C–D](https://arxiv.org/pdf/2103.06915).
- Kết quả: trên mọi thí nghiệm, model dùng mọi argument có cross-entropy thấp nhất và accuracy cao nhất; model "compensated" không argument (embedding sysname tăng từ 32 lên 64 chiều) bằng hoặc hơn bản nhỏ nhưng **luôn thua** bản có argument, nên lợi ích không chỉ do model to hơn; masked LM có lợi từ call-related hơn process-related; tăng tới 11,3 %; overhead tính toán không đáng kể — [Fournier §VI](https://arxiv.org/pdf/2103.06915); [abstract](https://arxiv.org/abs/2103.06915). Lưu ý: dữ liệu là web request tự sinh và trace pre-production của Ciena, nhiệm vụ là language modelling, **không** phải phát hiện attack.
- Mvula, Branco, Jourdan, Viktor (Discover Data 2023): W2V và GloVe trên chuỗi tên syscall (không argument) cho ADFA-LD, NGIDS-DS, WWW2019, LID-DS 2021, phân loại **supervised** bằng Extremely Randomized Trees; W2V tạo nhiều mẫu trùng hơn GloVe (rò rỉ train/test); nối W2V + GloVe cho balanced accuracy tốt nhất; trên LID-DS 2021 kết quả "tương đối ổn định" khi bỏ mẫu trùng — [PMC10077957](https://pmc.ncbi.nlm.nih.gov/articles/PMC10077957/).
- Tổng quan NLP cho HIDS (arXiv 2201.08066) liệt kê W2V, GloVe, FastText, GRSE dùng để biểu diễn syscall, và ghi nhận ADFA-LD thiếu parameter/return value, NGIDS-DS thiếu parameter — [arXiv 2201.08066](https://arxiv.org/pdf/2201.08066).

### Inferences
- Với Pulse (ExtraTrees, ngân sách < 2 s), Transformer/LSTM trên argument là không cần thiết; điều mượn được từ Fournier là **quy tắc chọn biểu diễn**: rút return value thành lớp (success/failure, hoặc lớp errno), và chỉ embed/hash các giá trị có nghĩa tự thân (tên process, path đã chuẩn hoá) chứ không phải pid/fd số.
- W2V trên "syscall+argument token" (ví dụ `openat:/etc`) có thể thay hashed bin, nhưng sẽ gặp vấn đề từ chưa thấy (LID-DS gán vector hằng cho từ lạ), thực chất lại là một novelty flag.

### Gaps
- Không tìm thấy bài nào tên "Syscall2Vec"/"sys2vec" hay "bag of system calls with semantic embeddings" có kết quả đo; không tìm thấy công trình tokenize path/buffer cho Transformer HIDS và đánh giá trên LID-DS.
- Fournier không tách riêng ảnh hưởng của return value so với entry; con số 11,3 % là cho language modelling, không cho phát hiện attack.

## 5. Feature hashing cho argument nhiều giá trị (path): ảnh hưởng va chạm, số bin, giữ ổn định giữa workload

### Takeaway
Lý thuyết feature hashing (Weinberger et al. 2009) cho thấy hashing **có dấu** cho ước lượng inner product không chệch và có cận đuôi mũ; va chạm chỉ đáng lo khi số bin nhỏ so với số feature hoạt động. Không tìm thấy nghiên cứu HIDS nào đo ảnh hưởng va chạm khi hash path syscall. Giải pháp ổn định trong văn liệu argument là **chuẩn hoá trước khi hash** (lớp ký tự của Mutz, cụm/SOM của Maggi/Frossi), không phải tăng số bin.

### Cited Findings
- Weinberger, Dasgupta, Attenberg, Langford, Smola (ICML 2009): đưa ra cận đuôi mũ cho feature hashing; hash kernel với hàm dấu ξ là **không chệch** (Lemma 2); bản gốc dùng tổng không dấu, bản có dấu cho ước lượng không chệch — [arXiv 0902.2206](https://arxiv.org/pdf/0902.2206).
- Fournier et al.: mã hoá sin/cos không phải song ánh nên có thể va chạm; số va chạm giảm khi chia giá trị cho một hằng phù hợp, nhưng hằng quá lớn làm các mã quá gần nhau, khó phân biệt — [arXiv 2103.06915 §IV.B](https://arxiv.org/pdf/2103.06915).
- Mutz 2006: chuỗi được rút gọn thành dãy lớp ký tự (ví dụ "/etc/passwd" → "slash-lowercase-slash-lowercase") trước khi suy cấu trúc, vì suy luận hiệu quả hơn khi đầu vào nhỏ và đã có phân lớp dựa trên tri thức miền — [Mutz 2006 §6](https://sites.cs.ucsb.edu/~chris/research/doc/tissec06_syscall.pdf).
- Frossi 2009: cây path xác suất và FSA-DF báo nhầm trên file tạm mới (proftpd: > 1000 syscall), Symbol SOM xử lý được nhờ độ đo tương tự — [Frossi 2009 §4.2](https://seclab.cs.ucsb.edu/files/publications/Frossi2009Selecting_and.pdf).

### Inferences
- Đề xuất cho Pulse (chưa đo): hash **path đã chuẩn hoá** chứ không hash path thô: (1) cắt ở depth 1–2 (`/etc/passwd`, `/usr/lib`, `/app/uploads`); (2) thay thành phần chứa số/hex/UUID/PID bằng token lớp (`/proc/<n>/stat`, `/tmp/<rand>`); (3) chuẩn hoá tương đối với cwd/root của container (cờ "ngoài cây thư mục làm việc", "có `..`"). Sau đó hash có dấu với seed cố định (ví dụ xxhash/FNV với seed hằng) vào 64–256 bin. Hash cố định giữ ý nghĩa bin giống nhau giữa các workload và giữa các lần train; chuẩn hoá ngăn path tạm/pid làm bin dao động.
- Với 64 bin hiện có cho syscall ID và bigram, một block path 64–128 bin là cùng bậc; ước lượng nhanh: nếu một container có vài chục prefix depth-2 khác nhau, xác suất va chạm giữa hai prefix cụ thể ≈ 1/B, nên với B = 128 va chạm giữa `/etc/*` và một prefix ứng dụng là hiếm nhưng có xảy ra; có thể giữ thêm vài feature tường minh (không hash) cho nhóm nhạy cảm như `/etc`, `/proc`, `/root`, `/var/run/secrets` (ý tưởng từ "sensitive groups" trong ablation LID-DS v4 của Pulse theo đề bài/commit log).

### Gaps
- Không tìm thấy nghiên cứu HIDS dùng hashed path bin nào báo số bin hay đo ảnh hưởng va chạm/ổn định giữa workload.

## 6. Mã hoá nào được biết là bắt được exploit thay đổi dữ liệu (path traversal, đọc file tuỳ ý, rò bộ nhớ qua read lớn, bão lỗi)

### Takeaway
Bằng chứng trực tiếp chỉ có cho **đọc file nhạy cảm qua path** (path chưa thấy/vùng SOM khác khi truy cập /etc/passwd, /etc/shadow — Frossi 2009) và **lỗi/return value bất thường** (A-LERAD bắt `guessftp`, `guesstelnet`, `ftpwrite`, `ps`). ZipSlip được nhóm LID-DS nêu là "phát hiện được bằng argument" nhưng không có số đo. Không có nguồn nào đo phát hiện Heartbleed hay range/sendfile overflow bằng I/O size. Cách mã hoá phù hợp với các miss của Pulse vì vậy dựa trên suy luận, có cơ sở từ cơ chế của các model kinh điển.

### Cited Findings
- Đọc file tuỳ ý: Hybrid IDS (Symbol SOM) báo vì path /etc/passwd, /etc/shadow "rơi vào vùng SOM khác so với lúc train"; FSA-DF báo vì chưa từng thấy các file này — [Frossi 2009 §4.2](https://seclab.cs.ucsb.edu/files/publications/Frossi2009Selecting_and.pdf).
- Lỗi/errno: `guessftp` bị bắt bởi "open file thất bại", `guesstelnet` bởi return value `ioctl` mới, `ftpwrite` bởi fd không hợp lệ và return value `mmap` không hợp lệ — [Tandon 2008 Table 4.4](https://cs.fit.edu/media/TechnicalReports/cs-2008-01.pdf); nhưng errno của `open`/`fcntl` cũng là nguồn false alarm không bắt được attack nào — [Tandon 2008 Table 4.5](https://cs.fit.edu/media/TechnicalReports/cs-2008-01.pdf).
- Buffer overflow qua argument chuỗi: String Length + Character Distribution + Structural Inference bắt 25/25 attack overflow trong MIT LL 1999 — [Mutz 2006 Table II](https://sites.cs.ucsb.edu/~chris/research/doc/tissec06_syscall.pdf).
- ZipSlip: nhóm LID-DS nêu là ví dụ lỗ hổng "phát hiện được bằng argument của syscall" (ghi đè file) — [BSI 2019](https://dbs.uni-leipzig.de/file/BSI-LID-DS.pdf) (phát biểu, không có số đo).
- DoS/lặp request: edge frequency model của Frossi bắt DoS (request được tạo đặc biệt gửi 50 lần) trên mt-daapd — [Frossi 2009 §3.2, §4.2](https://seclab.cs.ucsb.edu/files/publications/Frossi2009Selecting_and.pdf).
- SQL injection trong container được BoSC (chỉ tên syscall, không argument) phát hiện với TPR 100 %, FPR 0,58 % — [Abed et al. 2015](https://arxiv.org/pdf/1611.03053); đây là MySQL container chịu sqlmap, khác với Juice-Shop của LID-DS.

### Inferences
Ánh xạ đề xuất (chưa đo) từ miss của Pulse sang block feature mà ExtraTrees có thể học trên dữ liệu normal:

| Miss (LID-DS 2021) | Tín hiệu dữ liệu | Block feature đề xuất | Nguồn cơ chế |
|---|---|---|---|
| CVE-2019-5418 (Rails đọc /etc/passwd) | path mở nằm ngoài cây thư mục quen | hashed path prefix depth 1–2 (chuẩn hoá), `PathEvilness`-style độ sâu lệch, đếm path nhóm nhạy cảm | Frossi 2009 (SOM/path), LID-DS `PathEvilness` |
| ZipSlip (Java ghi ngoài thư mục) | `openat` với O_CREAT/O_WRONLY ở prefix mới, path có `..` | path histogram tách theo mode đọc/ghi (flags), cờ "ngoài cwd", độ dài/độ sâu path (Chebyshev-style) | Mutz 2006 (length, token finder cho flags), BSI 2019 |
| Heartbleed (read/write lớn rò bộ nhớ) | bucket log2 cao của `write/send*` | log2 I/O size histogram theo nhóm syscall, max bucket, tổng byte log; return value chuẩn hoá theo max lúc train | LID-DS `ReturnValue` (value/max), Fournier (ret) |
| CVE-2017-7529 (nginx range, sendfile offset xấu, lỗi) | `sendfile` size bất thường + errno | log2 size cho `sendfile`, errno class × nhóm syscall, tỉ lệ fail/total | Tandon 2008 (error status) |
| Juice-Shop SQLi | thay đổi đọc/ghi file DB, lỗi | errno histogram, I/O size histogram trên fd file DB (nếu path được hash) | suy luận |

- Để model "học" được thay vì cần rule: block histogram phải có **giá trị khác không ở chỗ normal gần như luôn bằng 0**; với ExtraTrees + conformal p-value, một nonconformity score dựa trên mật độ/khoảng cách (ví dụ isolation-depth hoặc khoảng cách k-NN trong không gian lá) sẽ chấm các cửa sổ đó là lạ. Nếu score lại là lỗi dự đoán/phân loại của một model giám sát giả, bin luôn bằng 0 khi train có thể không bao giờ được chọn để chia, nên tín hiệu bị bỏ qua — cần kiểm tra trên Pulse (suy luận).
- Hand-written check "unseen 7-gram" của Pulse tương ứng STIDE (n = 7) — baseline của chính LID-DS 2021 — [CRITIS 2022](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf); tức đây là novelty rule kinh điển, không phải ML. Bản "học" tương ứng là đếm hashed n-gram dài (n = 5–7) theo cửa sổ, nhưng Tandon cho thấy sequence ít thêm thông tin khi đã có argument (A-LERAD ≈ M-LERAD), nên ưu tiên argument block trước.

### Gaps
- Không tìm thấy nguồn nào đo phát hiện Heartbleed, nginx CVE-2017-7529, Rails CVE-2019-5418 hay ZipSlip bằng mô hình ML dùng argument (trên LID-DS hay nơi khác).
- Không tìm thấy so sánh trực tiếp "novelty rule viết tay vs feature argument học được" trên cùng dữ liệu; các so sánh có (Tandon, Mutz, Frossi) là giữa các model argument khác nhau và với baseline chỉ dùng sequence.
