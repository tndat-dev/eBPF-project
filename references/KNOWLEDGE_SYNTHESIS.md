# Tri thức tổng hợp từ tài liệu tham chiếu

Tổng hợp ngày 23/10/2026 từ 70 bài trong [`catalog.json`](catalog.json). File này gom những gì tài liệu đã xác lập, theo từng chủ đề mà luận văn cần, và chỉ ra chỗ đồ án dùng tới. Nó không thay [RESEARCH_IDEAS.md](../RESEARCH_IDEAS.md):
- RESEARCH_IDEAS ghi ý tưởng, khoảng cách G1–G9 và kế hoạch kiểm;
- file này là phần nền: khái niệm, bảo đảm lý thuyết, số liệu các bài tự báo cáo, và câu nào luận văn được phép nói dựa trên nguồn nào.

**Cách đọc từng bài:**
- 60 bản gốc: đọc tóm tắt, đoạn đóng góp, phần kết luận, và các đoạn cụ thể khi cần số liệu (ghi ở chỗ dùng).
- 10 bản dựng lại (đánh dấu *(dựng lại)*): chỉ có tóm tắt công khai và phần diễn giải của người dựng. **Không lấy chi tiết ngoài tóm tắt** từ các bài này; đối chiếu bản gốc trước khi trích trong luận văn.
- Lorden 1971 và Moustakides 1986 là bản quét JSTOR không có lớp chữ; Lorden đọc trực tiếp hai trang đầu.

**Ba loại nhận định, đánh dấu ở đầu câu:**
- **[Đ]** — bài đã chứng minh (định lý, bảo đảm hình thức), kèm giả thiết của nó;
- **[TB]** — số liệu tác giả tự báo cáo trên dữ liệu và cách đo của họ; **không so trực tiếp** với số của Pulse;
- **[ĐA]** — nhận định hoặc suy luận của đồ án. Phải có bằng chứng trong 4 báo cáo trạng thái trước khi đưa vào luận văn.

Tên bài viết dạng *Tác giả năm*; bảng tra sang file PDF ở [cuối file](#bảng-tra-khóa--file). Số mục như "Pulse 5.19", "syscall 5C", "RCA 5.14" là mục trong [SENTINEL_PULSE_STATUS.md](../SENTINEL_PULSE_STATUS.md), [SYSCALL_FEATURE_EXPERIMENT_STATUS.md](../SYSCALL_FEATURE_EXPERIMENT_STATUS.md) và [RCA_RUNTIME_STATUS.md](../RCA_RUNTIME_STATUS.md).

## Bản đồ nhanh

| Chủ đề | Bài chính | Dùng trong đồ án | Chương luận văn |
|---|---|---|---|
| 1. Phát hiện thay đổi tuần tự (CUSUM) | Page 1954 *(dựng lại)*, Lorden 1971, Moustakides 1986, Moustakides 2009, Vovk 2019, Bhattacharyya 2026 | Luật thời gian CUSUM b3/h6 `cap` của ML stable (Pulse 5.11a, 5.19) | Nền tảng; thiết kế |
| 2. P-value conformal, hiệu chỉnh, trôi phân phối | Vovk 2005 *(dựng lại)*, Bates 2021, Tibshirani 2019, Barber 2022, Gibbs 2021, Zaffran 2022, Angelopoulos 2023, Podkopaev 2021, Dasari 2026, Althani 2026, Araz 2026, Barbero 2020, Yang 2021, Rheey 2026 *(dựng lại)* | `tree_p`, `support_p`, joint p; calibration làm mới (Pulse 5.6, 5.17); Mondrian theo lớp launch (5.22) | Nền tảng; thiết kế; thảo luận |
| 3. Gộp p-value, nhiều kiểm định, FDR | Liu 2018 (Cauchy), Chen 2022, Wilson 2019 (HMP), Fisher 2021, Rebjock 2021, Krönert 2023, Zhang 2025 (e-GAI) | joint p kiểu Bonferroni; Cauchy blind (5.11a, không chọn); lý do không dùng FDR online (RESEARCH_IDEAS 6) | Thiết kế; thảo luận |
| 4. HIDS dựa trên syscall, container | Forrest 1996 *(dựng lại)*, Kim 2016, Abed 2016, Castanhel 2020, Lin 2020 *(dựng lại)*, Tien 2019 *(dựng lại)*, El Khairi 2022 (CHIDS), El Khairi 2024 (ReplicaWatcher), Bortolini 2025, Kim 2025, Zhou 2026, Zehra 2025 (FedMon), Ghimire 2025, Ghavamnia 2020a/b, Wagner 2002, Grimmer 2022 (LID-DS) | Bộ feature base29, cửa sổ 0,5 s, tripwire A1, mô hình đe dọa, độ phủ tấn công | Công trình liên quan; đánh giá; giới hạn |
| 5. Mô hình và chi phí suy luận | Geurts 2006, Liu 2008, Mehta 2024, Pedregosa 2011, Nakandala 2020, Guan 2023, Osaki 2024, Zheng 2026 *(dựng lại)*, Fernando 2024, He 2025 *(dựng lại)* | ExtraTrees cho nhánh tree; baseline Isolation Forest (5.15); chấm nhanh khớp từng bit | Thiết kế; cài đặt |
| 6. Provenance, RCA, phân loại cảnh báo | Alahmadi 2022, Hassan 2019 (NoDoze), Oliver 2024 (Carbon Filter), Cheng 2023 (Kairos), Li 2024 (NodLink), Jiang 2025 (ORTHRUS), Ying 2025 (METANOIA), Goyal 2023, Wei 2025 (CORTEX), Begimher 2026 (SIR-Bench), Jajodia 2026 (SIABench), Day 2012 (CONDOR) | RCA từ Tetragon, xếp hạng nghi phạm, phân loại case (Pulse 5.18), tầng triage probe (rule R4) | Thiết kế RCA; đánh giá RCA |
| 7. Công cụ runtime eBPF, overhead | Syairozi 2025, Kim 2025, Ghimire 2025, tài liệu Falco/Tetragon | Overhead probe (Pulse 5.21), so sánh với Falco (rule R2) | Cài đặt; đánh giá |
| 8. Phương pháp đánh giá | Arp 2020, Wilson 1927 *(dựng lại)*, Efron 1993 *(dựng lại)*, Rebjock 2021 | Bảng tự kiểm P1–P10 (RESEARCH_IDEAS 4.3), CI Wilson, bootstrap theo workload | Phương pháp đánh giá |

## 1. Phát hiện thay đổi tuần tự

### 1.1 Bài toán và tiêu chí

- **[Đ] Lorden 1971 định nghĩa bài toán:** X₁, X₂, … độc lập; trước thời điểm m chưa biết, phân bố là F₀; từ m trở đi là F₁ (cả hai đã biết). Một luật dừng N phải:
  - báo nhầm ít: E₀N ≥ γ (độ dài chạy trung bình khi không có thay đổi, ARL₀);
  - phản ứng nhanh trong trường hợp xấu nhất: Ē₁N = sup_m ess sup E_m[(N − m + 1)⁺ | X₁…X_{m−1}].
  
  Ē₁N là cận trên của số quan sát sau thay đổi trước khi báo, **bất kể dữ liệu trước thay đổi ra sao**. Đây là tiêu chí minimax mà mọi kết quả tối ưu về sau dùng.
- **[Đ] CUSUM của Page:** T_n = (T_{n−1} + log f₁(X_n)/f₀(X_n))⁺, báo khi T_n > γ. Page đã chỉ ra (Lorden nhắc lại) nó tương đương lặp lại một SPRT với hai biên log 0 và γ: mỗi khi tổng chạm 0 thì bắt đầu kiểm lại từ đầu. Với chính CUSUM, Ē₁N bằng ARL sau thay đổi E₁N; với luật khác thì không, nên E₁N một mình không đủ làm tiêu chí.
- **[Đ] Tối ưu:** Lorden 1971 chứng minh CUSUM đạt Ē₁N nhỏ nhất **tiệm cận** khi γ → ∞; Moustakides 1986 chứng minh nó **tối ưu chính xác** theo tiêu chí này (tóm tắt: *"Page's stopping time is optimal … in a well defined sense"*). Giả thiết: quan sát độc lập, biết f₀ và f₁, bước tăng là log tỉ số hợp lý.
- **[Đ][TB] Shiryaev–Roberts** tối ưu khi thay đổi xảy ra rất xa trong tương lai. So sánh số bằng phương trình tích phân chính xác (Moustakides 2009, dịch trung bình Gauss): khác biệt giữa hai luật chỉ đáng kể khi thay đổi nhỏ.

### 1.2 Phiên bản không cần biết phân bố: martingale conformal

- **[Đ] Vovk 2019** tổng quan các cách kiểm tính ngẫu nhiên trực tuyến; tất cả dựa trên **martingale conformal** dựng từ p-value conformal. Có bản conformal của CUSUM và Shiryaev–Roberts, với cận cho xác suất hoặc tần suất báo nhầm, giả thiết dữ liệu hoán đổi được khi chưa có thay đổi.
- **[Đ] Bhattacharyya 2026:** các cách dựng martingale conformal phổ biến **không tối ưu**:
  - độ trễ Ω(T) khi kiểm soát xác suất báo nhầm (T là thời điểm thay đổi);
  - Ω(√ARL) khi kiểm soát ARL.
  
  Bản tác giả đề xuất khởi động lại martingale ở mọi thời điểm rồi gộp có trọng số, đạt Θ(log T) và Θ(log ARL), tối ưu minimax. Lý do: lịch sử dài trước thay đổi làm "loãng" bằng chứng; khởi động lại thì mỗi bản chỉ tích bằng chứng cục bộ. Giả thiết: quan sát độc lập.

### 1.3 Áp vào Pulse

- **[ĐA] Luật của ML stable** (Pulse 5.19, chính sách `policy-cusum-b3-h6-cap`): S ← max(0, S + (−ln joint_p) − 3), báo khi S ≥ 6; biến thể `cap` không cho S vượt ngưỡng, nên alarm tắt ở cửa sổ đầu tiên có −ln p < 3.
- **[ĐA] Cái gì chuyển được từ lý thuyết, cái gì không:**
  - Dạng max(0, ·) chính là cơ chế "khởi động lại" của Page: tổng chạm 0 thì bắt đầu lại, nên lịch sử bình thường dài không làm chậm phát hiện. Đây là đúng điều Bhattacharyya 2026 chỉ ra là cần.
  - **Định lý tối ưu không chuyển sang được.** Bước tăng −ln p − 3 không phải log tỉ số hợp lý (không biết f₁); các cửa sổ phụ thuộc nhau qua feature lịch sử; joint p là Bonferroni bảo thủ. Vì vậy Pulse **không có bảo đảm ARL₀**; gánh cảnh báo được đo thực nghiệm theo đợt/replica-giờ.
  - Trực giác cho drift 3: nếu p hợp lệ (phân bố đều khi bình thường) thì −ln p ~ Exp(1), trung bình 1, nên bước tăng trung bình −2 và S nhanh về 0. Khi bị tấn công, p rất nhỏ nên −ln p lớn. Đây là lập luận định tính, không phải bảo đảm.
  - Lỗi `keep` (Pulse 5.19 bổ sung 1): S không chặn trên trong một đợt bất thường dài (tới 2.638, ngưỡng 6), mà mỗi cửa sổ bình thường chỉ trừ tối đa 3, nên alarm kéo dài sang trial sau; control 5,7%. Page dừng ở lần vượt ngưỡng đầu tiên (`restart` tương ứng với cách đó). `cap` là biến thể riêng của đồ án, **không có nguồn lý thuyết**; nó được chọn theo luật đăng ký trước vì gánh thấp hơn (control 3,2%, p95 2,05 s, 6,07 đợt/replica-giờ trên luồng liên tục).
- **[ĐA] Hệ quả thiết kế** (RESEARCH_IDEAS 6): với bằng chứng từng cửa sổ cho trước, CUSUM đã là luật dừng tốt nhất theo tiêu chí minimax. Muốn giảm báo nhầm ở cùng độ trễ thì phải **làm bằng chứng tốt hơn**, không phải chỉnh ngưỡng. Lưới CUSUM trên campaign (Pulse 5.13b) khớp với điều này: siết tham số đưa control về 0,6–2% nhưng p95 lên 3–5 s. Đây là lý do các hướng giảm gánh (Pulse 5.22) đều đổi bằng chứng: Mondrian theo lớp launch, chiết khấu theo replica, so với lịch sử container.

**Luận văn được nói:** "CUSUM là luật dừng tối ưu minimax giữa độ trễ và tần suất báo nhầm khi bước tăng là log tỉ số hợp lý của các quan sát độc lập (Lorden 1971; Moustakides 1986)." **Không được nói:** "CUSUM của Pulse tối ưu" hay "Pulse bảo đảm ARL₀".

## 2. P-value conformal, hiệu chỉnh và trôi phân phối

### 2.1 Nền tảng

- **[Đ] Conformal prediction** (Vovk 2005 *(dựng lại)*): từ một điểm bất thường bất kỳ, dựng p-value hợp lệ chỉ với giả thiết dữ liệu **hoán đổi được**, không cần mô hình phân bố. **Mondrian conformal** hiệu chỉnh riêng trong từng nhóm định trước, nên hợp lệ trong từng nhóm chứ không chỉ trung bình. (Lý thuyết Mondrian có trong tài liệu MAPIE, mục công cụ của catalog.)
- **[Đ] P-value conformal cho phát hiện ngoại lai** (Bates 2021):
  - p = (1 + số điểm calibration ≥ điểm mới)/(n + 1); hợp lệ biên (marginal) khi điểm mới và calibration hoán đổi được.
  - **p không bao giờ nhỏ hơn 1/(n + 1)**: muốn đạt ngưỡng α thì cần n ≥ 1/α − 1 điểm calibration sạch.
  - Các p-value của nhiều điểm mới **phụ thuộc dương** (PRDS) vì dùng chung tập calibration. Vì vậy BH vẫn kiểm soát FDR, nhưng **phép gộp Fisher bị hỏng**. Bài đưa thêm cách dựng p-value hợp lệ có điều kiện theo tập calibration (độc lập giữa các điểm), đổi lại kém mạnh hơn.
- **[ĐA] Trong Pulse** (Pulse 5.8f): đúng công thức trên (`detector/support_model.py: pvalues`), calibration là điểm của chính model trên normal không dùng để fit. Alpha gốc 0,05/30 ≈ 0,00167 mỗi cửa sổ (ngân sách thiết kế 5% cho khoảng 15 s); Pulse đòi tối thiểu 1.200 điểm calibration (`ceil(2/alpha) − 1`), phần nhân 2 là vì joint p nhân đôi p nhỏ nhất. Ngân sách 5% là **ngân sách thiết kế dưới giả thiết hoán đổi**; live không giữ được (Pulse 4, 5.6).

### 2.2 Khi giả thiết hoán đổi bị phá

| Bài | Ý chính | Loại |
|---|---|---|
| Tibshirani 2019 | Conformal có trọng số: khi phân bố covariate đổi nhưng biết (hoặc ước lượng được) tỉ số hợp lý giữa test và train, vẫn có khoảng hợp lệ; tính toán đơn giản như conformal thường | [Đ] |
| Barber 2022 (NexCP) | Trọng số cố định w_i ∈ [0, 1] (ví dụ giảm dần theo tuổi dữ liệu). Không cần giả thiết gì: khoảng hụt coverage ≤ Σ w_i·d_TV(Z, Z^i)/(1 + Σ w_i). Dữ liệu hoán đổi được thì bảo đảm như cũ | [Đ] |
| Gibbs 2021 (ACI) | Cập nhật α_{t+1} = α_t + γ(α − err_t); tần suất lỗi dài hạn tiến về α với **mọi** quá trình sinh dữ liệu. Cần biết nhãn ngay sau mỗi bước; chọn γ còn là heuristic | [Đ] |
| Zaffran 2022 | ACI làm khoảng rộng hơn conformal thường khi dữ liệu thực ra hoán đổi được; AgACI gộp nhiều γ bằng tổng hợp chuyên gia để khỏi chọn γ | [Đ][TB] |
| Angelopoulos 2023 | Conformal như điều khiển PID: theo vết phân vị (P), tích phân lỗi (I), dự báo điểm (D). P + I ổn định trong mọi thí nghiệm; D chỉ giúp khi điểm còn xu hướng dự báo được, nếu không thì thêm dao động | [Đ][TB] |
| Podkopaev 2021 | Chỉ báo động khi dịch chuyển **làm hỏng** chỉ số (accuracy, calibration), bỏ qua dịch chuyển vô hại; dùng confidence sequence nên theo dõi liên tục mà không tăng báo nhầm. Cần nhãn (có thể trễ) | [Đ] |
| Dasari 2026 | 3.933 lượt mô phỏng: model **tĩnh** giữa các lần làm mới thì **làm mới định kỳ thắng** làm mới theo lỗi hoặc theo phát hiện drift (ADWIN) khi drift đột ngột hoặc dần dần; chính sách phản ứng chỉ hơn khi drift lặp lại. Độ trễ huấn luyện và ngân sách tương tác như hàng đợi, có thể âm thầm làm mất nửa ngân sách làm mới | [TB] |
| Althani 2026 | Conformal theo lớp (Mondrian) khi mất cân bằng 1:345: conformal thường chỉ phủ 52,94% bất thường, theo lớp phủ 90,59% (α = 0,10). Random Forest suýt vi phạm (87,06% so với 90%) vì điểm rời rạc và tập calibration lớp hiếm chỉ ~21 điểm | [TB] |
| Araz 2026 | Lớp conformal biến điểm bất thường thành p-value; bản có trọng số và Mondrian sửa chỗ vùng calibration không hoán đổi với vùng tín hiệu; thêm bước look-elsewhere để có ý nghĩa toàn cục. Pipeline chuẩn tự tạo ra excess ~46σ chỉ do điểm tương quan với biến cộng hưởng | [TB] |

**Conformal trong bảo mật:**
- **[TB] Barbero 2020 (Transcendent):** nối "conformal evaluation" của Transcend với lý thuyết conformal prediction. Hai bộ đánh giá mới (ICE, CCE) ngang hoặc hơn bản gốc nhưng rẻ hơn nhiều; từ chối mẫu trôi trên dữ liệu malware 5 năm (2014–2019) đã loại các nguồn thiên lệch.
- **[TB] Yang 2021 (CADE):** autoencoder tương phản học khoảng cách để phát hiện **từng mẫu trôi**, kèm giải thích dựa trên khoảng cách (hiệu quả hơn giải thích biên quyết định).
- **[TB] Rheey 2026 *(dựng lại)*:** autoencoder + Mahalanobis + ngưỡng split conformal cho IDS O-RAN; FAR nằm trong ngân sách nếu dữ liệu bình thường hoán đổi được.

### 2.3 Áp vào Pulse

- **[ĐA] Hoán đổi bị phá là cơ chế giải thích calibration "đi theo ngày"** (Pulse 5.6b, 5.7b): làm mới calibration giảm 22,8% đợt cảnh báo/replica-giờ và đưa precision từ 92 lên 96% (Pulse 5.8g). Sự cố vận hành (bản sao CNPG `cnpg-2` hỏng từ 22/10 09:41 UTC, Pulse 5.24) là trường hợp cực đoan: phân bố normal đổi thật, p-value không còn hợp lệ, alarm liên tục.
- **[ĐA] Các chiến lược calibration của Pulse 5.17 ánh xạ thẳng vào tài liệu:** `weighted-24-6-1` là NexCP (Barber 2022); `aci-*` là ACI (Gibbs 2021); `mondrian-6-1` là Mondrian theo (workload, node). Dasari 2026 ủng hộ làm mới định kỳ hơn làm mới theo phát hiện drift khi model tĩnh, đúng trường hợp của Pulse.
- **[ĐA] Mondrian theo lớp launch** (Pulse 5.22): cửa sổ có exec chỉ so với cửa sổ có exec lúc bình thường. Althani 2026 cảnh báo nhóm nhỏ thì coverage dễ vỡ. Điều kiện này đã được kiểm (Pulse 5.22): lớp launch chiếm 21–49% cửa sổ ở 15 workload, và workload có probe exec đủ ≥ 1.200 cửa sổ cho cả hai lớp; 6 workload không có exec chỉ có một lớp.
- **[ĐA] Điểm rời rạc:** p-value dùng "≥" nên điểm trùng nhau làm p bảo thủ, không làm p sai về phía báo nhầm.

**Luận văn được nói:** "p-value conformal hợp lệ biên khi dữ liệu calibration và dữ liệu mới hoán đổi được (Vovk 2005; Bates 2021); khi môi trường đổi, giả thiết này bị phá, và đồ án đo được hệ quả." **Không được nói:** "Pulse bảo đảm tỉ lệ báo nhầm 5%".

## 3. Gộp p-value, nhiều kiểm định và FDR

### 3.1 Gộp các nhánh

- **[Đ] Bonferroni / min-p:** min(1, k·min p_i) hợp lệ với **mọi** cấu trúc phụ thuộc. joint p của Pulse = min(1, 2·min(tree_p, support_p)) là trường hợp k = 2. Chen 2022 nhắc MinP kiểm soát sai lầm loại I trong mọi điều kiện.
- **[Đ] Cauchy combination** (Liu 2018): T = Σ w_i·tan((0,5 − p_i)π). Đuôi phân bố của T xấp xỉ Cauchy dưới phụ thuộc tùy ý (giả thiết: thống kê từng phần có phân bố chuẩn hai chiều), nên p-value tính được chính xác, nhất là khi p rất nhỏ; mạnh với tín hiệu thưa.
- **[Đ][TB] Chen 2022:** Cauchy có thể kém hoặc vô dụng (ví dụ có cả p rất nhỏ lẫn rất lớn); MinP có khi mạnh hơn nhiều. Đề xuất MCM, CMC (gộp hai tầng). Định lý 1: các phép gộp này không cho p nhỏ hơn p nhỏ nhất.
- **[Đ] Harmonic mean p** (Wilson 2019): bền với phụ thuộc dương, gần đúng hợp lệ ở p nhỏ; nằm giữa Bonferroni (quá bảo thủ) và FDR.
- **[ĐA] Vì sao Cauchy không được chọn** (Pulse 5.11a, blind): p95 nhanh hơn (1,46 s) nhưng gánh cảnh báo tăng 16% (7,84 đợt/replica-giờ), không đạt tiêu chí. Với hai p-value cùng trọng số: khi một nhánh rất nhỏ còn nhánh kia không, tan((0,5 − p)π) ≈ 1/(πp) nên p Cauchy ≈ 2·min p, bằng Bonferroni; khi cả hai cùng nhỏ thì p Cauchy về gần min p, nhỏ hơn Bonferroni tới 2 lần. Tức Cauchy chỉ "lời" khi hai nhánh cùng đồng ý, và chỗ lời đó cũng làm cửa sổ normal sát ngưỡng dễ qua hơn. Đây là suy luận, chưa đo tách riêng.

### 3.2 Nhiều kiểm định trực tuyến (FDR)

- **[Đ] Fisher 2021:** LORD, SAFFRON và alpha-investing kiểm soát FDR (không chỉ mFDR) dưới **phụ thuộc dương cục bộ**, kể cả với một số luật dừng thích nghi.
- **[Đ][TB] Rebjock 2021:** luật FDR trực tuyến bị "α-death" khi bất thường cực hiếm (ngân sách cạn dần, ngưỡng co mãi); thêm cơ chế phân rã bộ nhớ để giữ độ mạnh, và chỉnh cho p-value phụ thuộc cục bộ. Tác giả lưu ý các dataset công khai để đánh giá phát hiện bất thường có **mật độ bất thường cao phi thực tế**.
- **[Đ] Krönert 2023:** điều kiện về **số điểm calibration** để p-value thực nghiệm cho phép kiểm soát FDR; kiểm soát mFDR cục bộ trên từng đoạn rồi chuyển thành FDR toàn chuỗi bằng BH sửa đổi. Kết quả mạnh nhất dưới độc lập; một phần dưới PRDS.
- **[Đ] Zhang 2025 (e-GAI):** khung alpha-investing tổng quát dựa trên e-value; e-LORD và e-SAFFRON mạnh hơn e-LOND dưới phụ thuộc phức tạp.
- **[ĐA] Không áp dụng cho Pulse** (RESEARCH_IDEAS 6): khi không có attack, BH trên p conformal chỉ tương đương một ngưỡng chặt hơn; FDR trực tuyến co ngưỡng khi lâu không phát hiện, không hợp với giám sát 24/7. Các bài này vẫn có ích cho phần thảo luận: Krönert khớp với yêu cầu tối thiểu 1.200 điểm calibration; Rebjock khớp với lập luận về tỉ lệ nền (mục 8).

### 3.3 Nhìn toàn cụm: hiệu ứng "nhìn chỗ khác"

- **[ĐA]** Mỗi cửa sổ 0,5 s của mỗi container là một kiểm định: ~80 container × 2 cửa sổ/s là cỡ 576.000 kiểm định mỗi giờ. Đây là dạng look-elsewhere mà Araz 2026 xử lý trong vật lý hạt. Nó giải thích vì sao gánh cảnh báo phải báo **theo replica-giờ** chứ không theo tỉ lệ từng cửa sổ, và vì sao precision 96% trên campaign cân bằng 1:1 có thể thành cỡ 0,01% ở tỉ lệ nền thật (Arp P8, RESEARCH_IDEAS 4.3). Ý nghĩa toàn cụm theo kiểu Araz là hướng mở, chưa làm.

## 4. HIDS dựa trên syscall và container

### 4.1 Dòng phát triển

| Bài | Biểu diễn | Mô hình | Đánh giá và kết quả tự báo cáo |
|---|---|---|---|
| Forrest 1996 *(dựng lại)* | Chuỗi syscall ngắn liên tiếp (cửa sổ trượt) | Tập "self" (STIDE) | Phát hiện một số xâm nhập vào sendmail, lpr (theo tóm tắt) |
| Kim 2016 | Chuỗi syscall | Mô hình ngôn ngữ LSTM + ensemble ngưỡng để giảm báo nhầm | Dataset công khai; tác giả nêu chi phí huấn luyện thấp vì không lưu cơ sở dữ liệu mẫu |
| Abed 2016 | Túi tần suất syscall (BoSC) theo epoch, thu từ kernel host | So khớp với túi normal | MySQL trong container: phát hiện 100% ở ngưỡng 10 lần không khớp mỗi epoch, FPR ~2%; không về 0 vì cùng tải không sinh ra cùng BoSC |
| Tien 2019 *(dựng lại)* | Giám sát container trên Kubernetes | Mạng nơ-ron có giám sát | Accuracy tới 96%; overhead chỉ hơn các phương pháp hiện có 5% (theo tóm tắt) |
| Castanhel 2020 | Cửa sổ syscall trong Docker | Bộ phân loại một lớp | Cửa sổ nhỏ đã cho F1 chấp nhận được, hợp với phát hiện trực tuyến; phụ thuộc bộ phân loại |
| Lin 2020 (CDL) *(dựng lại)* | Tần suất syscall | Phân loại ứng dụng trực tuyến + phát hiện bất thường theo lớp | 33 tấn công thật trên 24 ứng dụng; báo nhầm từ >12% xuống 0,24%; bắt 31 thay vì 20 tấn công trước khi thành công (theo tóm tắt) |
| El Khairi 2022 (CHIDS) | Syscall, tham số, tần suất, đặt trong đồ thị ngữ cảnh | Mô hình đồ thị | 11.700 trace normal + 1.980 attack, 20 kịch bản; vượt các công cụ cùng thời |
| El Khairi 2024 (ReplicaWatcher) | Sự kiện kernel theo replica | So sánh các replica, **không huấn luyện** | Precision 91,08%, recall 98,35%; bền khi normal đổi qua phiên bản (cart 0.6.0 → 0.7.0) |
| Bortolini 2025 | Syscall gom theo mức đe dọa và chức năng; ma trận tần suất bigram | Transformer | F1 0,90 so với 0,92 của bản đầy đủ, nhanh hơn >86% |
| Kim 2025 | Trace syscall từ Tetragon + thông tin flow, n-gram | Nhiều mô hình ML; RNN tốt nhất | Cryptojacking: accuracy 99,75%; overhead cao hơn ở tải nặng bộ nhớ và I/O; eBPF mở rộng tốt hơn perf khi tăng số container |
| Zhou 2026 | Mở file (hook `security_file_open`, dựng lại đường dẫn từ dentry), ngữ nghĩa đường dẫn | Autoencoder có attention | Recall 82,0%, FPR 0,79%, MCC 0,852; hơn Isolation Forest, One-Class SVM, LOF |
| Zehra 2025 (FedMon) | Syscall + mạng qua eBPF trên nhiều cụm K8s | VAE + Isolation Forest, học liên kết | Precision 94%, recall 91%, F1 0,92; giảm 60% băng thông |
| Ghimire 2025 (eBPF-PATROL) | Syscall + ngữ cảnh container, kiểm tham số | Luật người dùng, có chặn | Overhead < 2,5% |

**[ĐA] Bài học khớp với kết quả của Pulse** (chi tiết so sánh ở RESEARCH_IDEAS 3):
- Chỉ đếm tần suất thì yếu với attack tần suất thấp (CDL; `mprotect`/`seccomp` của Pulse; tốc độ attack 6/s làm recall giảm, Pulse 5.15c).
- Tham số syscall và ngữ cảnh process là thứ tách được hành vi (CHIDS, Zhou 2026, sentinel-ebpf): ủng hộ đặc trưng theo tham số (R7a) và triage dùng cây process (C1).
- Baseline cũ đi nhanh trong microservice (ReplicaWatcher), khớp với calibration đi theo ngày (Pulse 5.6b, 5.7b).
- Cửa sổ nhỏ vẫn đủ thông tin (Castanhel 2020), khớp với cửa sổ 0,5 s của Pulse; Pulse thêm phát hiện riêng: thêm syscall làm chậm p95 tới 5 s (syscall, mục 1).
- **Không bài nào trong bảng có đối chứng process mới vô hại**, và hầu như không bài nào báo độ trễ kernel → cảnh báo hay gánh cảnh báo theo giờ. Đây là chỗ đóng góp đánh giá của Pulse (RESEARCH_IDEAS "Đang mạnh ở đâu").

### 4.2 Thu hẹp bề mặt tấn công

- **[TB] Ghavamnia 2020a (Confine):** phân tích tĩnh image Docker sinh hồ sơ seccomp; với 150 image công khai, tắt được ≥ 145/326 syscall ở hơn nửa số container, vô hiệu 51 lỗ hổng kernel đã công bố.
- **[TB] Ghavamnia 2020b (temporal specialization):** server có pha khởi tạo và pha phục vụ với nhu cầu syscall khác nhau; sau khởi tạo tắt được nhiều syscall nguy hiểm, ví dụ `execve`. Trên 6 server: tắt thêm 51% syscall nhạy cảm so với specialization theo thư viện, phá 77% shellcode và 68% payload ROP thử, giảm thiểu 53 CVE kernel (13 cái mà cách cũ không chặn được).
- **[ĐA]** Tripwire A1 (rule R3) là phiên bản **phát hiện** của allowlist syscall: syscall vắng mặt trong hồ sơ workload xuất hiện thì báo. Temporal specialization cho cơ sở để nói exec trong pha phục vụ là đáng ngờ; ngoại lệ hợp lệ lớn nhất trên cụm là probe exec của Kubernetes (Pulse 5.18).

### 4.3 Né tránh (mimicry)

- **[Đ][TB] Wagner 2002:** mô hình hóa IDS và tập chuỗi độc hại bằng automat hữu hạn; kẻ tấn công chèn syscall "không làm gì" (no-op) hoặc thay syscall tương đương (`read` ↔ `mmap`, gộp nhiều `read`) để chuỗi độc hại khớp mô hình normal mà vẫn giữ tác dụng.
  - Thực nghiệm (mục 6 của bài): pH 0.17, chuỗi con độ dài 6, huấn luyện trên wuftpd; exploit `autowux` (format string, rồi `setreuid`, thoát chroot, `execve("/bin/sh")`). pH bắt được exploit gốc.
  - Tìm kiếm trên automat tích cho thấy **không có cách giấu chuỗi gốc**, vì cơ sở dữ liệu normal không có đường nào tới `dup2()`, `mkdir()` hay `execve()`. Muốn né, kẻ tấn công phải bỏ hẳn các syscall đó: dùng thư mục có sẵn thay cho `mkdir`, không mở shell mà gắn hành động vào shellcode (ví dụ thêm tài khoản root vào file mật khẩu) chỉ bằng syscall có trong hồ sơ.
- **[TB] Goyal 2023:** với 5 IDS dựa trên đồ thị provenance, chiến thuật mimicry né được **100%** mà không đổi hành vi tấn công.
- **[ĐA] Mô hình đe dọa của Pulse** (RESEARCH_IDEAS 4.2): điểm tần suất có thể bị "pha loãng"; syscall **vắng mặt** trong hồ sơ (`ptrace`, `setns`…) thì không pha loãng được, nên tripwire bền hơn. Thực nghiệm của Wagner 2002 ủng hộ đúng điểm này: syscall không có trong hồ sơ normal thì không giấu được. Nhưng nó cũng chỉ ra giới hạn: kẻ tấn công vẫn gây hại được nếu chọn payload chỉ dùng syscall có sẵn trong hồ sơ. Vì vậy tripwire chỉ phủ các kỹ thuật **buộc** phải dùng syscall lạ (`ptrace`, `setns`, `execveat`…), không phủ mọi tấn công. Luật triage probe hiện khớp theo binary nên kẻ tấn công dùng cùng interpreter qua `kubectl exec` sẽ lọt; bản thật phải khớp cả argv.

### 4.4 Dataset và khung tấn công

- **[TB] LID-DS 2021** (Grimmer 2022): khung ghi dataset, dataset syscall (kèm tham số, giá trị trả về) và thư viện đánh giá. Mỗi kịch bản có ba vai là container Docker: kẻ tấn công, nạn nhân, người dùng (hành vi và nhịp lấy mẫu từ log web server thật); 15 kịch bản.
- Dataset khác trong catalog (chỉ link): DongTing (Zenodo), Docker container escape (IEEE DataPort). Khung đối chiếu độ phủ: MITRE ATT&CK for Containers, Threat Matrix for Kubernetes (RESEARCH_IDEAS 5.3).
- **[ĐA]** LID-DS là đường khả thi nhất để có điểm so sánh công khai và chạy STIDE (G3), và để port vài kịch bản exploit thật (G2). Tạm hoãn vì máy chủ tải từ chối kết nối (21/10).

## 5. Mô hình và chi phí suy luận

- **[Đ][TB] ExtraTrees** (Geurts 2006): ngẫu nhiên hóa cả thuộc tính lẫn điểm cắt khi tách nút. Giảm phương sai đổi lấy tăng nhẹ độ chệch; giá trị K mặc định gần tối ưu trên 22/24 dataset; mô hình thu được trơn hơn (đa tuyến tính từng mảnh); nhanh vì không tối ưu điểm cắt.
  - **[ĐA]** Lý do dùng cho nhánh tree của base29: fit và chấm nhanh, chấm nhanh khớp từng bit với sklearn (Pulse 5.8i: 41.250 dòng, 0 lệch).
- **[TB] Isolation Forest** (Liu 2008): cô lập thay vì mô tả normal; thời gian tuyến tính, bộ nhớ thấp, dùng được khi tập huấn luyện không có bất thường. **[ĐA]** Trên dữ liệu Pulse, cùng khung conformal và ngân sách, Isolation Forest kém hẳn (Pulse 5.15a).
- **[TB] Mehta 2024** (104 dataset): học sâu thắng ở dữ liệu nhiều chiều và lớn; phương pháp cây không giám sát thắng ở dữ liệu nhỏ, một chiều (MGBTAI có precision cao nhất ở 25/31 dataset một chiều); nhiều mô hình sâu mới cần nhiễm bất thường trong tập huấn luyện và tốn tài nguyên.
- **[ĐA]** Baseline autoencoder trên cùng khung bắt attack ngang hoặc hơn base29, gánh thấp hơn ~9 lần ở cùng recall, nhanh hơn (p95 1,1 so với 2,8 s), nhưng gắn cờ binary vô hại ~100%; base29 chỉ hơn ở khả năng tách binary vô hại (Pulse 5.15a, lặp lại 5.15b: không thay base29).
- **Chi phí suy luận:**
  - [TB] Nakandala 2020 (Hummingbird): đưa hơn 40 featurizer và mô hình ML truyền thống về phép toán tensor, nhanh hơn bản C++/CUDA viết riêng.
  - [TB] Guan 2023: với forest nhỏ hoặc dữ liệu nhỏ, **chuyển dữ liệu** chứ không phải suy luận là nút cổ chai.
  - [TB] Osaki 2024: eBPF không có số thực dấu phẩy động; số cố định động cho phép phát hiện bất thường hoàn toàn trong kernel, thông lượng hơn 18% so với bản dấu phẩy động ở user space, độ chính xác tương đương.
  - Zheng 2026 *(dựng lại)*: suy luận CNN trong kernel bằng eBPF cho thiết bị biên (chỉ có tiêu đề và đoạn mở đầu).
  - **[ĐA]** Hướng đưa phần chấm điểm vào kernel để giảm độ trễ là việc tương lai; chưa đo phần nào của p95 nằm ở chấm điểm.
- **Một mô hình mỗi thực thể hay mô hình chung:**
  - [TB] Fernando 2024: mô hình cho từng thiết bị chính xác nhất nhưng tốn nhất; chuyển tham số trong cụm (ICPTL) đạt gần như vậy với 40% thời gian huấn luyện; một mô hình mỗi cụm (CM) giảm thêm 23% thời gian và ~66% số mô hình.
  - He 2025 (ShareAD) *(dựng lại)*: huấn luyện trước một mô hình chung rồi căn chỉnh theo người vận hành.
  - **[ĐA]** Pulse dùng 21 mô hình riêng theo workload; đây là hướng tham khảo nếu cần mở rộng nhiều workload.
- Pedregosa 2011: scikit-learn, thư viện cài đặt các mô hình trên.

## 6. Provenance, RCA và phân loại cảnh báo

### 6.1 Gánh cảnh báo là vấn đề vận hành có bằng chứng

- **[TB] Alahmadi 2022** (khảo sát 20 người làm SOC, phỏng vấn sâu 21 người): phần lớn cái gọi là báo nhầm thực ra là **benign trigger**: detector thấy đúng một sự kiện có thật, chỉ là sự kiện đó hợp lệ trong môi trường. Xác thực alarm là việc nặng, gây kiệt sức và chai sạn. Năm tính chất alarm cần có: Reliable, Explainable, Analytical, Contextual, Transferable.
- **[TB] Oliver 2024 (Carbon Filter):** analyst dành hơn nửa thời gian cho cảnh báo sai; triage dựa trên provenance tốn hơn một phút mỗi cảnh báo, trong khi EDR có hàng chục triệu cảnh báo mỗi ngày. Gom cụm theo command line khởi tạo process cho tỉ lệ tín hiệu/nhiễu tốt hơn 6 lần; lý thuyết 20 triệu cảnh báo/giờ.
- **[ĐA]** Pulse 5.18 xác nhận đúng dạng benign trigger trên dữ liệu của mình: 57,9% case trên normal (2.758/4.765) trùng lúc có exec, phần lớn là probe exec của Kubernetes.

### 6.2 Triage và điều tra bằng provenance

| Bài | Ý chính | Kết quả tự báo cáo |
|---|---|---|
| Hassan 2019 (NoDoze) | Đồ thị phụ thuộc nhân quả của alert; chấm độ bất thường từng cạnh theo tần suất trong lịch sử, lan truyền điểm (network diffusion); phân vùng thực thi theo hành vi để chống bùng nổ phụ thuộc | 364 alert tại NEC Labs: xếp alert thật cao hơn alert sai; giảm 84% báo nhầm, tiết kiệm hơn 90 giờ điều tra/tuần; đồ thị nhỏ hơn 2 bậc |
| Cheng 2023 (Kairos) | Bốn tiêu chí cho IDS provenance: phạm vi (vượt ranh giới ứng dụng), không cần biết trước tấn công, kịp thời, tái dựng tấn công. GNN encoder-decoder học thay đổi cấu trúc đồ thị theo thời gian | Thỏa cả bốn; vượt các cách trước trên benchmark |
| Li 2024 (NodLink) | Phát hiện trực tuyến như bài toán cây Steiner (có thuật toán xấp xỉ trực tuyến, sai số bị chặn) | Hệ thống trực tuyến trước đó sinh đồ thị > 100.000 nút; NodLink chính xác hơn nhiều bậc ở cùng thông lượng |
| Jiang 2025 (ORTHRUS) | **Chất lượng quy kết (QoA)**: công sức analyst cần để điều tra đầu ra; đề xuất cách đánh giá bảo thủ, ưu tiên hệ thống ít cảnh báo | Giảm số nút phải xem tay nhiều bậc so với 5 IDS khác |
| Ying 2025 (METANOIA) | Học tăng dần để chống concept drift trong provenance, tránh quên và tránh học hành vi độc hại | Precision tăng 30%/54%/29% ở mức cửa sổ/đồ thị/nút |
| Goyal 2023 | Mimicry chống IDS provenance | Né 100% trên 5 hệ thống |
| Day 2012 (CONDOR) | Đề xuất IDS lai chữ ký + bất thường để giảm báo nhầm | Đề xuất kiến trúc, không có đánh giá định lượng |

### 6.3 LLM cho phân loại và điều tra

- **[TB] Wei 2025 (CORTEX):** nhiều agent LLM chuyên vai (phân tích hành vi, thu thập bằng chứng, suy luận) trên bằng chứng thật; F1 hành động được từ 0,66 lên 0,78, báo nhầm từ 24,9% xuống 14,2% so với một agent.
- **[TB] Begimher 2026 (SIR-Bench):** 794 ca từ 129 mẫu sự cố ẩn danh; agent của tác giả đạt 97,1% phát hiện ca thật, 73,4% loại ca sai (tác giả ghi nằm trong khoảng 70–80% của analyst người), trung bình 5,67 phát hiện mới mỗi ca.
- **[TB] Jajodia 2026 (SIABench):** 25 kịch bản phân tích sự cố (229 câu hỏi) và 135 kịch bản triage; đánh giá 11 LLM; LLM tiến bộ nhưng còn thiếu về suy luận và độ tin cậy.
- **[ĐA]** Ngoài phạm vi luận văn; trích ở phần hướng phát triển của RCA.

### 6.4 Áp vào RCA của Pulse

- **[ĐA] Bốn tiêu chí của Kairos làm khung đánh giá RCA:**
  - phạm vi: cạnh `connect` nối process với Pod/Service đích, có ánh xạ qua NAT/mesh (RCA 5.13);
  - không cần biết trước tấn công: case dựng từ cây process quanh cửa sổ cảnh báo;
  - kịp thời: preview → case p95 2,59 s (RCA 5.11);
  - tái dựng: cây case, ví dụ thật trong `validation-evidence/rca/examples-20261023/`.
- **[ĐA] QoA của ORTHRUS** cho thước đo đúng: không chỉ coverage (86,7%) mà là analyst phải xem bao nhiêu nút. Top-1 nghi phạm (100% với luật hạ quyền trên dữ liệu mới) là một đại lượng QoA; số nút mỗi case nên được báo thêm.
- **[ĐA] NoDoze** là nguồn của luật triage theo lịch sử: hành vi đã lặp lại thì không tính là bằng chứng (Pulse 5.22, hướng 3). Luật triage probe giữ lại 54,0% case trên normal và 0 case attack (Pulse 5.18, development).
- **[ĐA] Alahmadi 2022** là căn cứ để báo riêng benign trigger thay vì gộp chung vào "báo nhầm".

## 7. Công cụ runtime eBPF và overhead

- **[TB] Syairozi 2025** (Falco, Tetragon, Tracee trên Kubernetes; node 2 vCPU, 4 GB; mỗi kịch bản lặp 20 lần):
  - MTTD: Tetragon 1,18 s cho thoát container và 0,42 s cho đào coin; Falco 1,12 s cho DoS; Tracee chậm nhất;
  - CPU: Tetragon ~6,5 millicore, Falco ~431,5 millicore; Falco ít bộ nhớ nhất;
  - cả ba phát hiện đủ, không báo nhầm, **nhưng không có tải vô hại để đo báo nhầm**.
- **[TB]** Kim 2025: overhead theo dõi syscall thay đổi theo tải, cao hơn ở tải nặng bộ nhớ và I/O. Ghimire 2025: < 2,5%.
- **[ĐA] Pulse 5.21:** khoảng 250–450 ns mỗi syscall của container được theo dõi, 80–230 ns với container không theo dõi (microbenchmark trên một worker). Mốc không probe đã cao (getpid ~1,07 µs, nhiều khả năng do VM, giảm thiểu Spectre và probe khác như Tetragon), nên **so bằng ns tuyệt đối, không bằng phần trăm**.
- **Tài liệu dự án (chỉ link trong catalog):**
  - Falco: luật và drift detection (binary không có trong image, nhận qua lớp upper của overlayfs; blog Sysdig);
  - Tetragon: policy kprobe, `exec_id`, sự kiện process;
  - Prometheus Alertmanager: API v2, route, receiver (RCA 5.14);
  - Istio ambient: probe của kubelet được SNAT về 169.254.7.127 / `fd16:9254:7127:1337:ffff:ffff:ffff:ffff` (RCA 5.13);
  - bảng ABI syscall Linux x86-64 v6.8 (ID syscall);
  - MAPIE (Mondrian), DeepOD (thư viện phát hiện bất thường sâu).

## 8. Phương pháp đánh giá

- **[TB] Arp 2020** ("Dos and Don'ts", USENIX Security 2022): 10 sai lầm phổ biến trong học máy cho bảo mật, có mặt rộng rãi trong 30 bài hội nghị hàng đầu được khảo sát; làm thực nghiệm ở 4 lĩnh vực để cho thấy chúng thổi phồng kết quả. Bảng tự kiểm P1–P10 của Pulse ở RESEARCH_IDEAS 4.3.
- **Khoảng tin cậy và lấy mẫu lại:**
  - Wilson 1927 *(dựng lại)*: khoảng score cho tỉ lệ nhị thức, luôn trong [0, 1], ổn ở tỉ lệ gần 0 hoặc 1 và mẫu nhỏ. Dùng cho precision, recall, control trong báo cáo `.md`.
  - Efron 1993 *(dựng lại)*: bootstrap; khi dữ liệu phụ thuộc theo nhóm thì lấy mẫu lại theo nhóm. Đồ án dùng bootstrap ghép cặp theo workload, 10.000 lần (syscall 5.7, 5B, 5C; Pulse 5.15).
  - Docx và slide không ghi CI; `.md` ghi đủ (DOCS_INDEX).
- **Tỉ lệ nền:** Rebjock 2021 nhắc dataset công khai có mật độ bất thường cao phi thực tế; Arp P8. Precision trên campaign 1:1 phải đi kèm gánh cảnh báo trên toàn bộ normal (mục 3.3).
- **Không so trực tiếp con số giữa các bài:** đơn vị (trace 30 s, cửa sổ 0,5 s, khoảng 15 s), tỉ lệ normal/attack và định nghĩa báo nhầm khác nhau (RESEARCH_IDEAS 3, nhận xét 2).

## 9. Câu được nói và nguồn

| Câu trong luận văn | Nguồn | Giới hạn phải nêu |
|---|---|---|
| CUSUM là luật dừng tối ưu minimax giữa độ trễ và tần suất báo nhầm | Lorden 1971, Moustakides 1986 | Khi bước tăng là log tỉ số hợp lý, quan sát độc lập |
| Martingale conformal phổ biến chậm trên lý thuyết; khởi động lại giải quyết | Bhattacharyya 2026 | Quan sát độc lập |
| p-value conformal hợp lệ không cần mô hình phân bố | Vovk 2005, Bates 2021 | Dữ liệu hoán đổi được; p ≥ 1/(n+1) |
| Có cách giữ coverage khi dữ liệu trôi | Barber 2022, Gibbs 2021, Tibshirani 2019 | Cận phụ thuộc mức trôi; ACI cần phản hồi nhãn |
| Làm mới định kỳ là chính sách hợp lý cho model tĩnh | Dasari 2026 | Mô phỏng, model tuyến tính, preprint |
| Mondrian giữ coverage cho nhóm hiếm | Vovk 2005, Althani 2026 | Nhóm phải đủ điểm calibration |
| Gộp min-p × số nhánh hợp lệ với mọi phụ thuộc | Bonferroni (chuẩn); Chen 2022 | Bảo thủ |
| Gộp Cauchy hợp lệ gần đúng dưới phụ thuộc | Liu 2018 | Gần đúng ở p nhỏ; có trường hợp vô dụng (Chen 2022) |
| Phần lớn báo nhầm trong SOC là benign trigger | Alahmadi 2022 | Nghiên cứu định tính, 20 + 21 người |
| Gánh cảnh báo là nút thắt vận hành | Alahmadi 2022, Oliver 2024, Hassan 2019 | Bối cảnh SOC/EDR doanh nghiệp |
| Chỉ tần suất syscall bỏ sót attack tần suất thấp | CDL (qua REPLICAWATCHER), Pulse 5.15c | CDL là bản dựng lại; số CDL lấy từ bảng của REPLICAWATCHER |
| Hồ sơ normal cũ đi trong microservice | El Khairi 2024 | — |
| Server không cần `execve` sau pha khởi tạo | Ghavamnia 2020b | 6 server, phân tích tĩnh |
| IDS syscall và provenance đều bị mimicry | Wagner 2002, Goyal 2023 | — |
| Các công trình gần nhất đánh giá offline, không có đối chứng vô hại | Bảng 4.1, Syairozi 2025 | Nhận định từ những bài đã đọc, không phải khảo sát toàn diện |
| Đánh giá ML cho bảo mật hay mắc 10 sai lầm | Arp 2020 | — |

## 10. Khoảng trống và việc đọc thêm

1. **CUSUM trên p-value conformal phụ thuộc:** các bảo đảm (Vovk 2019, Bhattacharyya 2026) cần quan sát độc lập hoặc hoán đổi được; cửa sổ của Pulse phụ thuộc qua feature lịch sử. Hướng mở: e-detector khởi động lại trên p-value conformal và đo ARL thực nghiệm.
2. **Cỡ nhóm Mondrian:** đã kiểm (Pulse 5.22), mỗi lớp ≥ 1.200 cửa sổ ở workload có probe exec. Còn mở: nhóm theo (workload, node) như gợi ý của kafka worker1 ở Pulse 5.25 sẽ nhỏ hơn nhiều, phải kiểm lại cỡ nhóm nếu dùng.
3. **Ý nghĩa toàn cụm** (look-elsewhere, Araz 2026): tỉ lệ báo nhầm cho cả cụm thay vì từng container.
4. **Bản dựng lại:** lấy bản gốc của 10 bài qua thư viện trước khi trích chi tiết. Năm bài kinh điển (Page, Wilson, Efron, Vovk 2005, Forrest) chỉ dùng cho định nghĩa chuẩn; năm bài còn lại (CDL, KubAnomaly, ShareAD, O-RAN, CNN trong kernel) chỉ dùng số trong tóm tắt.
5. **Wagner 2002:** đã đọc phần thực nghiệm (pH, wuftpd, mục 4.3). Chưa đọc phụ lục về số lần lệch cho phép trước khi pH phản ứng.
6. **Chưa thấy công trình trùng toàn bộ hướng của Pulse** trong 70 bài này (eBPF đếm syscall theo cgroup, model theo workload, p-value conformal, chạy live K8s, đo độ trễ và gánh cảnh báo, đối chứng vô hại). Câu này chỉ đúng với tập đã đọc; cần một lượt tìm có hệ thống trước khi viết paper.

## Bảng tra khóa → file

File nằm trong `references/pdf/` (ngoài git; bản sao trên NFS `/mnt/sentinel-pulse-archive/references/pdf`; lấy lại bằng `python3 scripts/fetch_references.py`).

| Khóa | Bài | Nơi công bố | File |
|---|---|---|---|
| Wilson 1927 *(dựng lại)* | Probable Inference, the Law of Succession, and Statistical Inference | Journal of the American Statistical Association | `1927-wilson-probable-inference-the-law-of-succession-and-statistical--reconstructed.pdf` |
| Page 1954 *(dựng lại)* | Continuous Inspection Schemes | Biometrika | `1954-page-continuous-inspection-schemes--reconstructed.pdf` |
| Lorden 1971 | Procedures for Reacting to a Change in Distribution | The Annals of Mathematical Statistics | `1971-lorden-procedures-for-reacting-to-a-change-in-distribution.pdf` |
| Moustakides 1986 | Optimal Stopping Times for Detecting Changes in Distributions | The Annals of Statistics | `1986-moustakides-optimal-stopping-times-for-detecting-changes-in.pdf` |
| Efron 1993 *(dựng lại)* | An Introduction to the Bootstrap | Chapman & Hall/CRC | `1993-efron-an-introduction-to-the-bootstrap--reconstructed.pdf` |
| Forrest 1996 *(dựng lại)* | A sense of self for Unix processes | IEEE Symposium on Security and Privacy 1996 | `1996-forrest-a-sense-of-self-for-unix-processes--reconstructed.pdf` |
| Wagner 2002 | Mimicry Attacks on Host-Based Intrusion Detection Systems | ACM CCS 2002 | `2002-wagner-mimicry-attacks-on-host-based-intrusion-detection-systems.pdf` |
| Vovk 2005 *(dựng lại)* | Algorithmic Learning in a Random World | Springer | `2005-vovk-algorithmic-learning-in-a-random-world--reconstructed.pdf` |
| Geurts 2006 | Extremely randomized trees | Machine Learning | `2006-geurts-extremely-randomized-trees.pdf` |
| Liu 2008 | Isolation Forest | 2008 Eighth IEEE International Conference on Data Mining | `2008-liu-isolation-forest.pdf` |
| Moustakides 2009 | Numerical Comparison of Cusum and Shiryaev-Roberts Procedures for Detecting Changes in Distributions | arXiv | `2009-moustakides-numerical-comparison-of-cusum-and-shiryaev-roberts.pdf` |
| Pedregosa 2011 | Scikit-learn: Machine Learning in Python | Journal of Machine Learning Research | `2011-pedregosa-scikit-learn-machine-learning-in-python.pdf` |
| Day 2012 | CONDOR: A Hybrid IDS to Offer Improved Intrusion Detection | IEEE TrustCom 2012 | `2012-day-condor-a-hybrid-ids-to-offer-improved-intrusion-detection.pdf` |
| Abed 2016 | Intrusion Detection System for Applications using Linux Containers | STM 2015, LNCS 9331, tr. 123–135 (DOI 10.1007/978-3-319-24858-5_8, theo trang arXiv 1611.03056); file là bản arXiv 2016 | `2016-abed-intrusion-detection-system-for-applications-using-linux.pdf` |
| Kim 2016 | LSTM-Based System-Call Language Modeling and Robust Ensemble Method for Designing Host-Based Intrusion Detection Systems | arXiv | `2016-kim-lstm-based-system-call-language-modeling-and-robust-ensemble.pdf` |
| Liu 2018 | Cauchy combination test: a powerful test with analytic p-value calculation under arbitrary dependency structures | arXiv | `2018-liu-cauchy-combination-test-a-powerful-test-with-analytic-p.pdf` |
| Hassan 2019 | NoDoze: Combatting Threat Alert Fatigue with Automated Provenance Triage | NDSS 2019 | `2019-hassan-nodoze-combatting-threat-alert-fatigue-with-automated.pdf` |
| Tibshirani 2019 | Conformal Prediction Under Covariate Shift | arXiv | `2019-tibshirani-conformal-prediction-under-covariate-shift.pdf` |
| Tien 2019 *(dựng lại)* | KubAnomaly: Anomaly detection for the Docker orchestration platform with neural network approaches | Engineering Reports | `2019-tien-kubanomaly-anomaly-detection-for-the-docker-orchestration--reconstructed.pdf` |
| Vovk 2019 | Testing randomness | arXiv | `2019-vovk-testing-randomness.pdf` |
| Wilson 2019 | The harmonic mean p -value for combining dependent tests | Proceedings of the National Academy of Sciences | `2019-wilson-the-harmonic-mean-p-value-for-combining-dependent-tests.pdf` |
| Arp 2020 | Dos and Don'ts of Machine Learning in Computer Security | arXiv | `2020-arp-dos-and-don-ts-of-machine-learning-in-computer-security.pdf` |
| Barbero 2020 | Transcending Transcend: Revisiting Malware Classification in the Presence of Concept Drift | arXiv | `2020-barbero-transcending-transcend-revisiting-malware-classification-in.pdf` |
| Castanhel 2020 | Sliding Window: The Impact of Trace Size in Anomaly Detection System for Containers Through Machine Learning | ERRC 2020 (SBC) | `2020-castanhel-sliding-window-the-impact-of-trace-size-in-anomaly-detection.pdf` |
| Ghavamnia 2020a | Confine: Automated System Call Policy Generation for Container Attack Surface Reduction | 23rd International Symposium on Research in Attacks, Intrusions and Defenses (RAID 2020) | `2020-ghavamnia-confine-automated-system-call-policy-generation-for.pdf` |
| Ghavamnia 2020b | Temporal System Call Specialization for Attack Surface Reduction | 29th USENIX Security Symposium (USENIX Security 20) | `2020-ghavamnia-temporal-system-call-specialization-for-attack-surface.pdf` |
| Lin 2020 *(dựng lại)* | CDL: Classified Distributed Learning for Detecting Security Attacks in Containerized Applications | Annual Computer Security Applications Conference | `2020-lin-cdl-classified-distributed-learning-for-detecting-security--reconstructed.pdf` |
| Nakandala 2020 | A Tensor Compiler for Unified Machine Learning Prediction Serving | Symposium on Operating Systems Design and Implementation (OSDI) | `2020-nakandala-a-tensor-compiler-for-unified-machine-learning-prediction.pdf` |
| Bates 2021 | Testing for Outliers with Conformal p-values | arXiv | `2021-bates-testing-for-outliers-with-conformal-p-values.pdf` |
| Fisher 2021 | Online False Discovery Rate Control for LORD & SAFFRON Under Positive, Local Dependence | arXiv | `2021-fisher-online-false-discovery-rate-control-for-lord-saffron-under.pdf` |
| Gibbs 2021 | Adaptive Conformal Inference Under Distribution Shift | arXiv | `2021-gibbs-adaptive-conformal-inference-under-distribution-shift.pdf` |
| Podkopaev 2021 | Tracking the risk of a deployed model and detecting harmful distribution shifts | arXiv | `2021-podkopaev-tracking-the-risk-of-a-deployed-model-and-detecting-harmful.pdf` |
| Rebjock 2021 | Online false discovery rate control for anomaly detection in time series | arXiv | `2021-rebjock-online-false-discovery-rate-control-for-anomaly-detection-in.pdf` |
| Yang 2021 | {CADE}: Detecting and Explaining Concept Drift Samples for Security Applications | 30th USENIX Security Symposium (USENIX Security 21) | `2021-yang-cade-detecting-and-explaining-concept-drift-samples-for.pdf` |
| Alahmadi 2022 | 99% False Positives: A Qualitative Study of {SOC} Analysts' Perspectives on Security Alarms | 31st USENIX Security Symposium (USENIX Security 22) | `2022-alahmadi-99-false-positives-a-qualitative-study-of-soc-analysts.pdf` |
| Barber 2022 | Conformal prediction beyond exchangeability | arXiv | `2022-barber-conformal-prediction-beyond-exchangeability.pdf` |
| Chen 2022 | Robust tests for combining p-values under arbitrary dependency structures | Scientific Reports | `2022-chen-robust-tests-for-combining-p-values-under-arbitrary.pdf` |
| Grimmer 2022 | Extended Abstract: LID-DS 2021 | CRITIS 2022 | `2022-grimmer-extended-abstract-lid-ds-2021.pdf` |
| El Khairi 2022 | Contextualizing System Calls in Containers for Anomaly-Based Intrusion Detection | Proceedings of the 2022 on Cloud Computing Security Workshop | `2022-khairi-contextualizing-system-calls-in-containers-for-anomaly-based.pdf` |
| Zaffran 2022 | Adaptive Conformal Predictions for Time Series | International Conference on Machine Learning | `2022-zaffran-adaptive-conformal-predictions-for-time-series.pdf` |
| Angelopoulos 2023 | Conformal PID Control for Time Series Prediction | arXiv | `2023-angelopoulos-conformal-pid-control-for-time-series-prediction.pdf` |
| Cheng 2023 | Kairos: Practical Intrusion Detection and Investigation using Whole-system Provenance | arXiv | `2023-cheng-kairos-practical-intrusion-detection-and-investigation-using.pdf` |
| Goyal 2023 | Sometimes, You Aren't What You Do: Mimicry Attacks against Provenance Graph Host Intrusion Detection Systems | NDSS 2023 | `2023-goyal-sometimes-you-aren-t-what-you-do-mimicry-attacks-against.pdf` |
| Guan 2023 | A Comparison of Decision Forest Inference Platforms from A Database Perspective | arXiv | `2023-guan-a-comparison-of-decision-forest-inference-platforms-from-a.pdf` |
| Krönert 2023 | FDR Control for Online Anomaly Detection | arXiv | `2023-kronert-fdr-control-for-online-anomaly-detection.pdf` |
| Fernando 2024 | Efficient Training Approaches for Performance Anomaly Detection Models in Edge Computing Environments | arXiv | `2024-fernando-efficient-training-approaches-for-performance-anomaly.pdf` |
| El Khairi 2024 | REPLICAWATCHER: Training-less Anomaly Detection in Containerized Microservices | NDSS 2024 | `2024-khairi-replicawatcher-training-less-anomaly-detection-in.pdf` |
| Li 2024 | NODLINK: An Online System for Fine-Grained APT Attack Detection and Investigation | NDSS 2024 | `2024-li-nodlink-an-online-system-for-fine-grained-apt-attack.pdf` |
| Mehta 2024 | Benchmarking Anomaly Detection Algorithms: Deep Learning and Beyond | arXiv | `2024-mehta-benchmarking-anomaly-detection-algorithms-deep-learning-and.pdf` |
| Oliver 2024 | Carbon Filter: Real-time Alert Triage Using Large Scale Clustering and Fast Search | arXiv | `2024-oliver-carbon-filter-real-time-alert-triage-using-large-scale.pdf` |
| Osaki 2024 | Dynamic Fixed-point Values in eBPF: a Case for Fully In-kernel Anomaly Detection | Proceedings of the 19th Asian Internet Engineering Conference | `2024-osaki-dynamic-fixed-point-values-in-ebpf-a-case-for-fully-in.pdf` |
| Bortolini 2025 | Detecção Eficiente de Anomalias em Hosts usando Transformer com Categorização de Chamadas de Sistema | Anais do XXV Simpósio Brasileiro de Cibersegurança (SBSeg 2025) | `2025-bortolini-deteccao-eficiente-de-anomalias-em-hosts-usando-transformer.pdf` |
| Ghimire 2025 | eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation using eBPF in Containerized and Virtualized Environments | arXiv | `2025-ghimire-ebpf-patrol-protective-agent-for-threat-recognition-and.pdf` |
| He 2025 *(dựng lại)* | On the Practicability of Deep Learning Based Anomaly Detection for Modern Online Software Systems: A Pre-Train-and-Align Framework | ACM Transactions on Software Engineering and Methodology | `2025-he-on-the-practicability-of-deep-learning-based-anomaly--reconstructed.pdf` |
| Jiang 2025 | ORTHRUS: Achieving High Quality of Attribution in Provenance-based Intrusion Detection Systems | USENIX Security 2025 | `2025-jiang-orthrus-achieving-high-quality-of-attribution-in-provenance.pdf` |
| Kim 2025 | Detecting Cryptojacking Containers Using eBPF-Based Security Runtime and Machine Learning | Electronics | `2025-kim-detecting-cryptojacking-containers-using-ebpf-based-security.pdf` |
| Syairozi 2025 | Comparative Analysis of eBPF-Based Runtime Security Monitoring Tools in Monitoring and Threat Detection on Kubernetes | Proceedings of the 1st International Conference on Research and Innovations in Information and Engineering Technology | `2025-syairozi-comparative-analysis-of-ebpf-based-runtime-security.pdf` |
| Wei 2025 | CORTEX: Collaborative LLM Agents for High-Stakes Alert Triage | NeurIPS 2025 | `2025-wei-cortex-collaborative-llm-agents-for-high-stakes-alert-triage.pdf` |
| Ying 2025 | METANOIA: A Lifelong Intrusion Detection and Investigation System for Mitigating Concept Drift | arXiv | `2025-ying-metanoia-a-lifelong-intrusion-detection-and-investigation.pdf` |
| Zehra 2025 | FedMon: Federated eBPF Monitoring for Distributed Anomaly Detection in Multi-Cluster Cloud Environments | arXiv | `2025-zehra-fedmon-federated-ebpf-monitoring-for-distributed-anomaly.pdf` |
| Zhang 2025 | e-GAI: e-value-based Generalized $α$-Investing for Online False Discovery Rate Control | International Conference on Machine Learning | `2025-zhang-e-gai-e-value-based-generalized-investing-for-online-false.pdf` |
| Althani 2026 | Class-Conditional Conformal Prediction for Reliable Anomaly Detection Under Extreme Class Imbalance | Machine Learning and Knowledge Extraction 8, 190 | `2026-althani-class-conditional-conformal-prediction-for-reliable-anomaly.pdf` |
| Araz 2026 | Conformal calibration and look-elsewhere effect in anomaly detection for new-physics searches | arXiv | `2026-araz-conformal-calibration-and-look-elsewhere-effect-in-anomaly.pdf` |
| Begimher 2026 | SIR-Bench: Evaluating Investigation Depth in Security Incident Response Agents | arXiv | `2026-begimher-sir-bench-evaluating-investigation-depth-in-security.pdf` |
| Bhattacharyya 2026 | Change detection with conformal martingales: new optimal constructions, and suboptimality of existing methods | arXiv | `2026-bhattacharyya-change-detection-with-conformal-martingales-new-optimal.pdf` |
| Dasari 2026 | When to Retrain: An Empirical Study of Retraining Policies for Streaming ML Under Concept Drift, Budget, and Latency Constraints | arXiv | `2026-dasari-when-to-retrain-an-empirical-study-of-retraining-policies.pdf` |
| Jajodia 2026 | Before You Hand Over the Wheel: Evaluating LLMs for Security Incident Analysis | arXiv | `2026-jajodia-before-you-hand-over-the-wheel-evaluating-llms-for-security.pdf` |
| Rheey 2026 *(dựng lại)* | Toward Reliable Intrusion Monitoring for O-RAN Based Networks with Conformal False Alarm Control | ICML 2026 | `2026-rheey-toward-reliable-intrusion-monitoring-for-o-ran-based--reconstructed.pdf` |
| Zheng 2026 *(dựng lại)* | In-Kernel CNN Inference for Edge Devices: An eBPF-Based Approach to Low-Latency and Resource-Efficient Processing | Lecture Notes in Computer Science | `2026-zheng-in-kernel-cnn-inference-for-edge-devices-an-ebpf-based--reconstructed.pdf` |
| Zhou 2026 | An Abnormal File Access Detection Model for Containers Based on eBPF Listening | Mathematics 14(6), 991 | `2026-zhou-an-abnormal-file-access-detection-model-for-containers-based.pdf` |
