# Calibration dưới distribution shift và kiểm soát alert burden cho streaming anomaly detection (áp dụng cho Sentinel Pulse)

Ghi chú nghiên cứu, 30/10/2026. Bối cảnh Pulse (từ đề bài, không phải nguồn ngoài): cửa sổ 0.5 s / container, split conformal p-value, calibration theo workload, joint p của 2 branch, alert khi 2 cửa sổ liên tiếp có p ≤ 5α với α = 0.05/30 (≈ 0.00167, nên 5α ≈ 0.0083). Burden đo được khoảng 1.5 episode/replica-giờ so với budget 0.1. Đã thử: CUSUM/k-of-n, NexCP, ACI, Mondrian theo node, rolling recalibration (12 h, cập nhật mỗi giờ: −37 % burden trên soak 48 h đã cũ, không thắng trong 24 h đầu sau calibration mới).

Quy ước: "Cited Findings" là kết quả đo hoặc định lý có nguồn. "Inferences" là suy luận của người viết cho Pulse, chưa được đo. Các con số Pulse ở trên lấy từ đề bài.

## 1. Conformal dưới shift: weighted/nonexchangeable, ACI/DtACI, conformal PID, expert aggregation, Mondrian/group-conditional, conformal test martingales, conformal outlier detection có FDR, e-values

### Takeaway
Không phương pháp nào giữ được *ngưỡng FPR theo từng cửa sổ* dưới drift tùy ý. Các phương pháp chỉ cho một trong hai loại bảo đảm. Loại thứ nhất là bảo đảm marginal có thêm số hạng sai lệch: NexCP có thêm Σ w̃ᵢ·d_TV. Loại thứ hai là tần suất lỗi trung bình dài hạn: ACI/DtACI/conformal PID đạt |tần suất − α| ≤ (b+η)/(ηT) với dữ liệu tùy ý. Với anomaly detection không nhãn, "lỗi" là chính alert, nên họ ACI/PID về bản chất là một **bộ điều khiển alert rate**: nó giữ được burden nhưng sẽ nâng ngưỡng trong lúc bị tấn công. Conformal test martingale (Vovk) là công cụ hợp lý để *phát hiện lúc calibration hết hạn* với bảo đảm false-alarm dạng Ville. Nó không thay được ngưỡng.

### Cited Findings
**Nonexchangeable conformal (NexCP)**
- Barber, Candès, Ramdas, Tibshirani, "Conformal prediction beyond exchangeability" (arXiv:2202.13415, v5 ngày 17/03/2023). Theorem 2: P{Yₙ₊₁ ∈ Ĉₙ} ≥ 1 − α − Σᵢ w̃ᵢ·d_TV(R(Z), R(Zⁱ)), với w̃ᵢ = wᵢ/(w₁+⋯+wₙ+1). Zⁱ là Z với điểm test hoán đổi vào vị trí i. Kết quả áp dụng cho cả split conformal. Trọng số là cố định, chọn trước (không phụ thuộc dữ liệu) — [arXiv HTML](https://arxiv.org/html/2202.13415v5)
- Thực nghiệm ELEC2, mục tiêu 90 %, trung bình trên toàn chuỗi. Trên dữ liệu gốc (có drift): CP+LS coverage 0.852 (width 0.565), NexCP+LS 0.890 (0.606), NexCP+WLS 0.893 (0.527). Trên bản hoán vị (exchangeable): ba phương pháp lần lượt 0.899 / 0.908 / 0.908. CP chuẩn bị undercover chủ yếu quanh giữa chuỗi — [arXiv HTML](https://arxiv.org/html/2202.13415v5)
- Abstract mô tả phương pháp là weighted quantile để chống drift và nêu thực nghiệm trên dữ liệu điện và dự báo bầu cử — [arXiv abs](https://arxiv.org/abs/2202.13415)

**Adaptive conformal inference (ACI) và DtACI**
- Gibbs & Candès (arXiv:2106.00170, 2021) mô hình hóa shift như một bài toán học trên **một tham số**. Phương pháp "provably achieves the desired coverage frequency over long-time intervals" và được thử trên 2 bộ dữ liệu thực — [arXiv abs](https://arxiv.org/abs/2106.00170)
- Gibbs & Candès (arXiv:2208.08401, v3 ngày 05/10/2023) thêm bước tự tune step-size của ACI theo thời gian. Phương pháp có "provably small regret over all local time intervals of a given width" (strongly adaptive regret), không cần giả định phân phối và không cần biết trước tốc độ thay đổi (ACI thì cần). Thử trên stock volatility và COVID-19 cases — [arXiv abs](https://arxiv.org/abs/2208.08401)

**Conformal PID control**
- Angelopoulos, Candès, Tibshirani (arXiv:2307.16895, 31/07/2023). Proposition 1 (quantile tracking): với mọi chuỗi score trong [−b, b], mọi η > 0 và T ≥ 1, |(1/T)Σ(errₜ − α)| ≤ (b+η)/(ηT). Không cần biết b để chạy thuật toán. Bảo đảm này không cần bất kỳ giả định phân phối nào — [arXiv HTML](https://arxiv.org/html/2307.16895)
- Các thành phần: (1) quantile tracking (P); (2) integrator dạng hàm bão hòa rₜ, ví dụ tan integrator rₜ(x) = K_I·tan(x·log t /(t·C_sat)) (I); (3) "scorecaster" dự báo quantile kế tiếp từ quá khứ (D), dùng Theta model hoặc quantile regression ℓ1 — [arXiv HTML](https://arxiv.org/html/2307.16895)
- Kết quả đo. COVID-19 California (mục tiêu 0.8): ensemble của CDC đạt 0.82 (set size 625, chuỗi miss dài nhất 6), conformal PID đạt 0.86 (858, chuỗi miss dài nhất 2). Trong một đoạn 10 tuần, ensemble 20 % còn PID 70 %. NY 0.78→0.85, Texas 0.75→0.85. Electricity, Transformer (0.9): ACI 0.899 nhưng set size trung bình **vô hạn**, PID 0.901 với set size 0.174. Amazon, AR: ACI và quantile tracking cùng 0.894, ACI set vô hạn, QT 17.6. Google, Transformer: QT 0.817, thêm integrator lên 0.897 — [arXiv HTML](https://arxiv.org/html/2307.16895)
- Code được link từ trang arXiv — [arXiv abs](https://arxiv.org/abs/2307.16895)

**Group-conditional / Mondrian**
- Gibbs, Cherian, Candès, "Conformal prediction with conditional guarantees" (arXiv:2305.12616, v4 09/2024). Với lớp covariate shift hữu hạn chiều, phương pháp cho "exact finite-sample coverage over all possible shifts". Ví dụ: với một tập subgroup cho trước, coverage được bảo đảm trên từng group. Với lớp vô hạn chiều, coverage chính xác là bất khả, nhưng sai số coverage định lượng được và điều chỉnh bằng hyperparameter. Phương pháp cắm được vào pipeline split conformal — [arXiv abs](https://arxiv.org/abs/2305.12616)

**Conformal test martingales (Vovk)**
- Vovk, Petej, Nouretdinov, Ahlberg, Carlsson, Gammerman, "Retrain or not retrain: Conformal test martingales for change-point detection" (PMLR 152, COPA 2021). Exchangeability martingale được xây từ conformal p-value, đặt chồng lên bất kỳ predictor nào, và tính hợp lệ được bảo đảm (validity guaranteed). Hiệu quả (efficiency) để ngỏ. Ba quy tắc alarm: Ville procedure (vượt ngưỡng cố định, tốt lúc đầu rồi kém dần), conformal CUSUM và conformal Shiryaev–Roberts. Mục đích là báo khi nào cần retrain. Minh họa trên Wine Quality với 1 change point — [PMLR](https://proceedings.mlr.press/v152/vovk21b.html); [PDF arXiv](https://arxiv.org/pdf/2102.10439)
- Eliades và cộng sự mở rộng: huấn luyện nhiều model trên các kích thước dữ liệu khác nhau, retrain classifier nào có inductive conformal martingale báo thay đổi — [PMLR v204](https://proceedings.mlr.press/v204/eliades23a/eliades23a.pdf)
- Vovk, "Testing randomness online" (Statistical Science 36(4)): nền tảng lý thuyết của các test exchangeability online — [Project Euclid](https://projecteuclid.org/journals/statistical-science/volume-36/issue-4/Testing-Randomness-Online/10.1214/20-STS817.pdf)

**Conformal outlier detection + FDR (Bates et al.)**
- Bates, Candès, Lei, Romano, Sesia, "Testing for outliers with conformal p-values", *Annals of Statistics* 51(1):149–178, 2023. Conformal p-value marginal là "positively dependent" và cho phép kiểm soát FDR chính xác, "although in a relatively weak marginal sense". Calibration-conditional p-value hợp lệ có điều kiện theo dữ liệu calibration và độc lập giữa các điểm test, cho phép bảo đảm type-I mạnh hơn. Có biến thể "asymptotic" và "Monte Carlo" — [arXiv abs](https://arxiv.org/abs/2104.08279)

**Online FDR và e-values cho streaming**
- Krönert, Célisse, Hattab, "FDR control for online anomaly detection" (arXiv:2312.01969, v2 16/12/2024). Họ kiểm soát cục bộ "modified FDR" (mFDR) rồi suy ra kiểm soát FDR toàn chuỗi. **Kích thước tập calibration** dùng cho empirical p-value là "an important ingredient", và tác giả có chiến lược riêng để tune nó. Chỉ có mô phỏng, abstract không có số — [arXiv abs](https://arxiv.org/abs/2312.01969)
- Xu & Ramdas, "Online multiple testing with e-values" (AISTATS 2024, PMLR v238): e-LOND kiểm soát FDR dưới phụ thuộc tùy ý, kể cả phụ thuộc không biết — [PMLR](https://proceedings.mlr.press/v238/xu24a.html); [arXiv](https://arxiv.org/pdf/2311.06412)
- Phê bình: e-LOND "does not make full use of the entire error budget", phân bổ mức kiểm định theo dãy giảm cố định, nên FDR bảo thủ và mất power — [arXiv 2603.24792](https://arxiv.org/pdf/2603.24792)
- "Feedback-Enhanced Online Multiple Testing with Applications to Conformal Selection" (arXiv:2509.03297) dùng rank-based conformal e-value, trong đó **mỗi null đã được xác nhận được thêm vào calibration pool**. Vì e-LOND chịu được phụ thuộc tùy ý, nó hấp thụ được phụ thuộc do calibration set chung thay đổi theo thời gian gây ra — [arXiv](https://arxiv.org/pdf/2509.03297)
- arXiv:2603.24792 (2026) thử các thủ tục e-value trên NYC taxi (streaming anomaly). Bảng kết quả bị lỗi định dạng khi trích, nên không gán được số cho từng biến thể — [arXiv](https://arxiv.org/pdf/2603.24792)

### Inferences
- **Vì sao NexCP và rolling recalibration không thắng khi calibration còn mới.** Theo Theorem 2, khi d_TV giữa dữ liệu cũ và mới nhỏ thì NexCP không cải thiện gì, và đổi lại mất cỡ mẫu hiệu dụng. Điều này khớp với việc "không thắng trong 24 h đầu". Lợi ích chỉ xuất hiện khi d_TV lớn (soak 48 h cũ).
- **ACI/PID trong bài toán không nhãn.** Với Pulse, errₜ = 1{alert ở cửa sổ t}. Proposition 1 khi đó bảo đảm tần suất alert dài hạn → α, *bất kể* alert là thật hay giả. Đây là cơ chế "budgeted alerting" có chứng minh: đặt α_target bằng budget, ví dụ 0.1 episode/replica-giờ quy ra tỉ lệ cửa sổ. Hệ quả: trong một chiến dịch tấn công kéo dài, ngưỡng sẽ tăng dần và che attack. Tốc độ che phụ thuộc η: sau khoảng 1/η cửa sổ có alert liên tục, ngưỡng đã dịch đáng kể. Cách giảm thiểu cần thử: (a) η rất nhỏ (chỉ theo được drift chậm theo ngày); (b) chỉ cho phép ngưỡng **giảm** nhanh và tăng chậm (bất đối xứng); (c) đóng băng cập nhật khi đang có episode mở. (b) và (c) làm mất bảo đảm Proposition 1 dạng nguyên bản.
- **Mondrian per-replica.** Với α = 0.00167, conformal p-value nhỏ nhất là 1/(n+1), nên mỗi group cần n ≥ 599 điểm để có thể đạt p ≤ α, và n ≥ 120 để đạt p ≤ 5α. Ở 2 cửa sổ/giây, 600 cửa sổ chỉ là 5 phút, nhưng ước lượng đuôi 0.17 % từ vài nghìn điểm vẫn nhiễu. Calibration per-replica cần ít nhất vài giờ dữ liệu sạch/replica (nhận định, chưa đo). Cách của Gibbs–Cherian–Candès với group chồng lấp (workload ∪ replica) cho bảo đảm đồng thời theo cả hai mức. Đây là ứng viên tốt cho "Kafka replica lệch": group = {workload, replica}.
- **Conformal test martingale làm trigger recalibration.** Thay lịch cố định mỗi giờ, chạy martingale trên p-value của từng replica. Theo Ville's inequality (cơ sở của Ville procedure trong Vovk 2021), P(sup M ≥ c) ≤ 1/c dưới exchangeability. Ví dụ c = 100 cho xác suất báo nhầm "calibration hết hạn" ≤ 1 % trên toàn bộ thời gian. Martingale không phân biệt được drift lành tính với tấn công: cả hai đều phá exchangeability. Vì vậy martingale chỉ nên mở "cửa sổ đề xuất recalibration" và để chính sách chống poisoning (mục 2) quyết định.
- **Cùng martingale đó phát hiện được sự cố vận hành.** Sự cố CNPG replica là một thay đổi bền vững. Martingale sẽ vọt lên rồi ở mức cao, có thể dùng để gom thành **một** incident thay vì hàng nghìn episode (xem mục 3).
- **FDR không phải mục tiêu đúng cho Pulse.** Pulse có khoảng 80 × 7,200 = 576,000 cửa sổ/giờ (80 container × 2 cửa sổ/s × 3,600 s) và rất ít non-null thật. Online FDR (LOND/e-LOND) kiểm soát *tỉ lệ* alert sai trong số alert, không kiểm soát *số lượng* alert/giờ. Khi gần như không có tấn công, FDR control ≈ FWER control trên dòng vô hạn, nên wealth cạn và power rất thấp. Mục tiêu vận hành nên là alert rate theo thời gian (budget). FDR hợp hơn ở tầng incident (ít test hơn).

### Gaps
- Chưa trích được nguyên văn công thức ACI αₜ₊₁ = αₜ + γ(α − errₜ) và cận |…| ≤ (max{α₁,1−α₁}+γ)/(γT) từ trang đã fetch (abstract không có). Công thức ghi theo hiểu biết của người viết, cần kiểm lại trong PDF arXiv:2106.00170.
- Chưa xác nhận venue: ACI (NeurIPS 2021?), DtACI (JMLR 2024?), conformal PID (NeurIPS 2023?), NexCP (Annals of Statistics 2023?). Các trang abstract đã fetch không ghi venue.
- Không đủ lượt tìm cho AgACI (Zaffran et al., ICML 2022, online aggregation các ACI expert). Không có số liệu.
- Chưa có kết quả thực nghiệm nào của các phương pháp trên cho syscall/container anomaly detection. Toàn bộ thực nghiệm là forecasting (điện, COVID, chứng khoán).
- Vovk 2021: chưa đọc full text, nên không có số về detection delay.

## 2. Recalibration chống poisoning: cập nhật calibration online mà không để attack lọt vào

### Takeaway
Kết quả lý thuyết quan trọng nhất (Bashari–Sesia–Romano, ICML 2025): khi outlier/attack lọt vào tập calibration và có score **lớn hơn** inlier, conformal outlier detection trở nên **bảo thủ hơn**. Type-I/FPR vẫn được giữ, cái mất là power. Vì vậy rủi ro của rolling recalibration "không biết lúc bị tấn công" chủ yếu là **bỏ sót** (thả lỏng ngưỡng), không phải tăng false alarm. Ngược lại, "trim mù" (bỏ top score hoặc bỏ cửa sổ đã alert mà không có nhãn) **làm phình type-I**. Đây đúng là rủi ro của chính sách "loại các cửa sổ đã alert khỏi calibration".

### Cited Findings
- Bashari, Sesia, Romano, "Robust Conformal Outlier Detection under Contaminated Reference Data" (arXiv:2502.04807, ICML 2025). Lemma 2.2: với n₀ inlier và n₁ outlier trong calibration, P(p̂ ≤ α) ≤ α − (n₁/(n₀+1))·(1 − α − E[F̂₁(Q̂_cal)]). Phép kiểm định bảo thủ khi E[F̂₁(Q̂_cal)] < 1 − α, tức score của outlier thường lớn hơn của inlier. **Nếu outlier có score nhỏ hơn inlier (adversarial), contamination có thể làm phình type-I.** Bản mixture: α − δ·E[F₀(Q̂) − F₁(Q̂)] — [arXiv HTML](https://arxiv.org/html/2502.04807v1); [ICML 2025](https://icml.cc/virtual/2025/poster/43852)
- Label-Trim: gán nhãn m điểm calibration có score cao nhất, loại bỏ những điểm được xác nhận là outlier. Theorem 3.1: nếu m ≤ α(n+1) thì P(p̂ᴸᵀ ≤ α) ≤ α + 1/(n₀+1) − (số hạng không âm khi outlier còn lại có score lớn), tức inflation tối đa khoảng 1/(n₀+1). Thực nghiệm cho type-I gần hợp lệ cả khi budget > 50, vượt điều kiện của định lý — [arXiv HTML](https://arxiv.org/html/2502.04807v1)
- Số đo: CIFAR10 làm inlier, 6 nguồn outlier, contamination 1 % / 3 % / 5 %, α = 0.01. Standard: type-I 0.008/0.005/0.004 (bảo thủ). Label-Trim: 0.010/0.010/0.008, power tương đối 1.17/1.52/1.79. Oracle: 0.010/0.010/0.009, power 1.17/1.55/1.96. Với α = 0.03: Standard 0.027/0.019/0.015, Label-Trim 0.029/0.025/0.021, power 1.04/1.14/1.22. Thêm 3 bộ tabular (shuttle, credit card, KDDCup99) — [arXiv HTML](https://arxiv.org/html/2502.04807v1)
- **Naive-Trim** (bỏ top r % score không có nhãn, với r = tỉ lệ contamination thật): loại nhầm inlier, làm lệch phân phối inlier và phình type-I. Ở α = 0.01, type-I = 0.017/0.027/0.036 (1.7–3.6× nominal). Ở α = 0.03, type-I = 0.035/0.043/0.052. Power cao nhất (1.66/2.79/4.16) nhưng tác giả coi phương pháp là không hợp lệ — [arXiv HTML](https://arxiv.org/html/2502.04807v1)
- "Split Conformal Prediction under Data Contamination" (arXiv:2407.07700, 2024) phân tích ảnh hưởng của việc một phần calibration score đến từ phân phối khác lên coverage và độ hiệu quả trên điểm test sạch. Họ đề xuất Contamination Robust Conformal Prediction cho classification — [arXiv HTML](https://arxiv.org/html/2407.07700v3)
- Online variant có nhãn phản hồi: null được xác nhận được thêm vào calibration pool, và e-LOND giữ FDR dù calibration set thay đổi — [arXiv 2509.03297](https://arxiv.org/pdf/2509.03297)

### Inferences
- **Áp vào Pulse.** Attack trên syscall thường làm score tăng (đó là lý do Pulse bắt được 30/30 attack trong run cuối, theo commit 0448bfc). Vậy theo Lemma 2.2, cửa sổ attack lọt vào rolling calibration *không* làm tăng FPR. Chúng nâng quantile và giảm recall. Mức hại tỉ lệ với n₁/(n₀+1). Ví dụ: calibration 12 h ≈ 86,400 cửa sổ/container, một attack 10 phút ≈ 1,200 cửa sổ, nên n₁/n₀ ≈ 1.4 %. Ở đuôi α = 0.00167 (≈ 144 điểm vượt ngưỡng trong 86,400), chừng đó cửa sổ attack đủ thay thế toàn bộ đuôi. **Ở α rất nhỏ, một attack ngắn cũng có thể dịch ngưỡng mạnh.** Đây là suy luận, cần đo bằng replay: chèn campaign vào calibration rồi đo recall.
- **Chính sách "bỏ cửa sổ đã alert khỏi calibration" chính là Naive-Trim có điều kiện.** Nó loại cả false alarm, vốn là inlier đuôi, nên quantile bị kéo xuống và FPR tăng. Đây là vòng phản hồi dương: càng alert càng loại đuôi, ngưỡng càng thấp, càng alert nhiều. Theo số của Bashari et al., inflation có thể là 1.7–3.6× ở α = 0.01. Cách sửa có cơ sở lý thuyết: chỉ loại cửa sổ alert **đã được xác nhận là attack** (Label-Trim, m ≤ α(n+1)). Trong lab, "xác nhận" có thể là ground truth của campaign. Trong production, đó là nhãn analyst.
- **Các chính sách ứng viên để pre-register (free, chỉ cần numpy):**
  1. *Delayed update*: chỉ đưa vào calibration các cửa sổ cũ hơn D giờ mà trong khoảng đó không có episode nào được xác nhận là attack. Chi phí: calibration trễ D giờ.
  2. *Label-Trim theo campaign*: dùng nhãn campaign làm oracle cho m cửa sổ có score cao nhất. Đây là cận trên của cái analyst có thể làm.
  3. *Cross-replica consensus*: chỉ nhận một cửa sổ vào calibration của replica r khi score của nó nằm trong phân phối của các replica cùng workload trong cùng khoảng thời gian (median ± k·MAD giữa các peer). Attack thường chỉ đánh một replica, còn drift lành tính (traffic) ảnh hưởng mọi replica. Suy luận này chưa có nguồn đo; chưa tìm được paper kiểm chứng.
  4. *Không trim, chấp nhận bảo thủ*: chỉ dùng được nếu đo recall thấy mất ít.
- **Hướng kiểm thử:** chạy replay offline trên dữ liệu soak có sẵn, so sánh 4 chính sách trên 2 metric: (i) burden (episode/replica-giờ), (ii) recall trên campaign. Kịch bản "attack lọt vào calibration" được dựng bằng cách cố ý giữ cửa sổ campaign.

### Gaps
- Không tìm thấy nghiên cứu đo trực tiếp poisoning *có chủ đích* vào calibration của conformal anomaly detector, ví dụ attacker tạo hoạt động "nhiễu" từ từ để nới ngưỡng (boiling-frog). Lemma 2.2 cũng cảnh báo trường hợp adversarial có score thấp có thể phình type-I.
- Không tìm được kết quả đo cho cross-replica consensus hay robust quantile (trimmed/winsorized) trong conformal streaming.
- Chưa đọc phần còn lại của arXiv:2407.07700 (số liệu).

## 3. Kiểm soát alert burden: budgeted alerting, aggregation, FDR trên nhiều stream, suppression/dedup trong SOC, metric khuyến nghị, số liệu thực địa

### Takeaway
Số liệu thực địa cho thấy SOC nhận hàng nghìn alert/ngày và bỏ qua phần lớn (Vectra 2024: 3,832/ngày, 62 % bị bỏ qua). Phần lớn "false positive" theo cảm nhận của analyst thực ra là **benign trigger**: alert đúng về mặt kỹ thuật nhưng có lý do hợp lệ (Alahmadi et al., USENIX Sec 2022). Đây đúng là trường hợp sự cố CNPG replica của Pulse. Hai đòn bẩy có kết quả đo là gom alert theo ngữ cảnh/nguyên nhân (NoDoze: −86 % false alarm) và tương quan alert với sự kiện vận hành (Gandalf). Với 2,900 episode/ngày, Pulse đang ở cùng cỡ với số alert/ngày của một SOC trung bình theo Vectra, cho chỉ 80 container.

### Cited Findings
- Alahmadi, Axon, Martinovic, "99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms" (USENIX Security 2022). Survey online 20 SOC practitioner xác nhận tỉ lệ FP cao, phải kiểm tra thủ công. Phỏng vấn 21 practitioner từ 7 SOC (Template Analysis). Phần lớn FP theo cảm nhận là **benign triggers**: alarm đúng do hành vi hợp lệ trong môi trường, nên analyst có thể bỏ qua. Tác giả khuyến nghị phân biệt các loại FP khi đánh giá công cụ. Quy trình kiểm tra lấy con người làm trung tâm. Năm thuộc tính alarm tốt: Reliable, Explainable, Analytical, Contextual, Transferable — [USENIX](https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi); [Oxford](https://www.cs.ox.ac.uk/publications/publication14673-abstract.html)
- Vectra (khảo sát, công bố khoảng tháng 10/2024): trung bình 3,832 alert/ngày, 62 % bị bỏ qua, 81 % nhân sự SOC dành hơn 2 giờ/ngày lọc alert. Đây là khảo sát do vendor tài trợ, số tự báo cáo — [MSSP Alert](https://www.msspalert.com/news/mssp-market-news-survey-shows-62-of-soc-alerts-are-ignored); [DevX](https://www.devx.com/daily-news/soc-teams-overwhelmed-ignore-most-alerts/)
- Vectra (bản trước, năm chưa xác minh, có thể là 2023): 4,484 alert/ngày, 67 % bị bỏ qua — [Expert Insights](https://expertinsights.com/?p=59508)
- Prophet Security 2026 (250 người, tự báo cáo): trung bình 28 % alert không được điều tra. 2/5 đã tắt hoặc cân nhắc tắt một detection rule vì không theo kịp lượng alert — [Expert Insights](https://expertinsights.com/?p=59508)
- IDC cho FireEye (2021): 35 % nói họ bỏ qua alert. Với analyst MSSP là 44 % khi hàng đợi quá đầy — [BusinessWire](https://www.businesswire.com/news/home/20210216005436/en)
- NoDoze (Hassan et al., NDSS 2019): dựng causal dependency graph cho mỗi alert, chấm điểm mỗi event theo tần suất các event liên quan từng xảy ra trong doanh nghiệp, rồi lan truyền điểm bằng network diffusion. Trên 364 threat alert, false alarm giảm 86 %, tiết kiệm hơn 90 giờ điều tra. Bản trước và tin của Illinois ghi 84 % (mạng 200 máy) — [NDSS](https://www.ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage); [UVA PDF](https://www.cs.virginia.edu/~hur7wv/papers/hassan-ndss19.pdf); [Illinois](https://siebelschool.illinois.edu/news/hassan-s-nodoze-brings-triage-security-phd-student-presents-paper-ndss-symposium)
- Krönert et al.: online FDR (mFDR cục bộ → FDR toàn chuỗi) cho anomaly detection, với kích thước calibration là tham số then chốt — [arXiv](https://arxiv.org/abs/2312.01969)

### Inferences
- **Metric nên báo cáo**, nhất quán với Alahmadi và Vectra:
  - episode/replica-giờ và alert/ngày toàn cụm (đã có);
  - *incident*/ngày sau khi gom (xem dưới);
  - ước lượng analyst-phút/ngày (= incident × thời gian triage giả định, ghi rõ là giả định);
  - tách loại alert: (a) attack, (b) benign trigger vận hành (failover, rollout, restart), (c) FP thống kê thuần.
  Chỉ loại (c) là lỗi của detector theo nghĩa Alahmadi. Loại (b) cần một cơ chế khác (context).
- **Gom thành incident (dedup):** gộp mọi episode cùng (workload, replica) cách nhau dưới T phút thành một incident. Mở incident mới chỉ khi martingale/score về lại nền (mục 1). Sự cố CNPG "alert liên tục" khi đó còn 1 incident. Cần báo cáo song song episode và incident để không che kết quả.
- **Budgeted alerting có chứng minh:** dùng quantile tracking (conformal PID) với α_target = budget, ví dụ 0.1 episode/replica-giờ, đặt ở tầng episode chứ không phải tầng cửa sổ. Đánh đổi là che attack kéo dài (mục 1). Nên đo bằng replay: burden đạt budget ± bao nhiêu, recall mất bao nhiêu.
- **Budget mục tiêu đặt trong ngữ cảnh:** 0.1 episode/replica-giờ × 80 container ≈ 192 episode/ngày. Con số này vẫn là khối lượng đáng kể cho một analyst. Dưới góc nhìn SOC, 1 sensor không nên đóng góp quá vài phần trăm của khoảng 3,800 alert/ngày (Vectra). Đây là nhận định, chưa có chuẩn công bố.
- **Context từ Kubernetes như suppression có lý do:** Kubernetes events/CNPG failover/rollout là tín hiệu "benign trigger". Tương quan alert với các event này giống Gandalf (mục 4), giúp gắn nhãn (b) thay vì im lặng xóa. Chỉ dùng API Kubernetes, miễn phí.

### Gaps
- Không tìm được nghiên cứu thực địa đo analyst-phút/alert một cách đáng tin. Các số SOC chủ yếu là khảo sát của vendor, tự báo cáo.
- Không tìm được paper về FDR trên hàng nghìn container streaming trong production.
- Năm của số 4,484/67 % (Vectra) chưa xác minh.

## 4. Baseline per-entity vs fleet (per-replica vs per-workload) trong hệ thống production, và xử lý sự cố vận hành so với tấn công

### Takeaway
Các hệ thống production tìm được dùng **kết hợp** baseline học từ lịch sử của từng thành phần với so sánh/tương quan trong nhóm peer hoặc với sự kiện triển khai. Ví dụ: Microsoft Gandalf (Azure, NSDI 2020); patent peer-group cho cloud; UEBA phân biệt entity-based và peer-based. Không tìm được paper công nghiệp nào so sánh định lượng per-entity với per-fleet trên cùng dữ liệu. Với Pulse, kiến trúc hợp lý là Mondrian/group-conditional đa mức (workload + replica) cộng với tầng tương quan sự kiện vận hành.

### Cited Findings
- Microsoft Gandalf (Li et al., NSDI 2020). Chạy production trên Azure hơn 18 tháng. Data-plane: precision 92.4 %, recall 100 % (không có outage lớn nào của Azure Compute do bad rollout trong giai đoạn đó). Control-plane: precision 94.9 %, recall 99.8 %. Ngưỡng cố định "not practical" ở quy mô Azure vì hệ thống/workload động và số fault signature lớn, nên baseline được học tự động từ lịch sử. Anomaly được tương quan với deployment event gần đó, và dùng vote-veto khi nhiều component cùng deploy. Ensemble ranking chọn rollout thủ phạm, binary classifier đánh giá tác động. Đây là số tự báo cáo — [USENIX NSDI'20](https://www.usenix.org/conference/nsdi20/presentation/li); [PDF](https://web.eecs.umich.edu/~ryanph/paper/gandalf-nsdi20.pdf); [tóm tắt Acolyer](https://blog.acolyer.org/2020/02/28/microsoft-gandalf/)
- Patent "Method and system for evaluating peer groups for comparative anomaly" (US12149402, liên quan US11601325). Giám sát một service riêng lẻ có thể thiếu tiêu chí "bất thường", nên component cloud được gom thành peer group (kỹ thuật pointwise và non-pointwise) và gắn cờ khi một component lệch khỏi nhóm — [Google Patents](https://patents.google.com/patent/US12149402)
- Splunk UEBA: entity-based detection so với chính lịch sử của entity. Peer-based detection dựng baseline cho peer group, ví dụ các server chạy cùng ứng dụng. Đây là tài liệu vendor — [Splunk blog](https://embargo.splunk.com/en_us/blog/security/beyond-logs-navigating-entity-behavior-in-splunk-platform.html)
- Theo *The DevOps Handbook* (trích lại, không phải nguồn gốc), Netflix ước lượng trạng thái "bình thường" của các node trong cluster rồi gắn cờ và loại các node lệch. Không xác nhận được bài gốc trên Netflix TechBlog — [Goodreads note](https://www.goodreads.com/notes/59012409-the-devops-handbook/54568504-attila-bert-k/63d37e3e-9bf3-4f0a-abf6-d56213b50c00)
- Lý thuyết hỗ trợ đa mức: coverage chính xác cho từng subgroup trong một tập group cho trước (Gibbs–Cherian–Candès) — [arXiv](https://arxiv.org/abs/2305.12616)
- Alahmadi et al.: "benign triggers" là nguồn FP chính theo cảm nhận, nên cần phân biệt bất thường vận hành với tấn công khi đánh giá — [USENIX](https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi)

### Inferences
- **Kafka replica lệch systematically:** per-workload calibration giả định các replica exchangeable với nhau, điều này sai với replica đó. Hai lựa chọn có thể thử:
  - (a) Mondrian theo replica, cần đủ dữ liệu sạch/replica (≥ vài nghìn cửa sổ; mục 1);
  - (b) group-conditional chồng lấp {workload} ∪ {replica} theo Gibbs–Cherian–Candès, để replica ít dữ liệu vẫn được neo vào workload.
  Rủi ro của per-replica: replica bị compromise từ lúc calibration sẽ tự "bình thường hóa". Peer comparison (fleet) bắt được trường hợp này, per-entity thì không. Nên giữ một tín hiệu peer song song: điểm lệch so với median các replica cùng workload.
- **Sự cố vận hành (CNPG replica failure) so với attack:** theo kiểu Gandalf, tương quan episode với Kubernetes/CNPG event (pod restart, failover, rollout) trong cửa sổ ±k phút, rồi gắn nhãn "operational" thay vì xóa. Đánh giá bằng cách đếm bao nhiêu episode trong run thật trùng event vận hành. Rủi ro: attacker gây failover để che. Vì vậy chỉ hạ mức ưu tiên, không suppress hẳn.
- **Thử nghiệm đề xuất cho Pulse**, offline replay trên soak đã có, chỉ dùng công cụ miễn phí (Python/numpy, `kubectl get events`): so sánh burden và recall của
  1. per-workload (hiện tại);
  2. per-replica Mondrian;
  3. group-conditional chồng lấp;
  4. (1) + peer-deviation gate (chỉ alert khi replica lệch cả so với lịch sử lẫn so với peer cùng thời điểm).
  Lựa chọn (4) cũng nhắm thẳng vào "alert ×2 khi traffic thay đổi", vì traffic thay đổi tác động đồng thời mọi replica.

### Gaps
- Không tìm được paper LinkedIn (ThirdEye) hay Netflix (RAD/outlier detection) có số đo so sánh per-entity với fleet. Lượt tìm Netflix không ra nguồn gốc.
- Không có nghiên cứu nào đo "attacker lợi dụng sự cố vận hành để che" trong container.
- Mọi đề xuất peer-gate/consensus ở trên là suy luận, chưa có bằng chứng thực nghiệm ngoài.
