# Tổng Quan Dự Án — Agent Runtime Sentinel
### Từ đồ án đã hoàn thành (V1) đến sản phẩm AI Agent Security (V2)

*Tài liệu tổng hợp — liên kết với: Roadmap chính, GiaiDoan1, Founder Strategy Framework, Founder Manifesto, Kiến Trúc Hệ Thống*

---

## 1. Tóm tắt

Đồ án cuối kỳ (học kỳ 2025.2, GVHD Nguyễn Đức Toàn) đã **hoàn thành và có kết quả thực nghiệm thật** — đây không phải kế hoạch, mà là **V1 đã chạy được, đã đo được số**. Toàn bộ chiến lược founder (Thesis, Customer, GTM, Business Model — các file trước) được xây dựng ĐÚNG NGAY TRÊN nền V1 này, không phải từ số 0. V2 (AI Agent Security, đã bàn ở các file trước) là bước mở rộng có chủ đích từ V1, không phải dự án khác.

---

## 2. V1 — Đã hoàn thành: Runtime Security tổng quát cho Kubernetes

**Hạ tầng thí nghiệm ban đầu:** cụm K8s 3 node (1 master, 2 worker). **Deployment hiện hành (xác minh 01-08-2026):** Kubernetes v1.34.10 gồm 3 control plane + 3 worker trên Ubuntu 24.04; Tetragon DaemonSet đạt 6/6 và giám sát syscall qua `TracingPolicyNamespaced`. Các kết quả paper cũ trên 3 node vẫn được giữ như evidence lịch sử, không được trình bày như topology hiện tại.

**Pipeline ML (5 giai đoạn):** phân tích syscall profile theo workload → sinh dữ liệu huấn luyện (n-gram unigram+bigram) → **LSTM Autoencoder + Isolation Forest** (per-pod model, ensemble 0.6×LSTM + 0.4×IF) → phát hiện real-time (cửa sổ 30s) → **phản hồi tự động 4 bước: cordon node → gán nhãn quarantine → CiliumNetworkPolicy deny-all → evict pod** → ánh xạ MITRE ATT&CK for Containers (rule-based, 6 kỹ thuật).

**Kết quả thực nghiệm (5 kịch bản × 5 lần, 25 lần đo):**

| Chỉ số | Kết quả |
|---|---|
| Detection Rate | 100% (25/25) |
| False Positive Rate | 0% |
| MITRE Mapping Accuracy | 100% (25/25) |
| Detection Latency trung bình | 88,46s (phụ thuộc cửa sổ 30s) |
| Response Latency trung bình | ~0,5s (4 bước cô lập) |

**Addendum runtime hiện hành (xác minh 01-08-2026):** model V7 cadence 10 giây
đã pass normal-control 216 cửa sổ với zero detection/score crossing/behavior
crossing và pass 15/15 real-kernel attack trials. Fast path early-warning có
p50/p95/max `0,285/0,919/0,956 giây`; ML confirmation có min/median/max
`7,058/17,303/18,593 giây`. Đây là hai metric khác nhau: fast path không tự cô
lập pod, ML path mới là quyết định xác nhận. Production đã promote nguyên tử
nhưng vẫn chạy audit `--dry-run`. Evidence nằm tại
`../validation-evidence/20260801T153648Z/`; chi tiết ở
`../PROJECT_STATUS_REPORT.md`, Mục 18.21. Bảng phía trên vẫn là kết quả paper V1
lịch sử, không được trộn với protocol 10 giây hiện hành.

**Bài học kỹ thuật quan trọng nhất (áp dụng thẳng vào V2):** *"Chất lượng và tính nhất quán dữ liệu baseline quan trọng hơn thuật toán"* — training distribution phải khớp runtime distribution; per-pod baseline giảm cả false positive lẫn false negative; thứ tự quarantine-trước-evict ngăn race condition exfiltration.

**Hạn chế đã tự nhận diện (Mục 7.3 của báo cáo) — đây chính là điểm nối sang V2:**
- Ngưỡng τ=0,80 **cố định (static)**, chưa thích nghi theo thời gian thực
- Chỉ phát hiện dựa trên **syscall sequence tổng quát** (n-gram), chưa hiểu ngữ nghĩa ứng dụng (agent gọi tool gì, qua giao thức gì)
- Chỉ test trên workload truyền thống (nginx/redis/postgres), chưa test AI Agent

---

## 3. V2 — Mở rộng có chủ đích: từ Workload Security → AI Agent Security

V1 chứng minh **cách tiếp cận đúng** (eBPF + ML + auto-response hoạt động thật, số liệu thật). V2 không thay thế V1, mà **giải quyết đúng 3 hạn chế V1 tự nêu**, đồng thời đổi đối tượng bảo vệ sang AI Agent — đúng Founder Thesis đã chốt.

| Hạn chế V1 (Mục 7.3-7.4 báo cáo) | Giải pháp V2 |
|---|---|
| Ngưỡng τ tĩnh, chưa thích nghi (chính báo cáo đề xuất "Threshold Adaptation" ở Mục 7.4.1) | **EVT-POT** — đúng hướng báo cáo tự đề ra, thay bằng nền tảng lý thuyết chặt hơn (extreme value theory) thay vì rolling variance đơn giản |
| N-gram syscall sequence — không hiểu ngữ nghĩa ứng dụng | **Graph Attention Network** trên đồ thị hành vi (agent→tool→resource) — thay vì chỉ đếm tần suất syscall, hiểu quan hệ *ai gọi ai* |
| Chưa hiểu giao thức tầng ứng dụng (chỉ syscall thô) | **Custom eBPF/C + uprobe SSL** bóc tách MCP call — phần hoàn toàn mới, không có trong V1 |
| Chỉ test workload truyền thống | Đối tượng mới: **AI Agent chạy qua MCP trong pod K8s** |
| Response 4 bước đã tốt (0,5s, đúng thứ tự) | **Giữ nguyên gần như 100%** — đây là phần V1 đã làm đúng, không cần xây lại |

**Điều này có nghĩa:** V2 kế thừa trực tiếp hạ tầng K8s/Cilium/Tetragon, toàn bộ Lớp 4 (Response) của V1, và bài học per-pod baseline — chỉ thay Lớp 1 (thêm custom eBPF/C cho MCP) và Lớp 3 (LSTM+IF → GAT+EVT-POT). Đây là lý do V2 khả thi trong khung thời gian Master's, không phải làm lại từ đầu.

---

## 4. Kiến trúc V2 (cập nhật, đối chiếu trực tiếp với V1)

*(Sơ đồ đầy đủ: `Dat_Kien_Truc_He_Thong_Diagram.mermaid`; chi tiết kỹ thuật: `Dat_Kien_Truc_He_Thong.md`)*

| Lớp | V1 (đã có) | V2 (bổ sung/thay) |
|---|---|---|
| 1. Data Collection | Tetragon TracingPolicy (declarative, syscall chuẩn) | **+ Custom eBPF/C (libbpf)** hook uprobe `SSL_read`/`SSL_write` để bóc JSON-RPC (MCP) — Tetragon vẫn giữ nguyên làm nền |
| 2. Graph Construction | N-gram vector (unigram+bigram), không phải đồ thị | **Mới hoàn toàn** — Go service dựng đồ thị hành vi agent (node=agent/tool/resource, edge=call) |
| 3. Anomaly Detection | LSTM Autoencoder + Isolation Forest, ensemble 0,6/0,4, ngưỡng tĩnh 0,80 | **Graph Attention Network + EVT-POT** — thay toàn bộ, giữ nguyên triết lý per-pod (giờ là per-agent) baseline đã được V1 chứng minh hiệu quả |
| 4. Response | 4 bước cordon→label→CiliumNetworkPolicy→evict, ~0,5s | **Giữ nguyên** — đã tối ưu, chỉ cần đổi trigger source sang Lớp 3 mới |
| 5. Product | Chưa có (V1 là đồ án, không đóng gói) | Dashboard, Helm chart, đa cụm (Mục Business Model — enterprise tier) |

**Rủi ro kỹ thuật kế thừa từ bài học V1 (áp dụng lại cho V2):**
- Đúng như V1 gặp vấn đề `sendfile`/`keep-alive` làm mất syscall event, MCP qua HTTPS cũng sẽ mất dữ liệu nếu không hook đúng tầng (uprobe SSL thay vì socket thường) — **đây là rủi ro lớn nhất, đã có tiền lệ thật trong V1, không phải suy đoán**.
- Bài học "training distribution phải khớp runtime distribution" áp dụng nguyên vẹn cho việc thu thập baseline hành vi AI Agent — cần thu thập từ agent chạy thật, không dùng dữ liệu tổng hợp (synthetic) như `generate-baseline.py` (Markov) mà V1 đã chứng minh kém hiệu quả hơn `generate_baseline2.py` (real vectors).

---

## 5. Liên kết chiến lược (recap từ các file trước)

| Câu hỏi | Trả lời (chi tiết đầy đủ ở file gốc) |
|---|---|
| Founder Thesis | AI Agent = lực lượng lao động số → cần Runtime Security độc lập → Kubernetes là môi trường mặc định (`Dat_Founder_Manifesto.md`) |
| Customer | DevSecOps/Platform Engineer, công ty Series B-D chạy K8s + AI Agent thật (`Dat_Founder_Strategy_Framework.md`, Mục 2) |
| Pain | Sự cố Replit (xoá production thật, 7/2025) + 6 kịch bản kỹ thuật cụ thể (Mục 3) — **giờ có thêm bằng chứng: chính V1 đã chứng minh 5 kịch bản tấn công tương tự phát hiện được 100%, làm nền tảng thuyết phục cho pitch** |
| Business Model | Open-core, tính phí theo số Agent giám sát (Mục 4) |
| GTM | Open Source → GitHub → CNCF → KubeCon, không qua SI/Bank (Mục 5) — V1 đã có kết quả thật là nguyên liệu launch GitHub cực tốt (số liệu 100% detection, 0% FPR) |
| Học Master's | HUST hướng Nghiên cứu (Mức 1 = 100% học phí) làm nền, song song Đức/Erasmus Mundus/Knight-Hennessy (`Dat_GiaiDoan1...md`, Phần C) |

---

## 6. Kế hoạch phát triển tiếp theo (cập nhật North Star Metrics)

V1 đã hoàn thành nghĩa là tiến độ **vượt trước** mốc 2026 đã đặt ra trước đây (trước đó chỉ kỳ vọng "Lớp 1: commit đầu tiên"). Cập nhật:

| Giai đoạn | Việc cần làm |
|---|---|
| **Ngay bây giờ** | Mang chính V1 + kết quả thực nghiệm này làm minh chứng khi liên hệ lab HUST xin đề cương hướng Nghiên cứu (đã có kết quả thật, không phải đề xuất suông — cơ hội đỗ Mức 1 học bổng cao hơn nữa) |
| **2026 (còn lại)** | Viết lại V1 thành 1-2 bài blog/CFP KubeCon (số liệu 100%/0% rất đáng công bố) · Bắt đầu Lớp 1 mới (custom eBPF/C + uprobe SSL cho MCP) trên chính cụm 3-node đã có sẵn — không cần dựng lại hạ tầng |
| **2027** | Lớp 2 (graph) + Lớp 3 (GAT+EVT-POT) thay thế LSTM+IF · Chạy lại đúng bộ 5 kịch bản tấn công (đổi mục tiêu sang AI Agent) để có bảng so sánh V1 vs V2 — chất liệu mạnh cho luận văn + demo sản phẩm |
| **2028** | Đóng gói Helm chart, tìm design partner đầu tiên |

---

## 7. Chỉ mục tài liệu liên quan

- `Dat_Global_Tech_Entrepreneur_Roadmap.md` — chiến lược tổng thể, so sánh trường Master's
- `Dat_GiaiDoan1_KienThuc_Portfolio_HocBong_FounderClarity.md` — kiến thức cần học, học bổng
- `Dat_Founder_Strategy_Framework.md` — 8 câu hỏi founder (Thesis, Customer, Pain, Business Model, GTM, Competitive Advantage, Personal Constraints, Decision Framework)
- `Dat_Founder_Manifesto.md` — bản rút gọn 1 trang + North Star Metrics
- `Dat_Kien_Truc_He_Thong.md` + `.mermaid` — kiến trúc kỹ thuật V2 chi tiết
- **Báo cáo đồ án V1 gốc** (`report_final.docx`) — nguồn dữ liệu/kết quả thực nghiệm cho toàn bộ tài liệu này
