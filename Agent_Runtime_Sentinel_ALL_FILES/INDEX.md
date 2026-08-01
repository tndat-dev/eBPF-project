# INDEX — Toàn bộ tài liệu dự án Agent Runtime Sentinel
### 9 file, chia 3 nhóm — đọc theo đúng thứ tự bên dưới nếu đọc lại từ đầu

---

## Nhóm 1 — Chiến lược & Định hướng (đọc trước tiên)

### 1. `Dat_Global_Tech_Entrepreneur_Roadmap.md` (27 KB)
Roadmap gốc, tổng quát nhất. Nghiên cứu thị trường (Wiz $32B, Chainguard $3.5B, Isovalent/Cisco), lộ trình 4 giai đoạn, so sánh 6 trường Master's (HUST, Stanford, MIT, Berkeley, CMU, NUS), rủi ro visa Mỹ 2026.
**Đọc khi:** cần bức tranh tổng thể hoặc quyết định trường/hướng đi lớn.

### 2. `Dat_Founder_Manifesto.md` (3 KB — ngắn nhất, đọc nhanh)
Bản rút gọn 1 trang: Founder Thesis (3 bước "Tôi tin rằng..."), 9 Decision Principles, North Star Metrics 2026-2029.
**Đọc khi:** cần nhắc lại định hướng cốt lõi trong 2 phút, hoặc in ra dán bàn làm việc.

### 3. `Dat_Founder_Strategy_Framework.md` (19 KB)
Trả lời sâu 8 câu hỏi founder: Customer (DevSecOps/Platform Engineer, Series B-D), Pain (sự cố Replit + 6 kịch bản kỹ thuật), Business Model (open-core, tính phí theo Agent), GTM (Open Source → CNCF → KubeCon, không qua SI/Bank), Competitive Advantage vs Google, Decision Framework (5 câu hỏi, đã áp dụng vào 6 tình huống thật trong quá trình bàn — kể cả HUST-vs-abroad và SI-channel-timing).
**Đọc khi:** cần lập luận chi tiết cho một quyết định cụ thể, hoặc chuẩn bị pitch.

---

## Nhóm 2 — Thực thi: Kiến thức, Portfolio, Học bổng

### 4. `Dat_GiaiDoan1_KienThuc_Portfolio_HocBong_FounderClarity.md` (34 KB — dài nhất)
4 phần: (A) Curriculum kỹ năng cần bổ sung theo trình tự tháng (CKS, eBPF/C thật, MCP, Go, cloud hyperscaler), (B) 5 dự án portfolio + chiến lược phân phối, (C) Bảng học bổng Master's đầy đủ — **HUST (Mức 1 = 100% học phí) và Đức (công lập, học phí 0) là 2 ưu tiên hàng đầu**, Erasmus Mundus/Knight-Hennessy là lớp thứ 2, (D) 10 câu hỏi Founder Clarity bản nháp đầu tiên (đã được Mục 8 File #3 nâng cấp dứt khoát hơn).
**Đọc khi:** cần checklist học/làm cụ thể, hoặc chuẩn bị hồ sơ học bổng.

---

## Nhóm 3 — Kỹ thuật: Kiến trúc & Build

### 5. `Dat_Kien_Truc_He_Thong.md` (7.5 KB) + `Dat_Kien_Truc_He_Thong_Diagram.mermaid` (2 KB)
Kiến trúc 5 lớp phiên bản đầu (trước khi đọc report V1): eBPF/Tetragon → Graph → GAT+EVT-POT → Response → Product. Có bảng ranh giới Open Source/Enterprise và Thesis/Portfolio/Product.
**Đọc khi:** cần sơ đồ trực quan nhanh (file `.mermaid`).

### 6. `Dat_Tong_Quan_Du_An.md` (9.7 KB)
**Quan trọng nhất trong nhóm kỹ thuật** — viết sau khi đọc báo cáo đồ án V1 thật (report_final.docx). Xác nhận: V1 đã hoàn thành, có kết quả thật (100% detection, 0% false positive, 5 kịch bản tấn công, latency đo được). Bảng đối chiếu từng lớp V1 → V2 (cái gì giữ nguyên — Lớp 4 Response — cái gì thay — Lớp 1 và Lớp 3).
**Đọc khi:** cần hiểu V1 đã có gì trước khi động vào code.

### 7. `Agent_Runtime_Sentinel_Build_Spec.md` (14.8 KB, tiếng Anh)
**File để code, không phải để đọc chiến lược.** Repo structure gợi ý, thứ tự implement (Layer 1 → 2 → 3 → 4), tech stack cụ thể từng lớp (libbpf, cilium/ebpf Go lib, PyTorch Geometric, pyextremes), rủi ro kỹ thuật (TLS/uprobe SSL, verifier limits, graph state), checklist 2 tuần đầu.
**Đọc khi:** ngồi vào máy bắt đầu code.

---

## Sơ đồ quan hệ giữa các file

```
Global_Tech_Entrepreneur_Roadmap (chiến lược tổng)
        │
        ├── Founder_Manifesto (bản rút gọn 1 trang)
        ├── Founder_Strategy_Framework (8 câu hỏi sâu)
        └── GiaiDoan1_... (kiến thức/portfolio/học bổng cụ thể)
                │
                ▼
        Kien_Truc_He_Thong + Diagram (kiến trúc kỹ thuật, bản đầu)
                │
                ▼ (sau khi đọc report V1 thật)
        Tong_Quan_Du_An (đối chiếu V1 → V2, xác nhận V1 đã xong)
                │
                ▼
        Agent_Runtime_Sentinel_Build_Spec (bắt đầu code)
```

---

## Còn thiếu / gợi ý bổ sung (chưa làm, cần xác nhận nếu muốn)
- **Literature review** cho phần thesis — đã tìm được danh sách paper cạnh tranh trực tiếp (eBPF+K8s+ML: 5-6 paper 2025-2026; MCP security: 4-5 paper, có cả ACM TOSEM) nhưng chưa đưa vào file nào — đã đề xuất ở lượt trước, chưa làm.

## Paper-readiness artifacts

- `../PROJECT_STATUS_REPORT.md`: trạng thái cluster/runtime đã kiểm chứng; Mục
  18.21 ghi release V7 production, normal-control và 15/15 kernel trials.
- `../validation-evidence/20260801T153648Z/`: normal, attack và release manifest
  immutable của bản production hiện hành.
- `PAPER_READINESS_PLAN.md`: hypothesis, benchmark, baseline, ablation và gate.
- `ARTIFACT.md`: inventory source/scripts/expected result/provenance.
- `ETHICS.md`: safety boundary cho TLS capture, attack simulation và enforcement.
- `REPRODUCE.md`: các gate tái lập hiện tại; không thay thế evaluation matrix.
