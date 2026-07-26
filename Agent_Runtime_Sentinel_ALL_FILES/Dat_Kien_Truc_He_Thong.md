# Kiến Trúc Hệ Thống — Agent Runtime Sentinel

### Tài liệu kỹ thuật cho: kỹ năng (Phần A) + portfolio (Phần B) + thesis HUST + product (Business Model)

*Xem sơ đồ trực quan: `Dat_Kien_Truc_He_Thong_Diagram.mermaid`*

---

## Tổng quan

Một core engine, 5 lớp, phục vụ 4 mục tiêu cùng lúc (kỹ năng, portfolio, thesis, product) — đúng nguyên tắc "ưu tiên vốn hiệu quả" đã đặt ra. Ý tưởng cốt lõi: quan sát AI Agent ở tầng kernel (không phải tầng prompt), mô hình hoá hành vi thành đồ thị, phát hiện bất thường bằng Graph Attention Network + ngưỡng thống kê EVT-POT.

---

## Chi tiết từng lớp

### Lớp 1 — Data Collection (Kernel, eBPF)

**Thành phần:**
- **Custom eBPF/C (libbpf)** — phần tự viết, đóng góp mới của thesis: hook vào socket syscalls (`connect`, `sendto`, `recvfrom`) **và** uprobe vào hàm `SSL_read`/`SSL_write` của thư viện TLS (OpenSSL/BoringSSL) — bắt buộc phải có phần uprobe này vì nếu MCP chạy qua HTTPS (rất phổ biến), hook socket thuần chỉ thấy byte đã mã hoá, vô dụng để bóc JSON-RPC. Đây là kỹ thuật Cilium/Pixie cũng dùng để quan sát traffic mã hoá.
- **Tetragon** — nền tảng loading/quản lý policy (TracingPolicy CRD), không viết lại phần này.

**Lưu ý kỹ thuật quan trọng (verifier limits):** eBPF program bị giới hạn nghiêm ngặt (không vòng lặp không giới hạn, stack nhỏ, không gọi hàm tuỳ ý) — **không parse JSON-RPC đầy đủ trong kernel**. Chiến lược đúng: eBPF chỉ copy raw bytes vào ring buffer càng nhanh càng gọn, việc parse ngữ nghĩa (lấy method/params) đẩy hết lên Lớp 2 (userspace). Nhiều người mới học eBPF hay cố nhồi logic phức tạp vào kernel — đây chính là lỗi cần tránh.

**Output:** raw byte stream (qua BPF ring buffer) chứa MCP call chưa parse.

---

### Lớp 2 — Graph Construction (Userspace, Go)

**Thành phần:**
- Go service đọc BPF ring buffer (dùng `cilium/ebpf` Go library — cùng hệ với Tetragon, tận dụng lại kinh nghiệm Go/kubebuilder từ đồ án cũ), parse JSON-RPC 2.0 → lấy method name (tool nào), params, agent identity.
- **Behavior Graph**: cấu trúc dữ liệu dạng sliding-window (ví dụ giữ 5-10 phút gần nhất, không giữ vô hạn — tránh phình bộ nhớ). Node = {agent instance, MCP tool, K8s resource/pod/service, external endpoint}. Edge = lời gọi, có timestamp + metadata.

**Output:** graph snapshot định kỳ (ví dụ mỗi 10-30 giây) đưa sang Lớp 3.

---

### Lớp 3 — Anomaly Detection (Python)

**Thành phần:**
- **Graph Attention Network** (PyTorch Geometric — thư viện chuẩn cho GNN) — học biểu diễn "hành vi bình thường" từ graph snapshot, attention mechanism xác định quan hệ nào (cạnh nào trong đồ thị) quan trọng nhất khi đánh giá một node/edge có bất thường không.
- **EVT-POT** (Extreme Value Theory – Peaks Over Threshold) — thay vì ngưỡng cố định (dễ gây false positive/negative), suy ngưỡng cảnh báo từ phân phối đuôi (tail distribution) của anomaly score theo thời gian thực — đúng mô típ đã dùng trong nhiều nghiên cứu multivariate time-series anomaly detection uy tín, khớp hướng lab HUST đang làm.

**Output:** anomaly score + quyết định (bình thường/bất thường) cho từng agent/hành động.

---

### Lớp 4 — Response

- **MVP (giai đoạn thesis + portfolio):** chỉ alert — webhook, log có cấu trúc, hoặc gửi Slack. Đơn giản, đủ để chứng minh luận điểm, không rủi ro gây gián đoạn hệ thống thật.
- **v2 (giai đoạn product, sau khi có design partner):** tích hợp Tetragon Enforcement (tự chặn/kill process) hoặc Kubernetes Admission Webhook (chặn hành động trước khi xảy ra) — chỉ làm khi đã đủ tin cậy vào độ chính xác của Lớp 3, vì enforcement sai (false positive) có thể tự tay gây ra đúng sự cố kiểu Replit đã nêu ở Mục Pain.

---

### Lớp 5 — Product (Enterprise, trả phí)

- Dashboard tập trung, Helm chart cài đặt dễ, quản lý đa cụm/đa cloud, tính năng compliance/audit.
- Đây là phần **duy nhất không cần cho thesis**, chỉ cần khi thương mại hoá.

---

## Ranh giới Open Source vs Enterprise (open-core, khớp Mục 4 Business Model)

| Lớp | Open Source (core) | Enterprise (trả phí) |
|---|---|---|
| 1. Data Collection | ✅ Toàn bộ | — |
| 2. Graph Construction | ✅ Toàn bộ | — |
| 3. Anomaly Detection | ✅ Model cơ bản | Model tinh chỉnh riêng theo dữ liệu khách hàng |
| 4. Response | ✅ Alert (MVP) | Enforcement nâng cao, tích hợp SIEM |
| 5. Product | — | ✅ Toàn bộ |

---

## Phạm vi: Thesis vs Portfolio vs Product

| | Thesis (HUST) | Portfolio (Phần B) | Product (bán được) |
|---|---|---|---|
| Lớp 1-3 (core engine) | ✅ Bắt buộc | ✅ Bắt buộc | ✅ Bắt buộc |
| So sánh baseline học thuật, viết luận văn | ✅ Chỉ ở đây | — | — |
| README, demo video, CNCF Sandbox | — | ✅ Chỉ ở đây | ✅ (kênh phân phối) |
| Chạy ổn định ngoài cluster 3-node, Helm chart | Không cần | Nên có | ✅ Bắt buộc |
| Có khách hàng thật dùng | Không cần | Không cần | ✅ Bắt buộc |

---

## Trình tự build (không làm cả 5 lớp cùng lúc)

Khớp North Star Metrics (file Founder Manifesto):

1. **2026:** Lớp 1 (custom eBPF/C nhận diện MCP call qua uprobe SSL) — commit đầu tiên, đây là phần khó nhất và cũng là phần chứng minh kỹ năng thật (Phần A2).
2. **Đầu 2027:** Lớp 2 (graph construction) + Lớp 3 bản đơn giản (có thể bắt đầu bằng thuật toán baseline dễ hơn GAT để có kết quả sớm, nâng cấp lên GAT+EVT-POT sau) → đủ để nộp CNCF Sandbox + MVP public.
3. **Giữa 2027:** Lớp 3 hoàn chỉnh (GAT+EVT-POT) — đây là phần thesis defense cần nhất.
4. **2028:** Lớp 4 (alert) hoàn thiện + bắt đầu Lớp 5 (dashboard tối giản) khi có design partner đầu tiên — không xây Lớp 5 trước khi có người thật muốn dùng.

---

## Rủi ro kỹ thuật cần lưu ý sớm

- **TLS/mã hoá:** đã nêu ở Lớp 1 — nếu không hook uprobe SSL, toàn bộ hệ thống vô dụng với traffic HTTPS. Cần thiết kế và test việc này sớm nhất, đây là rủi ro lớn nhất của toàn bộ kiến trúc.
- **Hiệu năng GAT real-time:** inference GAT cho từng sự kiện riêng lẻ sẽ quá chậm — cần batch/window theo chu kỳ (10-30 giây), không phải per-event.
- **Quản lý trạng thái đồ thị:** agent chạy lâu dài sẽ làm graph phình to nếu không giới hạn sliding window — cần chốt chính sách prune/expire dữ liệu cũ ngay từ đầu, không để tới lúc production mới xử lý.
- **Explainability cho hội đồng thesis:** GAT là mô hình khó giải thích hơn LSTM Autoencoder cũ — nên chuẩn bị sẵn phần visualize attention weight (thư viện PyG hỗ trợ sẵn) để hội đồng thấy được "vì sao mô hình cho là bất thường", không chỉ đưa ra con số.
