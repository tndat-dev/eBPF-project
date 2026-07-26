# Founder Manifesto

## Founder Thesis

```
Tôi tin rằng:

AI Agent sẽ trở thành lực lượng lao động số —
không chỉ chatbot, mà thực thể có quyền hành động
thật trong hệ thống doanh nghiệp.

        ↓

Mỗi AI Agent có quyền hành động thật đều cần một
lớp Runtime Security độc lập — quan sát nó THỰC SỰ
làm gì, không chỉ nó ĐƯỢC YÊU CẦU làm gì.

        ↓

Cloud-native / Kubernetes là môi trường mặc định
nơi AI Agent vận hành.

        ↓

Tôi muốn xây công ty sở hữu lớp Runtime Security đó
— bắt đầu từ Kubernetes, nơi tôi có lợi thế kỹ thuật
thật: eBPF, Cilium, Tetragon.
```

**Làm rõ 3 lớp (để không bị mơ hồ về sau):**

| Lớp | Vai trò | Có đổi không? |
|---|---|---|
| **eBPF** | Core competency — thứ khó copy nhất, bền vững nhất | Không đổi |
| **Kubernetes** | Beachhead — nơi bắt đầu vì có sẵn lợi thế + thị trường đã chín (Cilium/Tetragon/Isovalent) | Có thể mở rộng sang VM/serverless sau này |
| **AI Agent** | Market wedge — lý do khách hàng trả tiền NGAY, vì generic K8s security đã có Falco/Sysdig chiếm chỗ | Là điểm vào, không phải giới hạn vĩnh viễn |

Trả lời gọn khi ai hỏi "công ty bạn về cái gì": **eBPF-based runtime security, bắt đầu từ Kubernetes, mở đường bằng AI Agent.**

---

## Decision Principles

- Không chase trend — bám thesis
- Không build B2C — chỉ B2B Infrastructure
- Ưu tiên Infrastructure hơn Application layer
- Ưu tiên Open Source hơn Closed Source
- Ưu tiên Global Market hơn chỉ Việt Nam/SEA
- Ưu tiên Recurring Revenue hơn consulting/dự án một lần
- Ưu tiên vốn hiệu quả hơn tăng trưởng giả bằng tiền đốt
- Không bán Enterprise/Bank trước khi có Product-Market-Fit
- Nói KHÔNG nhiều hơn nói CÓ

---

## North Star Metrics

**Đo bằng Create, không đo bằng Study.**

| Năm | Cột mốc |
|---|---|
| **2026** | Kiểm tra hợp đồng SVTECH (IP assignment) · Liên hệ lab HUST, chốt đề cương Nghiên cứu · Tốt nghiệp AIMS · CKS · IELTS/TOEFL đạt điểm · Nộp hồ sơ HUST (Mức 1) + Đức + Erasmus Mundus + Knight-Hennessy · 2 blog · Flagship Lớp 1 (custom eBPF/C nhận diện MCP): commit đầu tiên · 5 Open Source PR |
| **2027** | Nhập học Master's (HUST hoặc phương án đỗ khác) · Flagship: đủ 3 lớp (eBPF+Tetragon → Graph → GAT+EVT-POT), MVP public + nộp CNCF Sandbox · 1 KubeCon CFP · 20-30 cuộc customer discovery · GitHub 5 dự án |
| **2028** | Design partner đầu tiên · ~100 users cộng đồng · Doanh thu đầu tiên (dù nhỏ) |
| **2029** | Tốt nghiệp Master's · 10 khách hàng trả tiền · Quyết định Big Tech offer vs full-time startup |
