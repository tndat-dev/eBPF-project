# Trạng thái đồ án Sentinel Pulse

Cập nhật **18/10/2026** từ SSH vào cụm (giờ UTC+7 trừ khi ghi UTC). Đây là báo cáo
duy nhất được cập nhật; việc cần làm nằm ở [../TODO.md](../TODO.md).

## 1. Tóm tắt một trang

- **Đồ án làm gì:** đếm syscall của từng container Kubernetes bằng eBPF, mỗi 0,5 giây
  tạo một vector 249 số, model học trên dữ liệu bình thường chấm điểm "lạ hay không".
  Khi có tín hiệu, một dịch vụ riêng dựng đồ thị bằng chứng (process, file, mạng) để điều tra.
- **Đang ở đâu:** pipeline chạy được end-to-end trên 3 worker thật, ở chế độ shadow
  (chỉ ghi "cảnh báo thử", không cảnh báo thật, không cách ly pod).
- **Kết quả mới nhất:** phát hiện tốt (recall ~98–99% trên tập attack phát triển,
  độ trễ p95 ~1,6 s) nhưng **cảnh báo nhầm quá nhiều**: precision 79,8% trong thiết kế
  1:1, khoảng 8% cửa sổ của dữ liệu bình thường bị gắn cờ (mức thiết kế 0,17%), và
  ~19–20 đợt cảnh báo mỗi workload-giờ so với ngân sách 0,1.
- **Kết luận chính:** nút thắt là **hiệu chỉnh ngưỡng (calibration) không theo kịp
  dữ liệu bình thường thay đổi**, không phải model thiếu nhạy. Chưa đạt kỳ vọng
  precision/recall ≥ 95%, tỷ lệ cảnh báo nhầm theo khoảng ≤ 5%, p95 ≤ 2 s.
- **Phiên 18/10:** dọn và tổ chức lại code; thu kết quả soak 48 giờ và holdout R4;
  chạy nghiên cứu "xác nhận nhiều cửa sổ" và "hiệu chỉnh lại p-value" trên dữ liệu phát triển.

## 2. Thuật ngữ (giải thích ngắn)

| Thuật ngữ | Nghĩa trong đồ án |
|---|---|
| syscall | Lời gọi hệ thống, ví dụ `read`, `connect`, `execve` |
| eBPF | Chương trình nhỏ chạy trong kernel; ở đây dùng để đếm syscall theo cgroup |
| cgroup / resolver | Nhóm tài nguyên của một container / tiến trình ánh xạ pod → container → cgroup |
| cửa sổ (window) | Khoảng 0,5 giây; mỗi container có một vector đặc trưng cho mỗi cửa sổ |
| vector 249 số | Số lần gọi 29 syscall chính, tỷ lệ, nhóm băm syscall khác, cặp syscall liền nhau, trung bình/độ lệch trượt |
| ngữ cảnh (context) | 3 cửa sổ trước + cửa sổ hiện tại = 996 số đưa vào model |
| ExtraTrees | Họ cây quyết định ngẫu nhiên (không phải deep learning) |
| nhánh support | Model phụ phát hiện giá trị nằm ngoài vùng từng thấy khi bình thường |
| p-value (conformal) | Điểm của cửa sổ so với điểm của dữ liệu bình thường dùng để hiệu chỉnh; p nhỏ = hiếm gặp. Chỉ đúng nghĩa khi dữ liệu lúc chạy giống dữ liệu hiệu chỉnh |
| alpha | Ngưỡng p; hiện là 0,05/30 ≈ 0,00167 cho mỗi cửa sổ |
| cảnh báo thử (preview) | Cờ `candidate_alert_preview=true`: tín hiệu để đánh giá, **không phải** cảnh báo vận hành |
| đóng băng (freeze) | Khóa code, model, ngưỡng bằng SHA-256 để không trộn phiên bản khi đánh giá |
| soak | Chạy liên tục nhiều giờ trên tải bình thường để đo độ ổn định và cảnh báo nhầm |
| development / blind | Dữ liệu đã nhìn khi phát triển / dữ liệu mới chưa từng dùng để chỉnh — chỉ kết quả blind mới dùng để kết luận |
| holdout | Dữ liệu để riêng không dùng để fit |
| cặp attack/control | Mỗi lượt gồm 15 s đối chứng (không làm gì) và 15 s chạy binary mô phỏng tấn công trên cùng container |
| TP / FN / FP / TN | Bắt đúng / bỏ sót / báo nhầm / im lặng đúng; "FP kỳ vọng" vì control chưa được review nhãn |
| unknown | Thiếu dữ liệu hoặc bằng chứng nên không chấm; không bao giờ tự đổi thành TN/FN |
| đợt cảnh báo (episode) | Các cửa sổ dương của một container cách nhau < 15 s gộp thành một đợt |
| xác nhận k-of-n | Chỉ báo khi ít nhất k trong n cửa sổ liên tiếp vượt ngưỡng |
| hiệu chỉnh lại (recalibration) | Tính lại p-value bằng tập dữ liệu bình thường gần hơn, không đổi model |
| cấu hình syscall (arm) | Một biến thể bộ đặc trưng: giữ 29 syscall, thêm hoặc bớt nhóm syscall |
| RCA | Điều tra nguyên nhân gốc; ở đây mới là đồ thị bằng chứng liên quan, chưa chứng minh nhân quả |

## 3. Kiến trúc

```mermaid
flowchart LR
    K[eBPF đếm syscall theo cgroup] --> C[collector: vector 249 số / 0,5 s]
    C --> D[detector: ExtraTrees + support → p-value]
    D --> P[chính sách: p ≤ alpha → cảnh báo thử]
    P --> R[rca: ghép sự kiện Tetragon → đồ thị bằng chứng]
    A[attack: cặp attack/control trên pod thật] -.đo.-> P
    S[syscall_study: so sánh bộ syscall, chạy offline] -.đề xuất bộ đặc trưng.-> C
```

Mỗi workload/container có model riêng (21 key trong namespace `production` của ứng dụng
AIMS). Code: [../sentinel_pulse/README.md](../sentinel_pulse/README.md).

## 4. Trạng thái cụm (11:30 ngày 18/10)

| Thành phần | Trạng thái |
|---|---|
| Soak Pulse 48 giờ (3 worker) | **Đã kết thúc bình thường** 17/10 00:56–01:06; `NRestarts=0` |
| Chấm holdout R4 (thí nghiệm syscall) | **Đã kết thúc** 16/10 13:03; 147 segment |
| RCA subscriber (`pulse-rca-runtime-events`, .234) | Vẫn chạy nhưng **không có tín hiệu mới** từ khi Pulse dừng; RAM ~966 MB / giới hạn 1 GB |
| Collector + resolver trên worker | Chạy (luồng đối chứng 1 s, có xoay vòng hằng ngày) |
| Detector v8 cũ (`sentinel-detector`) | Vẫn chạy dry-run trên .234 và worker1 từ 01/10 (~750 MB) — đề xuất dừng |
| Job nghiên cứu 18/10 | `pulse-confirmation-normal-*`, `pulse-recalibration-study-c1-20261018` trên .234 |
| NFS `/mnt/sentinel-pulse-archive` | 242/344 GB dùng (71%) |

## 5. Kết quả

### 5.1 Soak 48 giờ của candidate đóng băng (dữ liệu bình thường, chưa review nhãn)

| Worker | Cửa sổ đã chấm | Cảnh báo thử | Tỷ lệ | Issue ghi nhận |
|---|---:|---:|---:|---:|
| worker1 (.237) | 9.011.856 | 673.825 | 7,5% | 146 |
| worker4 (.238) | 8.051.218 | 950.765 | 11,8% | 381 |
| worker3 (.239) | 4.408.203 | 90.161 | 2,0% | 65 |
| **Tổng** | **21.471.277** | **1.714.751** | **8,0%** | 592 |

Mỗi worker đủ 172.800 giây đăng ký. Model `747c4eed…`, chính sách `fd0be94a…`.
Nếu p-value đúng nghĩa, tỷ lệ cửa sổ dương trên dữ liệu bình thường phải quanh 0,17%;
thực tế cao gấp ~47 lần. Lưu ý soak có chứa các lượt R3/R5 và giai đoạn bật policy
Tetragon cho RCA (xem 5.5), nhưng các khoảng đó quá ngắn để giải thích tỷ lệ này.

### 5.2 Ma trận attack/control phát triển R3 + R5 (đã công bố, tái lập 18/10)

R3: 315 cặp (21 key × 5 kịch bản × 3 tốc độ), chạy 14/10 19:30 → 15/10 00:17 UTC.

| | Bắt được | Không bắt | Unknown |
|---|---:|---:|---:|
| Attack | TP 284 | FN 2 | 29 |
| Control | FP kỳ vọng 72 | TN kỳ vọng 237 | 6 |

Precision 79,8%, recall 99,3% (cận dưới tính cả unknown: 90,2%), control dương 23,3%,
kernel → cảnh báo thử p50/p95/p99 = 1,07 / 1,61 / 4,75 s. R5 (RabbitMQ, 15 cặp):
TP 13, FN 0, FP 1, TN 14, unknown 2. Đây là dữ liệu **phát triển**, không phải blind,
và tỷ lệ 1:1 nên precision này không phải precision vận hành.

### 5.3 Holdout R4 — thí nghiệm chọn syscall

693 model (21 key × 11 cấu hình × 3 seed) chấm trên 24 giờ dữ liệu bình thường sau khi
đóng băng: 500,8 workload-giờ hợp lệ, đủ 21 key.

| Cấu hình | Đợt cảnh báo / workload-giờ (3 seed) | TB |
|---|---|---:|
| plus_top16 | 16,97 · 18,10 · 20,57 | 18,55 |
| plus_top32 | 17,26 · 20,32 · 18,92 | 18,83 |
| base29 (hiện tại) | 19,77 · 20,17 · 18,48 | 19,47 |
| drop_exec_pair | 19,87 · 21,80 · 20,80 | 20,82 |

(Đủ 11 cấu hình trong evidence.) **Không cấu hình nào gần ngân sách 0,1 đợt/giờ**;
chênh lệch giữa cấu hình nhỏ hơn dao động giữa các seed, nên theo protocol v2 hiện **chưa
chọn được** bộ syscall cho Pulse. Thí nghiệm này chạy song song với Pulse và là đầu vào
chọn feature cho nó: mọi cải tiến ngưỡng/hiệu chỉnh của Pulse cần áp dụng lại cho cả 11
cấu hình trên cùng holdout để so sánh trong điều kiện cảnh báo nhầm thấp hơn.
Workload ồn nhất: Kafka (43,6/giờ), search-recommendation (38,6), istio waypoint (38,2).

### 5.4 Nghiên cứu xác nhận k-of-n (phát triển, 18/10)

Không đổi model; chỉ yêu cầu k trong n cửa sổ liên tiếp vượt ngưỡng (có thể kèm alpha chặt hơn).
Công cụ tái lập đúng ma trận R3/R5 với chính sách hiện tại trước khi thử chính sách khác.

| Chính sách (R3) | Precision | Recall | Control dương | p95 | p99 |
|---|---:|---:|---:|---:|---:|
| hiện tại (1 cửa sổ) | 79,8% | 99,3% | 23,3% | 1,61 s | 4,75 s |
| 2 of 2 | 87,3% | 98,3% | 13,3% | 2,25 s | 5,05 s |
| 3 of 4 | 89,8% | 98,3% | 10,4% | 2,91 s | 5,40 s |
| 4 of 6 | 90,6% | 98,3% | 9,4% | 3,42 s | 5,95 s |
| 1 cửa sổ, alpha/2 | 86,9% | 88,5% | 12,3% | 2,05 s | 5,05 s |
| 4 of 6, alpha/2 | 94,3% | 87,4% | 4,9% | 4,63 s | 7,75 s |

Xác nhận nhiều cửa sổ giảm một nửa control dương với chi phí ~1 điểm recall, nhưng làm
p95 vượt 2 s. Vì độ trễ kernel → cảnh báo là ràng buộc cứng (dưới 2 s, càng thấp càng
tốt), k-of-n chỉ là phương án phụ (tối đa 2 cửa sổ); hướng chính là hiệu chỉnh lại
p-value (5.5) vì không cộng thêm độ trễ. Siết alpha làm mất recall nhanh. **Không chính
sách nào đạt đồng thời cả bốn kỳ vọng.** Số đợt cảnh báo trên soak cho từng chính sách: *đang tính (xem 5.6)*.

### 5.5 Hiệu chỉnh lại p-value (phát triển, 18/10) — *đang chạy*

Thiết kế (đăng ký trước khi xem kết quả): tập hiệu chỉnh = điểm của dữ liệu soak
15/10 00:30–07:30 UTC (sau R3, trước can thiệp RCA, bỏ khoảng R5 03:00–03:25); kiểm tra
trên phần soak từ 15/10 08:40 UTC đến hết và trên R3/R5. Lưu ý: phần kiểm tra trùng
thời gian bật policy Tetragon cho RCA.

### 5.6 RCA

Run r2 từ 15/10 15:37: 19.152 case đã sinh (giữ 500 gần nhất theo cấu hình), 43,17 triệu
decision đã đọc. 19.142 case (99,9%) thiếu ngữ cảnh connect và 1.693 thiếu ngữ cảnh
runtime. Audit trước đây chỉ kiểm tra cấu trúc của 107 case; chưa có nhãn để đo độ đúng.
Đồ thị là bằng chứng liên quan theo thời gian/định danh, chưa chứng minh nhân quả.

## 6. Đánh giá thẳng

**Hướng đi đúng:** đếm syscall bằng eBPF rẻ và khó né; model riêng cho từng workload,
chỉ học từ dữ liệu bình thường; ngưỡng dựa trên p-value có cơ sở; RCA tách khỏi
đường phát hiện; kỷ luật thí nghiệm (đóng băng, tách phát triển/blind, giữ unknown) tốt.

**Điểm yếu cần xử lý:**

1. *Calibration không chịu được thay đổi của dữ liệu bình thường* (chế độ tải, revision,
   thời gian). Đây là nguyên nhân chính của cảnh báo nhầm.
2. *Quyết định trên một cửa sổ 0,5 s* không có gộp theo thời gian.
3. *Rủi ro thổi phồng recall:* mọi attack đều khởi chạy một binary mới; chưa có đối
   chứng "chạy binary vô hại", nên một phần phát hiện có thể chỉ là "có process mới".
   Đặc trưng chỉ là tần suất, không có tham số syscall.
4. *Đánh giá 1:1* không phản ánh precision vận hành khi tấn công hiếm.
5. *Quy trình nặng:* nhiều thế hệ thí nghiệm song song; công sức dồn vào quản trị
   thay vì cải thiện model.

## 7. Đồng bộ code (18/10)

| Nơi | Trạng thái |
|---|---|
| GitHub `experiment/syscall-id-histogram-pilot` | = `bb52293`, trùng local trước refactor |
| GitHub `main` | Nhánh chính: đã hợp nhất nhánh thí nghiệm, đợt tái cấu trúc và 2 commit tài liệu cũ của `main` (`22f365a`); từ nay push thẳng lên `main`, commit chỉ mang danh tính tndat-dev |
| GitHub tag `archive/pre-refactor-20261018` | Cây code đầy đủ trước đợt dọn 18/10 |
| Cụm `/home/dat/eBPF-project-current` | `bb52293`, sạch — trùng GitHub |
| Cụm `/home/dat/eBPF-project` | `main` cũ, chậm 14 commit, có sửa chưa commit |
| Cụm `/home/dat/eBPF-project-refactor-*` | Bản clone dùng cho các job nghiên cứu 18/10; thư mục mang tên mã commit trước khi viết lại message ngày 18/10 (`0117901` = `471bcf0` hiện tại, cùng nội dung code) |
| Service đang chạy | Dùng snapshot source đóng băng (`/opt/...`, NFS), không phụ thuộc checkout |

## 8. Lệnh kiểm tra

```bash
export LAB_SSH_PASSWORD=...   # mật khẩu lab
python3 scripts/ssh_lab.py --list
python3 scripts/ssh_lab.py --host 10.1.16.234 systemctl show pulse-rca-runtime-events.service -p ActiveState -p NRestarts
python3 scripts/ssh_lab.py --host 10.1.16.234 python3 -m json.tool \
  /mnt/sentinel-pulse-archive/matched-parallel-20261015/workers/k8s-worker1.local/TERMINAL.json
```

Kết quả nghiên cứu 18/10: `/mnt/sentinel-pulse-archive/confirmation-study-20261018/`,
bản sao nhỏ trong `validation-evidence/results-20261018/`.
