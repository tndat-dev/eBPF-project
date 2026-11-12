# Nghiên cứu thiết kế mô hình token trên LID-DS 2021 development và CB-DS (12/11/2026)

Protocol `sentinel_pulse/protocol/token-design-study-v1.json` + amendment 1 (đăng ký 11/11 16:36 và 16:46, trước mọi lượt chạy).
Code `scripts/analysis/lidds_token_cache.py`, `lidds_token_study.py`, runner `scripts/lidds_token_study_run.sh`, source aba31b2.
Unit `token-study` trên `.234`, 12/11 08:11–09:48 (+07), 8 h 32 min CPU, trần 30 GB.

Dữ liệu: training, validation và phần development của test (544 bản ghi tấn công, 3.403 normal); CB-DS. Phần official không được
đọc. Cache: 10.572 bản ghi, 1.862,95 triệu sự kiện thành 182,5 triệu dòng (cửa sổ, 6-gram fact), 828 MB.

Mọi con số dưới đây là **development** (đã nhìn nhiều lần, có nhãn tấn công).

## Cổng (`gate.json`): đạt

- Điểm cửa sổ của `select1f` tính qua cache bằng điểm cross-fit đã lưu (`ml-xfit-tokens`) ở cả 16 kịch bản, 10.572 bản ghi; lệch lớn
  nhất 2,8 × 10⁻¹⁴.
- Quyết định tái lập `lidds-ml-v5`: development 530/544, 6 báo nhầm, p95 1,52 s; CB-DS 891/891, 3 báo nhầm.

## Q1 (`q1.json`): 39 syscall có hook

**Bỏ từng syscall** (syscall đó chỉ còn tên). 8 trong 39 không xuất hiện trong dữ liệu (`creat`, `openat2`, `preadv`, `pwritev`,
`readv`, `recvmmsg`, `renameat`, `splice`). Trong 31 còn lại, 7 làm đổi kết quả:

| Bỏ | Phát hiện (so với 530) | Báo nhầm (so với 6) | Ở đâu |
|---|---|---|---|
| `write` | 490 (−40) | 6 | CVE-2019-5418 −36, ZipSlip −4; p95 2,22 s |
| `open` | 526 (−4) | 6 | ZipSlip −4 |
| `read` | 528 (−2) | 7 (+1) | ZipSlip −2; p95 2,23 s |
| `pread` | 529 (−1) | 6 | ZipSlip −1 |
| `recv` + `recvfrom` | 530 | 9 (+3) | |
| `send` + `sendto` | 530 | 7 (+1) | |
| `stat` | 530 | 7 (+1) | |

24 syscall còn lại: bỏ riêng từng cái không đổi phát hiện, báo nhầm hay CB-DS.

**Tập con nhỏ nhất** (loại lùi một lượt theo thứ tự đã đăng ký, rồi lặp tới khi không bỏ được nữa; 36 lần chấm): bỏ được 26 unit, còn
**5: `open`, `read`, `recv` + `recvfrom`, `stat`, `write`**. Tập này cho 530/544, 6 báo nhầm, p95 1,52 s, CB-DS 891/891 với 3, giống
`select1f` ở từng kịch bản. Không unit nào trong 5 bỏ được nữa (`stat`: p95 1,57 s; `recv`: 9 báo nhầm; `read`: 7 báo nhầm, p95 2,22 s;
`open`: 526; `write`: 486). Đây là tập không bỏ thêm được unit nào, không phải cực tiểu toàn cục đã chứng minh.

**Thêm từng syscall** (13 ứng viên có dữ liệu): mã lỗi của `accept`, `clone`, `epoll_wait`, `lseek`, `nanosleep`, `poll`, `select`,
`setsockopt`; cỡ trả về của `getdents`, `getdents64`, `poll`, `epoll_wait`, `select`. Không ứng viên nào tăng phát hiện: 9 không đổi gì,
`getdents64` chỉ làm p95 thành 1,55 s, `epoll_wait` (cỡ) thêm 1 báo nhầm, `getdents` và `poll` (cỡ) mất 1 bản ghi ZipSlip. `sendto` và
`recvmsg` đã nằm trong 39. Trong toàn bộ dữ liệu chỉ 31/142 tên syscall từng trả lỗi.

Theo protocol: `select1f` giữ nguyên; tập 5 syscall được chấm một lần trên official như một lần tái dùng đã khai (kết quả ở
`official-smallest-subset.json` khi có).

## Q2 (`q2.json`): tham số, đổi từng cái một

| Tham số | Giá trị: phát hiện / báo nhầm / p95 (đang dùng in đậm) |
|---|---|
| Độ dài gram n | 2: 458 / 3 / 2,06 · 3: 530 / 8 / 1,66 · **4: 530 / 6 / 1,52** · 5: 526 / 6 / 1,75 · 6: 493 / 6 / 2,19 |
| Số giá trị lấy trung bình | 1: 123 / 7 / 3,46 · 3: 528 / 5 / 1,58 · 5: 529 / 7 / 1,49 · **10: 530 / 6 / 1,52** · 20: 492 / 7 / 2,27 |
| α′ | 0,01: 531 / 51 · 0,003: 530 / 25 · 0,001: 530 / 15 · 0,0005: 530 / 10 · **0,00018: 530 / 6** · 0,0001: 527 / 6 · 0,00005: 525 / 6 |
| Số fold | 3: 530 / 7 / 1,67 · **5: 530 / 6 / 1,52** · 10: 530 / 7 / 1,51 |
| Phần cực đại bỏ đi | 0: 523 / 4 · 0,5%: 524 / 6 · **1%: 530 / 6** · 2%: 530 / 9 · 5%: 530 / 15 |

CB-DS là 891/891 ở mọi điểm trừ top = 1 (0/891). Bộ đang dùng nằm ở điểm tốt nhất của từng trục (đúng như mong đợi, vì nó được chọn
trên chính dữ liệu này); quanh nó kết quả phẳng: n = 3, top = 3–5, fold 3–10, α′ 0,0005–0,003 giữ 528–530 với báo nhầm 5–25. Kết quả
hỏng ở các cực: top = 1 (một sự kiện lạ đơn lẻ không đủ), top = 20, n = 2, n = 6. Không chọn lại gì từ bảng này.

## Q3 (`q3.json`): Gumbel có đúng không

- **Không đúng như một phân bố.** Kiểm Anderson–Darling bác Gumbel ở 15/15 kịch bản sau hiệu chỉnh Holm (p ≤ 0,023). Hình dạng GEV
  ước lượng ξ từ −0,28 tới +0,77: 10 kịch bản có ξ âm (đuôi nhẹ hơn Gumbel), EPS (0,77) và ZipSlip (0,46) có đuôi nặng hơn nhiều.
- **Mức α′ không được giữ.** Trên 3.403 bản ghi normal development (ngoài mẫu): α′ = 0,01 kỳ vọng 34,0, thấy 51 (1,5 lần); 0,001: 3,4
  so với 15 (4,4 lần); 0,00018: 0,61 so với 6 (9,8 lần); 0,00005: 0,17 so với 6 (35 lần). Có một sàn 6 bản ghi không hạ được bằng α′.
- **Cùng ngưỡng viết cách khác:** τ = trung bình + k × độ lệch chuẩn của các cực đại đã bỏ 1%, với k = 6,27 ở α′ = 0,00018 (3,14 ở
  0,01; 7,27 ở 0,00005). α′ chỉ là cách đánh số cho k.
- **Vẫn là quy tắc không nhãn tốt nhất đã thử.** Phát hiện nhiều nhất với báo nhầm ≤ 6 / ≤ 12 / ≤ 20:
  quy tắc đang dùng 530 / 530 / 530; moment trên mọi cực đại 525 / 530 / 530; Gumbel hợp lý cực đại 495 / 530 / 530; phân bố chuẩn
  525 / 530 / 530; GEV hợp lý cực đại không có điểm nào ≤ 6, 459 / 496; cực đại giữ ra lớn nhất (hay thống kê thứ tự conformal): 497 với
  13 báo nhầm, không có điểm nào ≤ 12.

## Q4 (`q4.json`): mô hình hay luật đếm 4-gram chưa thấy

Cùng cross-fit, cùng quy tắc ngưỡng, cùng quyết định một cửa sổ; điểm của luật là số sự kiện có 4-gram chưa thấy trong cửa sổ.

| Ngân sách báo nhầm (bản ghi) | Mô hình | Luật đếm 4-gram chưa thấy |
|---|---|---|
| ≤ 3 | 472 | không có điểm nào |
| ≤ 6 | 530 | 444 |
| ≤ 12 | 530 | 488 |
| ≤ 20 | 530 | 497 |
| ≤ 34 | 531 (26 báo nhầm) | 526 (30 báo nhầm) |

- Ở ngân sách 6: mô hình hơn 86 bản ghi, CI 95% bootstrap ghép cặp [80; 93]. Ở mức đã đăng ký (α′ = 0,00018): mô hình 530 / 6, luật
  493 / 14. Luật đếm "4-gram hoặc token chưa thấy" cho đúng cùng số với luật 4-gram.
- **Mô phỏng tấn công chỉ dùng chuỗi đã thấy:** bỏ khỏi mỗi bản ghi tấn công mọi dòng có gram chưa thấy (ở chính độ dài của nó) hoặc
  token chưa thấy, giữ ngưỡng đã đăng ký: mô hình phát hiện **0/544** (trước khi bỏ: 530). Luật đếm cho 0 theo định nghĩa. Trên normal,
  cùng phép bỏ đưa báo nhầm từ 6 về 0. Tức là mọi phát hiện của mô hình trên dataset này dựa vào chuỗi chưa thấy; phần hơn của mô hình
  so với luật đếm là chấm được *mức độ* lạ (4-gram mới ghép từ các bước quen so với token chưa từng có), không phải thấy được bất
  thường về tần suất của chuỗi quen. Đây là cận dưới bán tổng hợp: bỏ sự kiện không phải một exploit thật.
- Ghi chú: một phép so trước đó (05/11, bảng chữ cũ, ngưỡng trên 60 bản ghi validation, hai luật ghép OR) cho hai bên ngang nhau
  (luật 530 / 14, mô hình 529 / 22). Phép so ở đây dùng đúng quy trình của hệ thống hiện tại.

## Điều rút ra

1. Tín hiệu trên LID-DS nằm ở rất ít syscall: cỡ của `write` (CVE-2019-5418), đường dẫn và mã lỗi của `open`, cỡ của `read` và `pread`.
   34/39 hook không cần cho kết quả development và CB-DS. Tập 39 không phải tối ưu; nó là một tập đủ, rộng hơn cần thiết.
2. Bộ tham số không nằm trên một đỉnh nhọn, trừ số giá trị lấy trung bình (phải từ 3 tới 10) và n (3 hoặc 4).
3. Gumbel chỉ là cách đặt k trong "trung bình + k độ lệch chuẩn"; không được diễn giải α′ như tỉ lệ báo nhầm.
4. Mô hình hơn luật đếm rõ rệt ở báo nhầm thấp, nhưng cả hai đều mù với tấn công không tạo chuỗi mới.
