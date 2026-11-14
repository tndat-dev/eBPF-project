# pulse-live-lidds: giao diện phát hiện (detection interface)

Tài liệu phòng thủ, đi kèm `pulse_live_lidds.md`. Mỗi kịch bản LID-DS 2021 được mô tả bằng **hành vi quan sát được** mà
hệ thống phát hiện cần thấy — *cái cần phát hiện*, không phải *cách thực hiện tấn công*. Không chứa payload, lệnh khai
thác, PoC hay địa chỉ C2. Dùng để đánh giá và giải thích detector (token model + RCA/Tetragon), và để viết đồ án.

## 1. Detector thấy gì

Hệ thống học **normal** của mỗi dịch vụ rồi báo khi hành vi runtime lệch khỏi normal đó. Hai nguồn tín hiệu:

- **Token model (eBPF):** mỗi syscall của tiến trình dịch vụ thành một token mang *tên syscall + chi tiết* (mã lỗi, cỡ
  đọc/ghi trả về, chế độ mở + thư mục đầu). Mô hình ngôn ngữ đếm 4-gram theo thread; một cửa sổ 0,5 s bị báo khi độ bất
  ngờ (−ln xác suất) của các chuỗi trong đó cao so với normal đã học. Tức detector nhạy với **token lạ** (một mã lỗi, cỡ,
  đường dẫn chưa từng thấy) và **chuỗi lạ** (4-gram chưa từng thấy) trong tiến trình dịch vụ.
- **RCA/Tetragon (bối cảnh):** sự kiện `PROCESS_EXEC`, `PROCESS_EXIT`, kết nối mạng — dùng để dựng cây bằng chứng và quy
  nguyên nhân cho một cảnh báo, không nằm trong đường quyết định của ML.

**Dòng dõi (lineage):** mỗi thread được gắn *native* (thuộc cây tiến trình của chính dịch vụ) hay *session* (vào qua
runtime exec). Khai thác **trong tiến trình dịch vụ** biểu hiện trên dòng **native**; đây là điểm phân biệt với một phiên
quản trị vô hại đi vào qua `kubectl exec` (dòng session).

## 2. Signature quan sát được theo kịch bản

Cột "Tín hiệu quan sát được" là *biểu hiện ở telemetry* mà detector dựa vào — mô tả phòng thủ, không phải hướng dẫn tấn
công. "Dòng" cho biết tín hiệu nằm ở native hay session.

| Kịch bản (dịch vụ) | Lớp lỗi | Tín hiệu quan sát được (cái cần phát hiện) | Dòng |
|---|---|---|---|
| CVE-2014-0160 (OpenSSL/Heartbleed) | lộ bộ nhớ | Phản hồi **lớn hơn hẳn yêu cầu**: tiến trình đọc một bản tin nhỏ (token cỡ đọc nhỏ) rồi ghi/truyền lặp lại các khối lớn (token cỡ ghi lớn) — tỉ lệ ghi/đọc bất thường trong cùng thread | native |
| CVE-2017-7529 (Nginx) | tràn số nguyên vùng đọc | Đọc file với **cỡ/offset bất thường** so với phục vụ tĩnh thường thấy (token cỡ đọc lạ, chuỗi lseek/read lạ) | native |
| ZipSlip | ghi ra ngoài thư mục | **Mở để ghi một đường dẫn ngoài thư mục làm việc quen** (token `open:w:<thư mục lạ>`, ví dụ ghi vào `/etc` khi normal chỉ ghi trong thư mục giải nén) | native |
| CVE-2019-5418 / CVE-2018-3760 (Rails) | đọc file tuỳ ý / path traversal | **Mở để đọc file ngoài cây tài nguyên của ứng dụng** (token `open:r:<thư mục hệ thống>` chưa từng thấy) kèm ghi phản hồi cỡ lạ | native |
| CVE-2017-12635_6 (CouchDB) | RCE | Tiến trình dịch vụ **sinh tiến trình con bất ngờ** (execve một binary không thuộc hành vi dịch vụ) và/hoặc **kết nối ra ngoài** chưa từng có; ở token là chuỗi syscall dựng tiến trình/kết nối lạ trong thread của dịch vụ | native |
| CVE-2020-13942 (Apache Unomi) | RCE qua biểu thức | Như trên: **tiến trình con/thao tác hệ thống bất ngờ** từ tiến trình Java của dịch vụ (execve, kết nối) — lệch khỏi normal chỉ gồm xử lý HTTP/lưu trữ | native |
| CVE-2020-9484 (Tomcat) | giải tuần tự hoá độc | **Chuỗi syscall giải tuần tự hoá/thao tác file-tiến trình bất thường** trong tiến trình Java; có thể kèm sinh tiến trình con | native |
| CVE-2020-23839 | XSS lưu trữ dẫn tới thao tác phía máy chủ | Khi tải trọng lưu trữ được kích hoạt, dịch vụ thực hiện **thao tác hệ thống ngoài luồng phục vụ trang** (đọc file nhạy cảm, sinh tiến trình) — biểu hiện token/chuỗi lạ | native |
| CWE-89-SQL-injection / PHP_CWE-434 (DVWA) | SQLi / upload | **Thao tác file hoặc tiến trình bất thường do một request** (ví dụ ghi/đọc file ngoài thư mục upload quen, hoặc sinh tiến trình con) — token đường dẫn/cỡ hoặc chuỗi lạ. *Lưu ý giới hạn:* SQLi thuần chỉ đổi ngữ nghĩa truy vấn trong tiến trình, có thể **không** để lại dấu ở tầng syscall (xem §3) | native |
| EPS_CWE-434 | upload file độc | **Ghi một file vào vị trí bất thường** rồi có thể **thực thi** nó (token mở-ghi đường dẫn lạ, sau đó execve một tiến trình con mới) | native |
| Juice-Shop | SQLi ở ứng dụng Node | Tương tự DVWA: nếu khai thác dẫn tới thao tác hệ thống thì thấy token/chuỗi lạ; nếu chỉ đổi ngữ nghĩa truy vấn thì có thể không để lại dấu syscall (giới hạn §3) | native |
| Bruteforce_CWE-307 | thử đăng nhập hàng loạt | **Tần suất/khối lượng xử lý request đăng nhập tăng đột biến** và/hoặc chuỗi xử lý lỗi xác thực lặp lại khác thường so với normal | native |

## 3. Giới hạn phát hiện (ghi cho đồ án)

- **Tấn công không tạo hành vi hệ thống mới** không hiện ở tầng syscall. Ví dụ SQLi thuần (DVWA, Juice-Shop loại
  `SQLInjectionUser`) chỉ đổi *ngữ nghĩa câu truy vấn* bên trong tiến trình đã chạy, đi tới đúng endpoint mà người dùng
  bình thường gọi, không sinh tiến trình/đường dẫn/cỡ đọc-ghi mới. Detector chỉ đọc syscall sẽ không thấy; cần lớp bổ trợ
  ở tầng ứng dụng (WAF, RASP, giám sát câu truy vấn ở driver CSDL). Đây là giới hạn phương pháp, đã nêu ở chương thảo luận.
- **Tấn công chỉ dùng chuỗi đã thấy** (mô phỏng): nếu kẻ tấn công ghép lại các chuỗi syscall đã có trong normal, token
  model (dựa vào chuỗi lạ) không phát hiện. Hướng bù: tín hiệu tần suất của gram quen (đang nghiên cứu, chưa chốt).
- **Process vô hại mới vẫn bị gắn cờ:** mọi tiến trình mới vào container đều "lạ" với mô hình theo workload. Thẻ dòng dõi
  giúp tách phiên quản trị (session) khỏi dịch vụ (native); khai thác trong tiến trình dịch vụ nằm ở native nên vẫn phát
  hiện được, còn phiên quản trị vô hại ở session được xử lý riêng.

## 4. Chỉ số đánh giá (khớp protocol pulse-live-lidds-v1)

Với mỗi kịch bản: **recall** = tỉ lệ chu kỳ có khai thác mà detector báo trong cửa sổ `[thời điểm khai thác, +30 s]`;
**báo nhầm** = chu kỳ bình thường có cảnh báo; **độ trễ** từ sự kiện kernel đầu tiên tới cuối cửa sổ báo; **tỉ lệ session
của cảnh báo** (gần 0 xác nhận phát hiện trên dòng native của dịch vụ). Số liệu thực đo ở
`validation-evidence/results-*/pulse-live-lidds/`.
