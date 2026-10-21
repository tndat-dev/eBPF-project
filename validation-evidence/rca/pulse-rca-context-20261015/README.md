# Bằng chứng triển khai nhánh RCA thứ ba

Nguồn: SSH `.234`, **15/10/2026 lúc 11:06 UTC+7**. Không phải số liệu kỳ vọng.

- [runtime-receipt.json](runtime-receipt.json): status subscriber, case count,
  unit properties, model/policy hash, tiến độ Pulse/syscall và cursor trước/sau
  restart riêng RCA. Source `2027dc8`; Pulse/study không bị restart.
- [real-case.json](real-case.json): cây thực tế từ
  `inventory-service-695bf6f445-ttlgj`, case `87ab07911c7413268acae4f4`;
  **99 connect attempt**, 10 process, 5 parent và 3 đích.
- [real-case-connect-edges.jsonl](real-case-connect-edges.jsonl): 99 input edge
  chuẩn hóa lấy từ SQLite ring, cùng hash tham chiếu trong cây. Không có argv
  hoặc request payload. Raw Tetragon protobuf/JSON không được persist bởi
  subscriber; raw_event_sha256 là hash event lúc nhận, không phải hash dòng
  normalized. Không giả vờ có raw replay corpus trong folder này.

Sample được chọn vì có nhiều connect context nhất trong 52 case tại snapshot,
để minh họa output; **không** dùng để đánh giá chất lượng hoặc chọn ngưỡng.
Trigger `candidate_alert_preview=true`, `alert=false`, `policy_applied=false`.
Đây là cây bằng chứng tương quan, không chứng minh inventory-service bị attack
hay process nào là root cause. `connect` entry không xác nhận kết nối thành công.

Cây lấy context 30 giây trước + 5 giây sau window_end. Receipt ghi tuổi
inventory, subscriber lag và coverage. `subscription_started_before_pre_window`
không bảo đảm stream tuyệt đối không mất event. Subscriber chỉ lấy connect
detail từ pod được policy chọn; ba stream mở không đồng nghĩa mọi workload
đều có event hoặc đầy đủ tree. Không có đo transport loss chính xác.

Case local trên VM bị retention 500 case; bản sao tại đây và input edge đã
được giữ trong Git để không mất sample theo vòng retention.

Kiểm tra integrity và join:

```bash
cd validation-evidence/rca/pulse-rca-context-20261015
sha256sum -c SHA256SUMS
```
