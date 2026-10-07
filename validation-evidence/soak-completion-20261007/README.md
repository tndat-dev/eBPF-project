# Bằng chứng cuối kỳ observation soak

Lấy chỉ đọc bằng SSH/SFTP từ `.234` ngày 07/10/2026 lúc 13:24 ICT. Campaign `pulse-observation-c1-20261006` hoàn thành lúc 12:42:20 ICT. Bản sao JSON giữ đúng bytes/checksum trên VM; không sửa raw seals hay adjudicate alert.

| File | SHA-256 từ VM, đã đối chiếu bản local |
|---|---|
| START.json | `10457f3f7f3823293258bf9fc8fcd1c14907cc29db68c232aca935f1a1be186f` |
| STATUS.json | `668105ece4e8160ab16edcd74efb7b2fcdf2f213edc4b62df559b4d057ae85d8` |
| TERMINAL.json | `03f86a54c3a2cc609607124be704ebf583844a5c878fe9ef4d034be590658ae3` |
| inspection.json | `cea262463b7a9ba5e082b9fb27a8536be64be4aaf7f3a810ca96f7542e9d02d2` |

21/21 workload đạt >=24 giờ exposure hợp lệ; wall time cuối kỳ 27,55 giờ. Một alert Redis được giữ, chưa adjudication. Không dùng quality_budget_met/eligible_alerts=0 để claim FPR=0 hoặc precision=100%.

Inspection helper cũ tính wall hours theo thời điểm kiểm tra, kể cả sau terminal. Review đã sửa để dùng `STATUS.elapsed_wall_seconds` khi terminal_present=true. Dữ liệu JSON gốc không bị sửa để phù hợp phép tính mới.

```bash
python3 -m sentinel_pulse.review_observation \
  --inspection validation-evidence/soak-completion-20261007/inspection.json
```
