# RCA sau tín hiệu Pulse — trạng thái và cách vận hành

## Phạm vi

Nhánh thứ ba chạy độc lập với Pulse realtime và thí nghiệm feature/syscall.
Không sửa model, policy, feature, input study hoặc capture đang chạy.
Code: [rca_service.py](sentinel_pulse/rca_service.py),
[rca_tree.py](sentinel_pulse/rca_tree.py),
[rca_connect.py](sentinel_pulse/rca_connect.py).

Pulse hiện xuất **candidate_alert_preview**, chưa phát alert production.
RCA nhận tín hiệu preview đã khớp model/policy hash để kiểm chứng luồng sau
alert; không đổi tên preview thành operational alert và không tự xử lý pod.

## Luồng đang triển khai

1. Subscriber đọc ba luồng Tetragon trên ba worker. Giữ các `sys_connect`
   thuộc policy `sentinel-aims-syscalls`; không persist argv, nội dung request,
   token hay TLS plaintext. Không thay tracing policy đang triển khai.
2. SQLite local giữ context gần thời điểm hiện tại; không phụ thuộc NFS để
   ghi context. Đọc preview từ các log capture trên NFS bằng cursor bền vững,
   chỉ xử lý dòng JSONL hoàn chỉnh. Lần đầu bắt đầu ở cuối log hiện tại và
   ghi receipt số byte đã bỏ qua, không giả vờ có lịch sử trước khi subscribe.
3. Join bằng **node + Pod UID + container name**, không join chỉ theo tên pod,
   PID hoặc IP. Nếu có CRI ID trong trigger thì đối chiếu cả CRI ID.
4. Sau tín hiệu, lấy cửa sổ **30 giây trước + 5 giây sau** để dựng cây bằng
   chứng: signal → container → process → connect attempt → IP/port/đích K8s.
   Cạnh parent → process dựa trên exec ID của Tetragon, không dựa PID tái sử dụng.
5. Xuất JSON node/edge và Markdown dễ đọc. Ghi rõ thiếu context, pod ngoài
   selector policy, inventory cũ, lag đọc preview, giới hạn số event và
   subscription chưa đủ thời gian phủ cửa sổ trước tín hiệu.

Đây là **cây/graph bằng chứng điều tra**, chưa phải thuật toán chứng minh
root cause nhân quả. Anomaly từ count tổng hợp của container không chỉ ra
process nào có lỗi. Các process/connect trong cây là hành vi quan sát quanh
tín hiệu, không mặc nhiên là hành vi tấn công.

## Giới hạn và retention

- Policy hiện dùng selector `aims.hust.vn/runtime-hardened=true`; các dependency
  như broker/database không mặc nhiên có connect detail. Case thiếu event vẫn
  được giữ và đánh dấu unknown, không suy ra không có kết nối.
- Entry `connect` là **lần gọi/thử kết nối**, không phải receipt thành công.
  Cần return probe hoặc network flow để khẳng định thành công; chưa triển khai.
- IP→Pod/Service được resolve theo inventory API gần thời điểm nhận event.
  Ghi tuổi inventory; chưa có lịch sử inventory hoàn chỉnh để replay mọi lần
  tái sử dụng IP hoặc NAT/service-mesh mapping.
- Buffer context giữ **180 giây**, tối đa **20.000 event**. Nếu chạm cap,
  ghi issue và bỏ context cũ nhất của riêng nhánh RCA. Không xóa capture gốc.
- Gom case theo node/Pod UID/container trong **300 giây** để tránh tạo một
  cây mỗi 500 ms. Tất cả decision vẫn nằm nguyên trong capture Pulse;
  STATUS RCA đếm số positive đã đọc và số được gom.
- Mỗi cây tối đa **200 connect event**; truncation được ghi rõ. Query tối đa
  10.001 event, ghi cờ khi đạt trần. Chỉ giữ **500 case JSON/Markdown gần nhất**
  của subscriber mới này; case cũ hết retention sẽ bị xóa, có counter.
  Muốn giữ minh chứng lâu dài phải sao chép case + SHA-256 sang evidence.
- RCA CPU quota **0,5 core**, RAM cap **512 MiB**, trên control plane `.234`.
  Đây là hạn mức cấu hình, không phải overhead đã đo.
- Service tự restart, enable sau boot, resume cursor/case từ SQLite WAL.
  Đổi config/source phải dùng output đăng ký mới; không trộn checkpoint cũ.
  Reconnect có issue; không cam kết không mất event khi sensor/API/VM mất kết nối.
- Subscriber không nằm trong đường quyết định ML nên bước đợi post-context
  không cộng vào kernel→preview latency. RCA có latency hoàn tất cây riêng.

## Triển khai và kết quả live đã kiểm chứng

SSH xác minh lúc **11:06 ngày 15/10/2026, UTC+7**: service
`pulse-rca-context.service` đang `active/running`, `enabled`, trên `.234`.
Source ba module được ghim tại `/opt/sentinel-pulse-rca/2027dc8`, khớp Git
commit **2027dc8**. Cấu hình riêng
`/etc/sentinel-pulse-rca/parallel-20261015.json`; environment file
`/etc/sentinel-pulse/rca-context.env` do systemd đọc. Không cài thêm package.

- Đã sinh **52 case**; **27 case có connect context**, 25 case không có.
  Đây là số case RCA, **không phải TP/FP hoặc confusion matrix**.
- Ví dụ thật: `inventory-service-695bf6f445-ttlgj` có **99 lần connect** trong
  khoảng join; cây chứa 10 process, 5 parent, 3 đích: `kube-dns:53`,
  `aims-postgres-cnpg-rw:5432`, `127.0.0.1:8000`.
  Không kết luận các kết nối này độc hại hoặc gây anomaly.
- Đã thử restart **riêng RCA**: trước restart 49 case; sau resume còn nguyên
  ledger và tăng lên 52, các cursor đều tăng; chỉ có đúng ba receipt initial-tail
  của lần đầu, không tua lại từ đầu. Không thử reboot VM trong lượt này.
- Unit báo MemoryCurrent **88.834.048 byte ≈ 84,7 MiB** ở snapshot.
  Đây là cgroup gồm subscriber và ba kubectl, chưa phải A/B overhead benchmark.
- 33 test RCA local và **57 test regression trên VM** đều pass. Suite VM gồm
  RCA, preview evaluator/replay, batch scorer và matched study; không train lại.
  Python host chưa có NumPy nên regression ML chạy bằng venv hiện hữu trên VM.
- Lúc cài, config ban đầu không đọc được vì thư mục cha `/etc/sentinel-pulse`
  là root:root 0750. Đã chuyển config sang thư mục RCA riêng root:dat 0750,
  file 0640; không nới quyền cấu hình khác. Journal giữ startup failure.
  Restart chủ động có thể reset `NRestarts`, không dùng counter này để nói
  chưa từng có lỗi. Pulse/syscall không restart bởi thao tác triển khai này.

Bằng chứng đã sao chép về repo: [receipt và case thật](validation-evidence/pulse-rca-context-20261015/README.md).
Các số trên là snapshot, không phải SLO hoặc kết quả phát hiện cuối cùng.
Một số counter STATUS có thể mất phần chưa checkpoint trong khoảng 5 giây
khi process restart; ledger case/cursor SQLite là nguồn kiểm tra resume.

## Cách kiểm tra

Unit: [pulse-rca-context.service](sentinel_pulse/systemd/pulse-rca-context.service).

```bash
sudo systemctl status pulse-rca-context.service --no-pager
sudo systemctl show pulse-rca-context.service -p ActiveState -p NRestarts -p UnitFileState
sudo python3 -m json.tool /var/lib/sentinel-pulse-rca/parallel-20261015/STATUS.json
sudo ls /var/lib/sentinel-pulse-rca/parallel-20261015/cases
```

Lỗi RCA không được dùng để dừng hay reset Pulse/syscall study. NFS reader
RCA còn có thể chờ khi NFS lỗi; đây là consumer riêng, không thay đổi loop
collector. Độ đầy đủ Tetragon chưa được đo bằng exact-event reconciliation.
