# Biên bản gỡ tài nguyên triển khai V8

Kiểm kê và xử lý qua SSH trên master `10.1.16.234`, **12/10/2026 khoảng
22:03 ICT**. Mục tiêu là gỡ runtime V8 đã triển khai, không xóa dữ liệu thử
nghiệm hoặc thành phần dùng chung.

## Đã gỡ khỏi systemd

Không tìm thấy Deployment/DaemonSet/StatefulSet/Service/Job/ConfigMap/PVC nào
có tên V8 trong Kubernetes. Trên master có 13 unit V8 riêng:

- `aims-v8-falco-evidence.service` — đang chạy vòng auto-restart, `NRestarts`
  quan sát được là 464.042; đã stop/disable.
- `aims-v8-capture.service`, `aims-v8-blind-attack.service`,
  `aims-v8-normal-ablation.service`, `aims-v8-overhead.service`,
  `aims-v8-post-capture.service`, `aims-v8-release-finalize.service`.
- Các unit trigger `aims-v8-overhead.path`, `aims-v8-release-finalize.path`
  và timer blind-attack, normal-ablation, overhead, post-capture.

Các unit đã stop/disable, chuyển khỏi `/etc/systemd/system`, sau đó
`daemon-reload` và `reset-failed`. Kết quả kiểm tra: không còn unit file V8,
không còn unit V8 active; `aims-v8-falco-evidence.service` có `MainPID=0` và
`inactive/dead`. File unit được giữ để khôi phục tại:
`/home/dat/ml-service/v8-retired-systemd-20261012/`.

## Những gì được giữ lại có chủ đích

- Tetragon, Pulse collector/resolver, các workload AIMS và loadgen không mang
  tên V8 được giữ nguyên.
- `sentinel-detector.service` đang chạy trên master và worker1 không phải V8
  riêng: release manifest của model store ghi `expected_version=7`; unit này
  dùng các artifact trong cùng model store. Nó được giữ, không thay đổi.
- Model store dùng chung và các thư mục raw/staging/replay V8 được giữ nguyên.
  Đây là artifact/evidence lịch sử, không phải unit/workload đang triển khai;
  xóa chúng sẽ mất dữ liệu và không cần thiết để gỡ runtime V8.
- ConfigMap `sentinel-detector-config` không có nhãn phiên bản V8; không xóa
  chỉ dựa vào tên chung.

## Phạm vi xác nhận

Inventory unit V8 được kiểm tra trên sáu node; chỉ master `.234` có unit `aims-v8-*`.
Inventory Kubernetes qua API trên master không có workload V8. Việc gỡ này
không đụng tới file code V8 trong Git hay xóa kết quả nghiên cứu. Gỡ dữ liệu
V8 lưu trữ khỏi VM/NFS là tác vụ cleanup riêng, không nằm trong lần retire
runtime này.
