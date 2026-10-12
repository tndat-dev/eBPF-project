# Trạng thái readiness cụm Kubernetes

Cập nhật từ kiểm tra trực tiếp qua SSH: **12/10/2026 13:31 UTC**. Báo cáo này
tách readiness của workload đang được quản lý khỏi pod đã kết thúc; `Succeeded`
là trạng thái hợp lệ của Job, không phải microservice lỗi.

## Tóm tắt hiện hành

- Sáu node (`10.1.16.234`–`.239`) đều `Ready`, Kubernetes `v1.34.10`, Ubuntu
  24.04.4, kernel `6.8.0-138-generic`.
- Không có Deployment, StatefulSet hoặc DaemonSet nào thiếu replica ready so
  với replica mong muốn. Các workload được scale `0/0` vẫn là cấu hình chủ đích.
- Snapshot mới nhất: toàn cụm **249 pod objects** gồm **238 Running/Ready** và
  **11 Succeeded** (Job đã hoàn tất); không có pod Failed, Pending hoặc Running
  nhưng thiếu container Ready. Các pod `Succeeded` là trạng thái kết thúc hợp
  lệ, không phải microservice chưa sẵn sàng.
- Namespace `production`: **70 pod objects**, gồm **66 Running/Ready** và **4
  Succeeded**; không có pod production Failed/Pending/Running-not-ready.
- Trước cleanup, namespace `velero` có **53 pod Failed/Evicted** cũ; các object
  terminal này đã được dọn sau khi ghi lại nguyên nhân. Snapshot hiện hành
  không còn pod Failed; Deployment Velero `1/1`, node-agent DaemonSet `3/3`.
- PostgreSQL CNPG `3/3`, trạng thái `Cluster in healthy state`; Kafka CR
  `Ready=True`; các StatefulSet RabbitMQ `3/3`, Redis `3/3`, Redis Sentinel
  `3/3`, MinIO `2/2`.
- Các DaemonSet kiểm soát node đều đủ: Cilium, kube-proxy, Tetragon, Falco,
  Istio CNI/ztunnel và node-exporter `6/6`; Longhorn manager/CSI `3/3`.

## Sự cố được giữ lại trong hồ sơ

Các pod terminal không được tính thành normal/TN và không được diễn giải là
model false positive. Trước khi dọn object pod, API ghi nhận:

- 20 pod AIMS loadgen bị từ chối/evict trên `k8s-worker3.local` khoảng
  **11/10 21:14 UTC**, reason `DiskPressure`.
- Các pod production terminal còn lại (microservice/loadgen) bị `Evicted` do
  `ephemeral-storage` dưới ngưỡng kubelet; pod cũ nhất trong nhóm này từ
  **26/09**. Velero có 53 pod Evicted cũ trên worker3.
- Kiểm tra hiện tại lúc **12/10 12:38 UTC**: worker3 `DiskPressure=False`,
  transition gần nhất **10:45 UTC**; filesystem `/` còn **283 GiB**. Node vẫn
  `Ready`; đây là sự cố đã hồi phục, không phải điều kiện hiện tại.
- Dung lượng `/` hiện đọc qua SSH: worker1 còn **154 GiB**, worker3 **283 GiB**,
  worker4 **111 GiB**; ba control-plane lần lượt còn 381/535/538 GiB. Worker4
  có biên dự phòng nhỏ hơn, nên cần theo dõi trước các đợt rollout/tải tăng.

Các con số trên là snapshot API/host trực tiếp; việc dọn pod terminal bên dưới
chỉ loại object đã kết thúc khỏi danh sách đang quan sát, không xóa Deployment,
ReplicaSet, Job, PVC, dữ liệu volume hay log thí nghiệm. Root cause DiskPressure
được ghi rõ, không che đi bằng cleanup.

## Hành động readiness

Đã xác nhận các pod Failed trong `production` và `velero` là terminal, còn
controller tương ứng đã đạt replica mong muốn. Đã xóa **31 object Failed trong
production** và **53 object Failed trong velero** khỏi API; thao tác không xóa
Deployment, ReplicaSet, Job, PVC, dữ liệu volume hay log thí nghiệm. Giữ các Job
pod `Succeeded` theo vòng đời bình thường; không restart database/broker và
không thay đổi cấu hình storage.

Kiểm tra mới nhất lúc **12/10/2026 13:31 UTC**: production còn **66
Running/Ready + 4 Succeeded**, không còn pod Failed; toàn cluster có **238
Running/Ready + 11 Succeeded**, không có pod Failed/Pending hoặc Running nào
chưa Ready. Cả **100 Deployment, StatefulSet, DaemonSet** đạt replica mong muốn.
Sáu node đều `Ready`, `MemoryPressure=False`, `DiskPressure=False`,
`PIDPressure=False`.

Smoke test không ghi dữ liệu: `/api/health/` của **10/10 microservice trả
HTTP 200**; ingress frontend/health/products trả HTTP 200; MinIO liveness trả
HTTP 200; Redis `AUTH` + `PING` thành công; cổng PostgreSQL primary, Kafka và
RabbitMQ mở. Ingress generator còn phát 401 ở `/api/auth/me/` và 400 ở GET
`/api/cart/` vì đang tạo error-mix không kèm phiên đăng nhập/cart; đây không
phải lỗi readiness. Dependency loadgen không có timeout log trong 2 phút kiểm
tra gần nhất.

## Liên hệ với Sentinel Pulse

Node/control-plane health tốt và workload production hiện sẵn sàng, nhưng các
pod Evicted ghi nhận một khoảng hạ tầng bất thường trước đó. Không dùng thời
gian DiskPressure hoặc telemetry thiếu làm normal baseline; giữ incident này
trong báo cáo vận hành. Job refit C2 không bị tác động: journal trực tiếp lúc
**13:31:15 UTC** ghi `255/608` fit; unit còn chạy, chưa có terminal result.
Hai exact-ID histogram pilot bounded trên worker1/worker3 đã hoàn tất, analyzer
và cohort đều hợp lệ; raw artifacts và checksum được lưu trên NFS, kết quả
exploratory có giới hạn ở `syscall_analysis.md`.
