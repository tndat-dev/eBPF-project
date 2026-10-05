# Phụ thuộc trước khi gỡ Longhorn — 02/10/2026

Read-only inventory từ master `10.1.16.234`, gồm `PVS.json` và `STORAGECLASSES.json`. Longhorn Helm release hiện là `longhorn`, namespace `longhorn-system`, chart/app `1.12.0`.

29 PV Longhorn đang Bound, reclaim policy Delete: production 16, vault 6, opensearch 3, observability 2, jenkins 1, trivy-system 1. Production gồm PostgreSQL, Kafka, RabbitMQ, Redis và MinIO. Longhorn đang là default StorageClass; cụm còn có `nfs-client` với policy Retain, nhưng chưa đánh giá khả năng thay thế cho từng ứng dụng.

Yêu cầu gỡ Longhorn chưa xác định việc giữ hay xóa dữ liệu của các ứng dụng phụ thuộc. Chưa xóa workload/PVC/PV, chưa bật deleting-confirmation-flag và chưa uninstall Helm release.

Tài liệu uninstall tương ứng phiên bản đang cài: [Longhorn 1.12 uninstall](https://longhorn.io/docs/1.12.0/deploy/uninstall/). Quy trình chính thức yêu cầu xử lý các workload dùng volume trước khi gỡ, và có confirmation flag vì uninstall có thể làm mất dữ liệu.
