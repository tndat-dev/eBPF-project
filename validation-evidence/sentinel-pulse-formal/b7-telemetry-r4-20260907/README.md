# B7 telemetry R4 — formal run bị infrastructure-reject

Run `sentinel-pulse-formal-normal-b7-telemetry-r4-20260907T113747Z` tạo marker
lúc 11:43:43 UTC ngày 07-09-2026 và bị monitor dừng lúc 11:55:28 UTC. Archive
hoàn tất lúc 11:56:03 UTC. `DISPOSITION.json` ghi:

- `terminal_run_status=rejected_infrastructure_failure`;
- `candidate_status=not_evaluated_by_this_run`;
- `normal_gate_result=null`;
- dữ liệu không được dùng cho normal gate, train hoặc tune.

Worker3 có một snapshot interval 4,832 giây, snapshot tiếp theo 1,355 giây;
ingest lag tối đa 6,197 giây và window-start-to-emit tối đa 6,808 giây. `sar`
cũng thiếu bốn mẫu một giây liên tiếp trong đúng khoảng đó. Journal ghi
containerd `context deadline exceeded`, inactive ttrpc stream và ExecSync
timeout ba giây lúc 11:54:29–11:54:31 UTC. Worker1 đồng thời có iowait tăng
tới 14,67%; worker4 không có spike tương ứng. Không có kernel OOM hoặc I/O
reset trong snapshot đã truy vấn.

Counter cũ ghi 18 vì cùng hai snapshot bất thường được nhân theo các workload
được emit; đây không phải 18 sự cố độc lập. Source kế tiếp sửa counter theo
snapshot, cache metadata resolver và flush một batch mỗi snapshot. Gate 0,8
giây vẫn giữ fail-closed; thay đổi không hợp thức hóa R4.

Các file trong thư mục này là bản sao chọn lọc lấy nguyên byte từ archive trên
control plane. Raw feature/decision/journal và checksum index đầy đủ vẫn ở:

`/home/dat/sentinel-pulse-evidence/formal-b7-telemetry/sentinel-pulse-formal-normal-b7-telemetry-r4-20260907T113747Z/`

SHA-256 `DISPOSITION.json` là
`a4900a2d11e029e7d500772f5264ef6be144a8106a4ada3eddcf42de31de9af8`;
`worker3-node-finalize.json` là
`2188d4933b8e6d649211d1111e24542c6c8d6e2a8e2a2939fa6c88fd4b1008d0`.
