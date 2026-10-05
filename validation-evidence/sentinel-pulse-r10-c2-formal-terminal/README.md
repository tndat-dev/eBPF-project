# R10-C2 terminal receipt — xác minh 02/10/2026

Run `sentinel-pulse-r10-c2-formal-20261001` bắt đầu `2026-10-01T13:08:37Z`, dừng `2026-10-01T15:51:28Z` do `unhealthy_longhorn_volume`. Disposition là `rejected_infrastructure_failure`; chưa đánh giá normal gate và không promote candidate.

Archive hoàn tất `2026-10-01T15:56:33Z`. SSH sáng 02/10 xác nhận 38/38 checksum trong `RAW_SHA256SUMS` đạt khi chạy từ đúng evidence directory. Control collector đã phục hồi trên ba worker; experiment collector và candidate detector inactive.

Worker4 có availability cuối 0,997703 thấp hơn 0,999; worker1 và worker3 có capture valid nhưng formal run vẫn bị reject. Các JSON worker-finalize và disposition đi kèm lưu số liệu gốc. Snapshot monitor cuối có tổng 1.260.946 decision và 0 alert; các snapshot không cùng timestamp và không thay thế thống kê toàn bộ decision stream.

Raw archives ở master:
`/home/dat/eBPF-project-formal-r10-c2-20261001/validation-evidence/sentinel-pulse-campaign/sentinel-pulse-r10-c2-formal-20261001/`.

Receipt này không có raw tarball nên không thể verify mọi mục của checksum index trực tiếp trên host. Data-use flags trong disposition đều false cho training, tuning, normal gate và blind attack.
