# AIMS overhead V2 — zero-error counterbalanced campaign

Campaign `20260805T093000Z` chạy trên cluster sáu node từ
`2026-08-05T09:30:17Z` đến `11:28:16Z`. Sáu phase-order block bao phủ đủ mọi
hoán vị của `no_tracing`, `tetragon_only`, `full_pipeline`; mỗi phase có 10 lần
`wrk -t2 -c8 -d30s`, tổng 180 repetition. Cả 180 lần đều có 0 socket error và
0 non-2xx/3xx.

`counterbalanced-local-validation.json` được tái sinh trên máy khác bằng code
hiện tại từ sáu comparison, sáu protocol và 18 raw phase report. File này giống
byte-for-byte aggregate do collector tạo:

```text
SHA-256 323bd5815ceee7a0bba5e2a9006c92cd8077930314ca0266e0f549648857b69a
```

## Kết quả paired block

| Effect | Median throughput loss | 95% block-bootstrap CI | Median p99 increase | 95% block-bootstrap CI |
|---|---:|---:|---:|---:|
| Tetragon policy vs no tracing | -1.698% | [-3.955%, 1.909%] | 1.321% | [-4.002%, 8.674%] |
| Full pipeline vs no tracing | -1.545% | [-3.930%, 1.376%] | 2.702% | [-2.249%, 4.767%] |
| Detector increment vs Tetragon | 0.245% | [-4.293%, 3.521%] | 0.573% | [-8.286%, 7.901%] |

Tất cả CI đều cắt 0. Kết quả đúng là campaign không phát hiện effect khác 0 ở
cỡ mẫu sáu block; không được diễn giải throughput loss âm thành tăng tốc do
Sentinel. Đây vẫn là một campaign trên một cluster.

Median theo sáu block: full detector dùng 24.589% một CPU core (range
23.043--26.691%) và 431.019MiB RAM (429.303--431.977MiB). Tổng Tetragon
DaemonSet là 264m CPU/9637.25MiB ở phase policy-only và 271.25m/9656MiB ở full
pipeline. Đây là Metrics Server snapshot lagged, không phải resident-set
profiler.

`cluster-post-campaign.txt` xác minh lại ngày 11-08-2026: campaign unit
`success/inactive`, `sentinel-detector.service` active, AIMS tracing policy đã
restore, Tetragon và 6/6 node Ready. `SHA256SUMS` khóa toàn bộ bundle.
