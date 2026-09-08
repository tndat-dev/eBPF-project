# Sentinel Pulse availability R8 smoke canary

Run `sentinel-pulse-availability-r8-smoke-20260908T061606Z` là canary
live-normal **không formal**, chạy khoảng 600 giây trên ba worker. Mục tiêu của
run chỉ là xác minh code/lifecycle telemetry availability mới trước khi mở
formal normal soak 24 giờ; run không dùng attack, không cho phép claim recall,
FPR hoặc kernel-to-alert và không tự động promote model.

Kết quả terminal trên control plane:

- `AGGREGATE.json.valid=true` và `coverage_preflight_gate=true`;
- 42.031 decision, trong đó 41.544 đã score; 0 alert và 0 detector restart;
- đủ 20/20 workload-container key, không có workload thiếu hoặc ngoài manifest;
- thời lượng collector tối thiểu 601,841 giây;
- inference p50/p95/p99/max = 16,848/24,435/29,787/49,803 ms;
- post-window processing p50/p95/p99/max =
  0,162/0,300/0,347/0,535 giây;
- window-start-to-decision p50/p95/p99/max =
  0,666/0,804/0,852/1,038 giây;
- telemetry availability bằng 100% trên 3/3 worker, estimated missing snapshot,
  delayed interval, short interval và cadence violation đều bằng 0.

Model manifest SHA-256 là
`2e37ffd1ef4476b09e123315b467e47814613b9ff22dfd0b4e28fbb375952a81`;
policy SHA-256 là
`711e66a920be6e6d532c665afe6b2ae02e2afac00a73d0f7fbab1672e6b631da`.
Toàn bộ 9 entry `START_SHA256SUMS` và 73 entry `FINAL_SHA256SUMS` đã verify.
SHA-256 của `AGGREGATE.json` là
`1707520b79ccfc4e14f5cb10395b036ccb5bd5d22e9ac09922809e6e8336222b`;
SHA-256 của `FINAL_SHA256SUMS` là
`83abdda8f1ddb6dfbe502d2b0e26db61868be81e16f20d61fa9f6aaf0497c561`.

Raw evidence immutable nằm trên control plane tại
`/home/dat/sentinel-pulse-evidence/canary-availability/sentinel-pulse-availability-r8-smoke-20260908T061606Z/`.
