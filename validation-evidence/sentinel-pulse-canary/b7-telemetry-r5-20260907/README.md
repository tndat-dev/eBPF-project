# Sentinel Pulse B7 telemetry canary R5

- Run: `sentinel-pulse-b7-telemetry-r5-20260907T122659Z`
- Runtime commit: `d54c7397159bf4e12ad3dda4fe6f2ef0838b2774`
- Mode: normal-only, non-formal, 7.200 giây, không chạy sysstat recorder
- Terminal disposition: infrastructure/evidence failure; candidate không được
  đánh giá, không cho phép accuracy claim hoặc promotion
- Aggregate decisions: 517.116; observed alerts: 0
- Node result: worker1 valid, worker4 valid, worker3 failed cadence gate
- Worker3: 138.393 feature row, một delayed loader snapshot, interval max
  4,873938 giây, interval p99 0,507403 giây, ingest-lag p99 0,019569 giây,
  window-start-to-emit p99 0,523591 giây
- Hard-integrity counters: 0; `capture_interval_violation=1`
- Live journal: containerd/kubelet ghi hai ExecSync probe timeout 3 giây trong
  cùng khoảng node pause; R5 không có recorder nên observer-perturbation không
  được evidence ủng hộ
- Counterfactual replay của validator successor: 14.291 snapshot quan sát, 9
  snapshot 500 ms ước tính bị thiếu, availability 99,9371%, max gap 4,873938
  giây. Replay này không thay đổi terminal disposition của R5.

Canonical immutable archive ở control plane:
`/home/dat/sentinel-pulse-evidence/canary-b7-telemetry/sentinel-pulse-b7-telemetry-r5-20260907T122659Z/`.
`FAILED_FINAL_SHA256SUMS` đã verify. Một gói chọn lọc read-only được tạo tại
`/tmp/sentinel-pulse-r5-selected.tgz`, SHA-256
`15758ed154b47540f472022c05f8ebf595558b81bd9d12a4e4c28e1a027d5014`;
đây không phải checksum của full archive.
