# Sentinel Pulse a5 normal soak — monitoring checkpoint

Run: `pulse500-normal-soak-a5-20260827T070900Z`
Lifecycle: `sentinel-pulse-a5-lifecycle.service`
Model: `pulse500-model-a1-20260820T093721Z` (manifest sha `c4683505...`)
Policy (semantic-v4): `272e9119...`
Duration: 90000s (25h) · expected finalize ≥ `2026-08-28T08:08:26Z`

> Tài liệu này là snapshot lịch sử, không phải evidence source. Checker cũ từng
> append tự động; cơ chế đó đã bị loại bỏ vì có thể làm bẩn worktree và sửa
> artifact sau archive. Số liệu terminal phải lấy từ marker/checksum trên
> control plane.

## Checkpoints

- **2026-08-27T08:12Z (post-launch)** — lifecycle `active`/`normal_monitor`; 6/6 nodes
  Ready; Tetragon 6/6; MONITOR 9/9 samples `alerts:0`; collectors+detectors active,
  nrestarts 0 on all 3 workers.
  - feature rows: worker1=8331, worker4=6160, worker3=2496.
  - Gating OK: `maximum_alerts:0`, `minimum_duration_hours_per_workload:24.0`,
    `blind_evaluation_started:false`, no event loss / backpressure.
- **2026-08-27T12:38:43Z** (4.50h / 18.8% soak) — Total decisions: 1,169,933, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T12:38:49Z** (4.51h / 18.8% soak) — Total decisions: 1,169,933, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T12:39:21Z** (4.52h / 18.8% soak) — Total decisions: 1,174,778, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T12:44:23Z** (4.60h / 19.2% soak) — Total decisions: 1,194,321, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T13:09:21Z** (5.02h / 20.9% soak) — Total decisions: 1,301,118, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T13:14:25Z** (5.10h / 21.2% soak) — Total decisions: 1,325,317, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T13:39:23Z** (5.52h / 23.0% soak) — Total decisions: 1,432,105, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T13:44:27Z** (5.60h / 23.3% soak) — Total decisions: 1,456,732, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T14:09:25Z** (6.02h / 25.1% soak) — Total decisions: 1,563,561, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T14:14:29Z** (6.10h / 25.4% soak) — Total decisions: 1,588,371, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T14:31:01Z** (6.38h / 26.6% soak) — Total decisions: 1,656,454, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T14:39:28Z** (6.52h / 27.2% soak) — Total decisions: 1,695,495, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T15:09:30Z** (7.02h / 29.2% soak) — Total decisions: 1,825,760, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T15:39:32Z** (7.52h / 31.3% soak) — Total decisions: 1,955,422, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T16:09:34Z** (8.02h / 33.4% soak) — Total decisions: 2,087,935, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T16:39:35Z** (8.52h / 35.5% soak) — Total decisions: 2,215,658, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T17:09:35Z** (9.02h / 37.6% soak) — Total decisions: 2,348,394, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T17:39:38Z** (9.52h / 39.7% soak) — Total decisions: 2,478,673, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T18:09:39Z** (10.02h / 41.8% soak) — Total decisions: 2,609,050, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T18:39:40Z** (10.52h / 43.8% soak) — Total decisions: 2,737,198, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T19:09:40Z** (11.02h / 45.9% soak) — Total decisions: 2,870,321, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T19:39:40Z** (11.52h / 48.0% soak) — Total decisions: 2,998,492, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T20:09:41Z** (12.02h / 50.1% soak) — Total decisions: 3,132,014, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T20:39:41Z** (12.52h / 52.2% soak) — Total decisions: 3,260,448, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T21:09:41Z** (13.02h / 54.3% soak) — Total decisions: 3,389,369, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T21:39:42Z** (13.52h / 56.3% soak) — Total decisions: 3,518,683, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T22:09:42Z** (14.02h / 58.4% soak) — Total decisions: 3,651,273, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T22:39:42Z** (14.52h / 60.5% soak) — Total decisions: 3,782,891, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T23:09:42Z** (15.02h / 62.6% soak) — Total decisions: 3,913,094, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-27T23:39:43Z** (15.52h / 64.7% soak) — Total decisions: 4,043,626, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-28T00:09:43Z** (16.02h / 66.8% soak) — Total decisions: 4,174,158, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-28T00:39:44Z** (16.52h / 68.8% soak) — Total decisions: 4,304,359, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-28T01:09:44Z** (17.02h / 70.9% soak) — Total decisions: 4,435,432, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-28T01:39:44Z** (17.52h / 73.0% soak) — Total decisions: 4,564,359, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-28T02:09:45Z** (18.02h / 75.1% soak) — Total decisions: 4,694,978, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-28T02:39:45Z** (18.52h / 77.2% soak) — Total decisions: 4,824,502, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-28T03:09:45Z** (19.02h / 79.3% soak) — Total decisions: 4,953,076, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-28T03:11:09Z** (19.05h / 79.4% soak) — Total decisions: 4,963,086, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-28T03:31:21Z** (19.38h / 80.8% soak) — Total decisions: 5,049,093, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.
- **2026-08-28T03:31:29Z** (19.38h / 80.8% soak) — Total decisions: 5,049,093, Alerts: 0, Restarts: 0. Workers: 3/3 healthy.

## Terminal disposition

- **2026-08-28T06:01:32Z** — A5 bị `infrastructure-reject` do production pod
  `notification-service-85955489ff-v5tmq` tạm thời unready sau container exit
  255. Snapshot monitor cuối: 5.699.660 decision, 0 emitted alert và 0
  candidate-detector restart. Vì chưa đủ 24 giờ và không có attack labels,
  không được diễn giải thành normal-pass, 0% FPR hay 100% accuracy.
- Periodic checker cũ ghi tiếp `SOAK_PERIODIC_CHECKS.log` sau archive, làm
  top-level `RAW_SHA256SUMS` mismatch đúng file phụ này; ba raw worker archive
  vẫn checksum pass. Timer đã bị disable ngày 29-08-2026 và checker mới là
  read-only.
