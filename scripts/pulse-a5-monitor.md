# Sentinel Pulse a5 normal soak — monitoring checkpoint

Run: `pulse500-normal-soak-a5-20260827T070900Z`
Lifecycle: `sentinel-pulse-a5-lifecycle.service`
Model: `pulse500-model-a1-20260820T093721Z` (manifest sha `c4683505...`)
Policy (semantic-v4): `272e9119...`
Duration: 90000s (25h) · expected finalize ≥ `2026-08-28T08:08:26Z`

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
