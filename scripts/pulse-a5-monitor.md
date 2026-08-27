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
