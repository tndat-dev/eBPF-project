# Smoke of the live rolling calibration (Pulse 5.31): `pulse-recal-smoke`, 29/10 14:57–16:13 (UTC+7)

Workers only (no campaign, RCA or bridge), snapshot `b440850`, `rolling-1-1` with the campaign exclusion on (no campaign:
no interval). Checks the code path only; no metric of the confirmation protocol is read from it.

| File | What |
|---|---|
| `CONFIG.json` | the planned run (recalibration block, per-worker score buffers) |
| `recalibration-<node>.jsonl` | every refresh of each worker: two `unchanged` (no usable hour yet), then `applied` epoch 1 at 16:05 (21 workloads swapped) |
| `STATUS-<node>.json` | final worker status (0 issues, 0 refresh failures) |
| `live-recalibration-check.json` | `scripts/analysis/live_recalibration_check.py`: 62,887 rows under epoch 1 rescored from an independent rebuild, agreement 1.0 on every worker; array sizes equal to the rebuild and the same on the three workers |

The run directory (4.3 GB), its snapshot and the worker units / configs / local copies were deleted after the copy.
