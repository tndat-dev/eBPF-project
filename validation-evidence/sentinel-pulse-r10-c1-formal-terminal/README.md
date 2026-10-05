# Sentinel Pulse R10-C1 terminal evidence receipt

- Run: `pulse500-normal-r10-c1-20260930`
- Source capture/evidence on master: `/home/dat/sentinel-pulse-evidence/formal-normal-r10-c1-20260930`
- Lifecycle terminal state: failed closed at `2026-09-30T20:25:50Z`, after 61,685 s (about 17 h 8 min, 71.4% of the preregistered 24 h).
- Reason: `collector_integrity_violation` on worker `10.1.16.237`.
- Archive completed: `2026-10-01T11:56:13Z`; archive disposition does not promote the candidate.
- `RAW_SHA256SUMS`: 41 entries; all 41 validated on the master with `sha256sum -c` (exit 0).
- Production control collector restoration recorded at `2026-10-01T11:55:29Z`; direct checks confirmed `sentinel-pulse-collector.service` active on `.237`, `.239`, and `.238`.
- Raw capture archives remain only on the master (about 5.77 GB total); this host receipt intentionally contains metadata and finalization reports only.

## Per-worker finalization

| Worker | Rows | Valid | Telemetry availability | Delayed intervals | Maximum gap | p99 interval | p99 ingest lag | p99 window-start-to-emit | Rejection |
|---|---:|:---:|---:|---:|---:|---:|---:|---:|---|
| `10.1.16.237` | 2,650,897 | no | 1.000000 | 0 | — | 0.512883 s | 0.036629 s | 0.543581 s | `snapshot_consistency_retry_exhausted=1`, `target_snapshot_gap=1` |
| `10.1.16.239` | 3,579,468 | no | 0.999374 | 8 | 43.460053 s | 0.512644 s | 0.034786 s | 0.541713 s | max gap > 10 s |
| `10.1.16.238` | 3,853,988 | no | 0.998940 | 17 | 22.208448 s | 0.512576 s | 0.036355 s | 0.543260 s | max gap > 10 s and availability < 0.999 |

Every worker is invalid under the preregistered capture contract. The rows are
not eligible for training, tuning, calibration, normal-pass claims, or blind
attack evaluation. The monitor's zero-alert observation is not an FPR estimate
or a model-quality result because the formal run did not pass its integrity and
duration gates. No causal link between the telemetry gaps and backup activity
has been established.

## Preserved compact source artifacts

- `FAILED`, `ARCHIVE_COMPLETE`, `CONTROL_COLLECTOR_RESTORED.json`
- `SOAK_START.json`, `DISPOSITION.json`, `RAW_SHA256SUMS`
- `workers/10.1.16.{237,238,239}-node-finalize.json`

The capture tarballs and full monitor remain on the master at the source path
above; this is a receipt, not a replacement for the immutable source evidence.
