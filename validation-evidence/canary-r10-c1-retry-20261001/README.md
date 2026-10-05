# Sentinel Pulse bounded live-normal canary

- Run: `sentinel-pulse-canary-r10-c1-retry-20261001`
- Evidence: `nonformal_live_normal_canary`; not a preregistered formal soak.
- Start: `2026-10-01T12:16:26.938778Z`; three node captures lasted 902.67–903.87 s.
- Frozen model manifest SHA-256: `6ddf7cf9b03cb783b82c23272f7046bafa7ab1412b0545b60a2821d1f441cc21`.
- Frozen policy SHA-256: `602165bd48d81f549d3bfb65e5bdb319a11252678cbf484d739afcf2e5bc8143`.
- Outcome: valid bounded canary; 114,964 decisions, 0 alerts, 0 detector restarts; no missing or unexpected workload keys.
- Policy/raw-score detail: 1,182 decisions (1.028%) were `suppressed` with `raw_model_anomalous=true`; semantic corroboration was false for all, while 91 had score corroboration. Search service contributed 881/6,959 raw flags (12.66%). This is an unlabeled raw-signal rate, not a ground-truth false-positive rate. These signals were not used for training or threshold/model tuning.
- Read-only feature join matched all 881 search raw flags. Their per-node exact syscall total had p50 24–25 and p90 36–38; non-raw search windows had p50 18 and p90 1,370–1,427. Each of `setuid`, `setgid`, `capset`, `connect`, and `execve` was nonzero in 16/881 rows; the union of those counters was 30/881. Descriptive only: no root cause or false-positive label is inferred.
- Coverage: 21 workload keys passed the configured coverage gate. Frontend observed 906/908 one-second buckets (0.9978); all other keys met or exceeded the gate.
- Timing: aggregate inference p99 30.77 ms; normal window-start-to-decision p99 1.096 s, max 1.570 s. This is not an observed kernel-to-alert latency because the run was normal-only and produced no alert.
- Collector: all three nodes had telemetry availability 1.0, zero cadence violations, zero estimated missing snapshots, and zero collector hard-drop counters. Per-node p99 window-start-to-emit was 0.546/0.549/0.545 s for worker1/worker3/worker4.
- Approximate per-node experiment CPU average 0.073/0.075/0.074 cores and peak memory 109.4/108.9/110.2 MB.
- `FINAL_SHA256SUMS`: all 73 entries verified on the master. Control collector restored and candidate/500-ms experiment services inactive on all three workers.
- `accuracy_claim_allowed=false`, `automatic_promotion=false`; no attack data was injected and no FPR/recall claim follows from this run.

The compact local files preserve the aggregate, start metadata, monitor, checksum
list and node finalizer JSONs. The complete node captures and decision streams
remain on the master at `/home/dat/sentinel-pulse-evidence/canary-r10-c1-retry-20261001`.
