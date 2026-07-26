# Candidate validation protocol

This protocol separates model selection from final evaluation. A candidate is
never copied over the running release until every gate below passes against the
same model directory and bundled vocabulary.

## 1. Real-data capture

- Capture 30-second Tetragon windows from Postgres, Nginx and Redis.
- Collect four normal operating regimes independently: 1× load, `wrk` c50,
  mixed scaled load, and 1× recovery after scale-down.
- Require at least 20 qualifying windows from every workload in every phase.
- Reject a phase when the bounded reader reports any backpressure or a target
  is missing.
- Store row-aligned event counts/syscall counts plus SHA-256 checksums.

High-rate context syscalls are rate-limited in-kernel; security-sensitive
syscalls are never sampled. The policy must pass a c50 probe before collection.

## 2. Dataset and offline gate

- Preserve existing feature indexes and ensure every syscall emitted by the
  policy exists in the release vocabulary.
- Zero-padding a newly added feature is allowed only when row metadata proves
  the syscall never occurred; otherwise recollection is mandatory because its
  bigram positions cannot be reconstructed.
- Build an 80/20 deterministic holdout with samples from every phase in both
  partitions. Fit scalers, tail calibration and behavior limits on train only.
- Reject a workload if holdout median score exceeds 0.50, p95 exceeds 0.80,
  more than 10% of scores exceed 0.80, any normal behavior gate fires, or two
  actionable holdout windows are consecutive.

## 3. Independent live-normal matrix

Run a fresh detector process and a fresh calibration file over the same four
regimes, after training. Each regime must contain at least eight qualifying
windows per workload. Required result: zero alerts, zero raw score crossings,
zero workload-conditioned behavior crossings and zero consecutive actionable
pairs. Report inference and ingest-lag distributions from raw JSONL telemetry.
Give every detector, profiler and test process a unique telemetry path. Reject
the run if a row has an impossible event-time/ingest-lag or belongs to a pod not
created by that run; never remove individual rows to make a report pass.

## 4. Real kernel attack matrix

Compile `runtime_attack.c` as a static binary and execute all five safe attack
profiles inside each of the three monitored workloads. This yields 15 trials
covering container syscall entry, Tetragon export, all-node ingestion,
event-time windowing, model inference and alert emission. The generator uses
invalid arguments and loopback-only destinations, so it cannot mount, escalate,
open a remote shell, mine or exfiltrate data.

Every trial must have a start acknowledgement, zero pre-injection alerts, a
zero attack exit code and a post-injection detection. Injection time is stamped
on the master after the in-container start acknowledgement so it shares a clock
with detection telemetry and excludes `kubectl exec` startup time.

## 5. Promotion and post-promotion checks

`promote_candidate.py` verifies SHA-256 lineage across the dataset manifest,
training report, bundled vocabulary, normal matrix, calibration and 15-trial
attack matrix. It then swaps the complete release directory atomically and
keeps timestamped model/calibration backups. The systemd service loads the
vocabulary from that release directory and fails closed on model-dimension or
checkpoint errors.

After promotion, repeat a normal soak and a three-phase overhead matrix:
no tracing, Tetragon only, and full detector. Each overhead phase uses five
independent 30-second `wrk` repetitions and reports raw outputs, median p99,
throughput, failed requests, CPU/RAM snapshots and bootstrap confidence
intervals.

Unit tests executed on a production host must use temporary metrics and
calibration paths. Their synthetic pod keys and timestamps must never share the
production JSONL stream.

Passing this protocol is evidence for the measured cluster, workloads and
attack implementations. It is not a mathematical guarantee of zero false
positives or universal attack detection.
