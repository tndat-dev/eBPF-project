# Agent Runtime Sentinel

This is the production-like syscall vertical slice for V2. It keeps V1's
Tetragon collection and responder contract and adds reproducible, per-workload
training, real EVT-POT thresholds, behavior gating and end-to-end telemetry.

Selected runtime model: V7 robust-tail LSTM autoencoder. The decoder has no
teacher-forcing identity shortcut, frequency scaling has a 1% variance floor,
and the empirical p99 normal reconstruction tail maps to score 0.20. Isolation
Forest remains an ablation/diagnostic value: its V6 mixture was rejected because
trees cannot split syscall dimensions that are constant throughout baseline,
which reduced attack margins without improving normal stability.

False-positive controls:

- baseline is keyed by namespace/deployment, never a shared global model;
- 100 Postgres, 100 Nginx and 95 Redis real windows cover independent 1x,
  `wrk -c50`, high-mixed and recovery phases; deterministic phase-stratified
  holdout prevents a regime from existing only in train or validation;
- a release vocabulary of 210 features preserves prior indexes and permits
  zero-padding a new feature only when source metadata proves it never occurred;
- threshold is learned from a Generalized Pareto Peaks-Over-Threshold tail with
  an 0.80 safety floor and a finite-sample empirical fallback;
- a single noisy window cannot isolate a pod; detection requires two consecutive
  windows above threshold and a workload-conditioned suspicious-behavior gate;
- only clean-looking windows update online calibration, preventing a startup
  attack from poisoning the normal score tail; a sample must be below both the
  offline score threshold and the kernel behavior gate;
- system namespaces and load generators are excluded from response evaluation.

The selected V7 candidate passed offline holdout (maximum normal scores 0.153,
0.203 and 0.228), a four-regime independent live control, and all five safe
attack profiles inside each monitored workload (15/15). The live control
observed 44 windows per workload with zero raw score crossings; its maximum
scores were 0.266 (Postgres), 0.644 (Nginx under `wrk -c50`) and 0.225 (Redis).

Promotion verifies nine model-release hashes and seven runtime-code hashes,
atomically installs both the release and its validated normal calibration, and
preserves timestamped model/calibration backups. The service intentionally
remains in audit/dry-run mode: enabling cordon/quarantine/eviction is a separate
operational decision.

Conditional normalization, workload embeddings and normalizing flows remain
research candidates, not claimed features. With the available corpus, the
empirically stable choice is one calibrated model per workload plus a shared
runtime contract. A learned MoE gate would need substantially more labeled,
workload-diverse data to avoid reducing attack margins.
