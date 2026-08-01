# eBPF Runtime Sentinel

The working runtime pipeline is under `ml-service/`; production-like Kubernetes
policies, systemd deployment, attack generators and reproducible benchmarks are
under `sentinel/`. The detector consumes all Tetragon node streams, currently
builds 10-second per-deployment syscall n-gram windows, scores a robust-tail LSTM model,
applies EVT-POT thresholding plus an independent kernel behavior gate, and hands
alerts to the four-step isolation responder.

The systemd detector is active in audit/dry-run mode with full Tetragon coverage
gating. The production V7 release uses a validated 10-second cadence. Isolation
Forest is retained only as a diagnostic; it is not mixed into the actionable
score. The action decision requires independent kernel corroboration: a
workload-conditioned behavior gate, or persistent full-threshold ML score plus
extreme event volume learned only from clean windows. A high score or high
volume alone is not actionable.

The production release was promoted atomically on 1 August 2026 after a strict
offline gate, an independent four-regime live normal matrix and 15/15 real
in-container kernel attack trials. All 216 measured normal-control windows had
zero detections, score crossings, behavior crossings and actionable pairs while
Tetragon remained healthy on 6/6 nodes. Fast-path early warning matched 6/6
high-specificity trials at p50/p95/max 0.285/0.919/0.956 seconds. The separate
ML confirmation path measured min/median/max 7.058/17.303/18.593 seconds; this
distinction is intentional and must be preserved in paper claims. Atomic model,
calibration and systemd backups remain available for rollback. Immutable release
evidence is under `validation-evidence/20260801T153648Z/` and the full history,
including rejected candidates and root-cause analyses, is in
`PROJECT_STATUS_REPORT.md`.

Sentinel's cluster client uses a dedicated local HAProxy endpoint backed by all
three Kubernetes control planes; the operator's default kubeconfig remains
unchanged. Collection and validation now reject API membership failures,
incomplete DaemonSet coverage, queue backpressure and any unexpected Tetragon
stream restart. Validation emits runtime-health samples inside every measured
regime/trial and defaults to the same confirmation policy as the systemd
production detector.

Key reproducibility entry points:

- `collect_real_baseline.py` and `merge_baselines.py`: immutable real-data
  collection with checksums;
- `build_phase_dataset.py` and `train_candidate.py`: mixed-vocabulary-safe,
  phase-balanced holdout, deterministic seeds and immutable candidate output;
- `analyze_normal_run.py`, `run_kernel_regression.py` and
  `run_kernel_matrix.py`: independent normal control and 15-trial real syscall
  attack validation with injection acknowledgements and dual-clock latency;
- `promote_candidate.py`: gated, atomic promotion with rollback artifacts;
- `sentinel/benchmarks/measure_phase.py`: repeated workload/Tetragon/ML overhead
  measurements with raw ApacheBench output.

Raw reports and environment captures are stored under
`sentinel/benchmarks/results/`. Passing results are empirical evidence for this
cluster, traffic mix and attack implementation; they are not a mathematical
guarantee of universal zero false positives.

The original V1 scripts remain for comparison. The Agent Runtime Sentinel V2
extension is now scaffolded under `agent_runtime/`:

- MCP JSON-RPC parsing and a bounded sliding-window behavior graph
  (`agent -> tool -> resource`);
- deterministic graph feature vectors so the current test/evaluation harness can
  run before PyTorch Geometric is installed;
- five AI-agent attack scenarios mapped to the V1 evaluation methodology;
- a realtime graph-to-alert bridge using a robust median/MAD baseline,
  two-window confirmation and cooldown to suppress legitimate MCP bursts;
- an eBPF TLS-uprobe skeleton showing the correct split: copy raw bytes in
  kernel space, parse JSON-RPC in userspace.

The full MCP TLS-uprobe/GAT pipeline in `Agent_Runtime_Sentinel_ALL_FILES/` is
still a V2 extension and must not be claimed as fully deployed until real MCP
capture data, a ring-buffer consumer, a minimal HTTPS MCP pod, and an
independent evaluation exist.
