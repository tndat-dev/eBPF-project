# eBPF Runtime Sentinel

The working runtime pipeline is under `ml-service/`; production-like Kubernetes
policies, systemd deployment, attack generators and reproducible benchmarks are
under `sentinel/`. The detector consumes all Tetragon node streams, builds
30-second per-deployment syscall n-gram windows, scores a robust-tail LSTM model,
applies EVT-POT thresholding plus an independent kernel behavior gate, and hands
alerts to the four-step isolation responder.

Current deployed release: V7 phase-stratified robust-tail LSTM with
workload-conditioned behavior gates. It uses a fixed 210-feature vocabulary
and was trained from 100 Postgres, 100 Nginx and 95 Redis qualifying windows
captured under four independently collected normal regimes. Isolation Forest
is retained only as a diagnostic; it is not mixed into the actionable score.

The immutable V7 release passed its offline holdout gate, a four-regime live
normal matrix (44 observed windows per workload, zero alerts, zero raw score
crossings and zero behavior-gate crossings), and 15/15 real in-container
kernel attack trials across all three workloads. Median kernel-to-alert latency
was 57.934 seconds. The systemd detector is deployed and continuously scoring,
but response remains intentionally in audit/dry-run mode.

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

The original V1 scripts remain for comparison. The MCP TLS-uprobe/GAT layers in
`Agent_Runtime_Sentinel_Build_Spec.md` are a separate V2 extension and must not
be claimed as deployed until real MCP capture data and an independent
evaluation exist.
