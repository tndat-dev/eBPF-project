# Artifact Inventory — Agent Runtime Sentinel

## Phạm vi

Artifact gồm source runtime V1/V2, Kubernetes manifests, benchmark/replay
scripts và báo cáo result. Không đóng gói password, kubeconfig, raw plaintext
MCP payload, secret, PVC data hay private endpoint.

## Thành phần và entrypoint

| Claim / chức năng | Entry point | Kết quả kỳ vọng |
|---|---|---|
| Full current gate | `./scripts/run_artifact_gates.sh` | toàn bộ gate không-mutating pass |
| Unit/replay V2 | `pytest -q tests/test_agent_runtime_*.py` | test pass |
| Semantic replay gate | `python3 -m agent_runtime.eval.replay_validation` | normal 0 alert, scenario có alert xác nhận |
| Userspace benchmark | `python3 -m agent_runtime.benchmark --iterations 10000 --snapshot-every 100` | JSON p50/p95/p99 |
| GAT benchmark | `python3 -m agent_runtime.eval.gat_benchmark --iterations 100 --epochs 80` | JSON inference latency |
| eBPF build | `make -C agent_runtime/ebpf all` | object + loader |
| MCP manifest validation | `kubectl apply --server-side --dry-run=server -f agent_runtime/k8s/mcp-demo.yaml` | server dry-run pass |
| AIMS workload contract | `ml-service/aims_release_contract.json` | explicit eligible/excluded targets and non-automatic promotion gates |
| AIMS frozen split contract | `ml-service/aims_candidate_split_contract.json` | run-01 fit, run-02--03 independent validation, run-04--05 blind normal test; holdout training forbidden |
| AIMS immutable fit dataset | `ml-service/run_aims_candidate.sh build ...` | exact four run-01 phases, contract/parent/source/array SHA-256 and role in manifest |
| AIMS fit-only calibration | `ml-service/build_aims_fit_calibration.py` | frozen POT/event-volume state from candidate-fit rows only; shared hash for validation and blind trials |
| AIMS normal matrix | `ml-service/run_aims_normal_matrix.sh` | 20 independent phase captures, 24 hours by default, hashes and sensor health |
| AIMS matrix validator | `ml-service/aims_matrix_validation.py` | fail-closed on missing/time-collapsed/tampered or sensor-degraded evidence |
| AIMS split replay evaluator | `ml-service/evaluate_aims_normal_split.py` | exact production detector replay for frozen validation/blind-normal roles; identity-bound atomic phase checkpoints include behavior/extreme-volume/confirmation policy; zero-alert gate |
| AIMS evaluation scheduler | `sentinel/systemd/aims-split-evaluation@.{service,timer}` | deterministic one-thread replay, 6h bound; waits for complete phase set and never trains/promotes |
| AIMS systemd runner | `sentinel/systemd/aims-normal-matrix.service` | disconnect-safe single matrix with low scheduling priority |
| AIMS resume state | `.aims-normal-matrix-active` trên VM, không commit | giữ root qua restart; valid phase được verify, invalid phase chuyển `rejected/` |
| AIMS traffic regimes | `ml-service/set_aims_traffic_regime.sh` | deterministic steady/burst/recovery/toolmix/idle traffic |
| AIMS blind attack contract | `ml-service/aims_blind_attack_contract.json` | frozen source/binary hash, scenarios, seeds, rates and safety boundary |
| AIMS blind matrix | `ml-service/run_aims_blind_matrix.py` | shuffled 8-workload x 5-trial x 5-scenario kernel evaluation; preserves complete misses against rerun/cherry-picking; no promotion |
| Bounded kernel harness | `ml-service/run_kernel_regression.py` | bounded Kubernetes transport, exact-binary fallback, attack acknowledgement, pod preventive-control snapshot và post-injection sensor visibility |
| AIMS blind attack scheduler | `ml-service/run_aims_blind_attack.sh`, `sentinel/systemd/aims-blind-attack.{service,timer}` | waits for exact blind-normal candidate/calibration/split hashes, resumes valid trials and quarantines failures |
| Finite-sample behavior gate | `ml-service/graph_signals.py`, `ml-service/build_phase_dataset.py` | one-sided 95% Wilson lower bound and row-aligned validation event counts prevent low-volume rate noise from becoming kernel evidence |
| Paper statistics | `ml-service/paper_statistics.py` | validates every blind-trial SHA, merges disjoint normal splits, emits stratified metrics plus trial/workload block bootstrap and phase/run false-alert sensitivity |
| Frozen AIMS fit-v2 evidence | `validation-evidence/aims-fit-v2-20260805/` | two disjoint normal reports, aggregate plus 40 hash-valid nested blind reports, and byte-reproducible statistics JSON/Markdown |
| Baseline/ablation contract | `ml-service/evaluation_matrix_contract.json` | V8 paired-replay release, new frozen seeds, 20 normal phases/5 independent runs and minimum attack trials |
| Syscall evaluation protocol | `ml-service/syscall_evaluation_protocol.json` | exact score/gate/confirmation semantics for 11 syscall methods; transparently frozen after normal capture start but before candidate fit/blind attack |
| V8 capture split | `ml-service/v8_capture_split_contract.json`, `validate_v8_capture_contract.py` | one whole fit run plus five whole independent evaluation runs; binds release/schema/vocabulary before collection |
| V8 capture service | `sentinel/systemd/aims-v8-capture.service`, `ml-service/run_aims_normal_matrix.sh` | 28.8-hour disconnect-safe matrix; snapshots code/vocab/unit, probes endpoints, archives traffic errors, quarantines incomplete phases and canonical-merges 24 captures |
| V8 fit/evaluation path | `build_phase_dataset.py`, `evaluate_aims_normal_split.py`, `run_aims_split_evaluation.sh`, `run_v8_post_capture.sh` | native V8 split handling: run-01 fit only, run-02--06 one terminal independent evaluation; checks terminal capture hashes and blocks evaluation while capture is active |
| V8 background handoff | `deploy_and_run_v8_post_capture.sh`, `v8_post_capture_STAGING_SHA256SUMS`, `sentinel/systemd/aims-v8-post-capture.{service,timer}` | hash-gated atomic staging deploy after capture success; bounded one-CPU/no-promotion background fit and terminal replay |
| Falco paired baseline evidence | `falco_evidence_collector.py`, `sentinel/systemd/aims-v8-falco-evidence.service` | backfills from run-02 boundary, reads all six real Falco DaemonSet outputs, separates clean API EOF/reconnect from actual stream failure, and stores only privacy-safe AIMS rule decisions plus continuity/provenance |
| Falco normal evidence finalizer | `falco_evidence_finalizer.py`, integrated by `run_v8_post_capture.sh` | fail-closed mapping of privacy-safe Falco alerts onto exactly 20 independent normal phases; accepts explicit zero-row artifact only with live six-reader coverage and publishes immutable SHA-256 bundle |
| Falco blind-attack finalizer | `falco_attack_evidence_finalizer.py`, integrated by `run_v8_blind_attack.sh` | maps privacy-safe Falco decisions to exactly 200 same-pod injection horizons, reports Wilson recall CI and latency, and gates the terminal attack marker on fresh six-reader coverage |
| V8 blind attack contract | `v8_blind_attack_contract.json` | derives five seeds from the evaluation contract frozen before capture, binds split/source/binary hashes, requires sequence capture and forbids training/tuning/promotion |
| V8 blind attack handoff | `run_v8_blind_attack.sh`, `sentinel/systemd/aims-v8-blind-attack.{service,timer}` | starts only after terminal independent normal pass, requires fresh healthy Falco coverage, runs bounded 200-injection matrix and preserves complete misses |
| V8 canonical attack replay | `run_aims_blind_matrix.py`, `merge_feature_captures.py`, `build_feature_replay_dataset.py` | validates and merges every child capture, requires exactly 200 injection intervals, labels only by same-pod interval and records labels_used_for_training=false |
| Attack observability audit | `ml-service/audit_attack_observability.py` | post-hoc construct-validity check over hash-bound target-pod windows; reports scenario syscall visibility separately, never relabels primary blind misses and never feeds training/tuning |
| Baseline/ablation validator | `ml-service/evaluation_matrix_validation.py` | independently gates syscall or agent track; refuses missing capture hash, unpaired/incomparable results and blind-set leakage |
| V8 normal ablation replay | `ml-service/run_v8_normal_ablation_matrix.sh`, `sentinel/systemd/aims-v8-normal-ablation.{service,timer}` | post-attack resumable IF/LSTM/EVT plus three detector-gate replays; preserves false alerts and never promotes |
| Shared-workload routing ablation | `ml-service/train_shared_workload_candidate.py`, `SharedWorkloadModelManager` | fits exactly one pooled model from run-01 only, preserves workload-specific behavior limits, creates independent fit-only calibration and replays unchanged run-02--06 holdouts |
| V8 paired attack replay | `ml-service/evaluate_aims_attack_replay.py` | resets detector and fit-only calibration per captured injection group, validates the exact 8×5×5 blind matrix, and emits trial recall/Wilson CI plus confirmation latency for every ML baseline/ablation |
| Tetragon paired rule baseline | `ml-service/evaluate_tetragon_rule_replay.py` | replays the frozen sensitive-syscall rule on the same 20 normal phases and 200 attack intervals; emits alert-rate, Wilson recall CI and hash-checked evidence |
| Terminal syscall matrix assembler | `ml-service/assemble_syscall_evaluation_matrix.py` | atomically combines two rule baselines and nine paired ML baseline/ablations; binds both canonical captures, protocol/code/environment provenance, validates all 11 results and publishes one checksum manifest |
| Paired syscall paper statistics | `ml-service/analyze_syscall_evaluation_matrix.py` | verifies identical attack trials and normal phases across all methods; emits 55 exact McNemar/Holm comparisons, workload/run-block bootstrap, exact run-level false-alert sign-flip tests, detected-latency CDF and censor-aware restricted time-to-detection |
| Generalization V9 protocol | `ml-service/generalization_evaluation_contract.json`, `validate_generalization_contract.py` | pre-evidence LOWO/version-shift/cross-cluster contract; requires cluster/image/version identity, new seeds, no held-out calibration/refit and hash-bound V8 parents |
| Live fast-path normal finalizer | `ml-service/fast_path_normal_evidence_finalizer.py`, `v8_fast_path_normal_contract.json` | freezes retrospective privacy-safe early warnings over exactly 20 normal holdout phases; gates runtime source/unit identity, service continuity, Tetragon health and telemetry corruption without claiming replay or statistical FPR |
| Syscall paper table renderer | `ml-service/render_syscall_paper_results.py` | deterministically emits Markdown/CSV from all 11 checksum-bound results and paired statistics; keeps early-warning/confirmation lanes separate and embeds non-overclaiming limitations |
| Paired feature-window capture | `SENTINEL_FEATURE_CAPTURE=aggregate|sequence` plus dedicated `SENTINEL_FEATURE_CAPTURE_PATH` | v2 rows bind release/run/phase/regime and keep sparse vectors/counts or syscall-name sequence separate from general telemetry; never stores acknowledgements/arguments/payloads |
| Canonical capture freeze | `ml-service/merge_feature_captures.py` | validates and hash-binds every source, deterministic ordering, rejects cross-file overlap/duplicate injection evidence before atomic output |
| Feature-capture integrity gate | `ml-service/validate_feature_capture.py` | validates schema/privacy, sparse-vector bounds, counts/sequence consistency, duplicate/overlapping windows and source SHA-256 |
| Paired replay dataset builder | `ml-service/build_feature_replay_dataset.py` | joins feature windows only to explicit same-pod injection start/end intervals, rejects incomplete/failed injections and writes dataset SHA-256 manifest |
| AIMS counterbalanced overhead harness | `sentinel/benchmarks/{measure_phase,compare_overhead,aggregate_counterbalanced_overhead}.py`, `run_aims_overhead_{matrix,counterbalanced}.sh` | 10×30s wrk per phase, six phase orders, zero socket/HTTP-error gate, 18 phase-report hashes, resumability and paired experiment-block bootstrap |
| Frozen AIMS overhead V2 | `validation-evidence/aims-overhead-v2-20260805/` | 6 order blocks, 18 phase reports/180 zero-error repetitions, copied-bundle local regeneration identical to collector aggregate |
| V8 post-terminal overhead gate | `validate_v8_overhead_prerequisites.py`, `run_v8_overhead_counterbalanced.sh`, `sentinel/systemd/aims-v8-overhead.{service,timer,env}` | waits for terminal normal/blind/ablation evidence, binds V8 candidate/calibration/policy hashes, runs six counterbalanced production blocks without tuning/promotion and publishes checksums only after all quality gates pass |
| V8 overhead deploy bundle | `deploy_v8_overhead.sh`, `v8_overhead_STAGING_SHA256SUMS` | verifies an immutable staging bundle, runs focused tests, atomically installs runtime files and arms only the marker-gated timer |

## Provenance

- Snapshot training JSONL phải có `review_status=approved_normal`.
- `snapshot_dataset.py` tạo/kiểm tra SHA-256 provenance.
- Model candidate không tự promote; promotion cần holdout và review độc lập.
- Ghi kernel version, image digest, chart version, commit hash, seed và timestamp
  cho từng trial.

## Kết quả không được suy diễn

Unit/replay result không chứng minh detection rate production, false-positive
rate dài hạn, hay end-to-end latency trên kernel. Các claim này cần matrix trong
`PAPER_READINESS_PLAN.md`.
