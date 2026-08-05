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
| AIMS split replay evaluator | `ml-service/evaluate_aims_normal_split.py` | exact production detector replay for frozen validation/blind-normal roles; identity-bound atomic phase checkpoints; zero-alert gate |
| AIMS evaluation scheduler | `sentinel/systemd/aims-split-evaluation@.{service,timer}` | deterministic one-thread replay, 6h bound; waits for complete phase set and never trains/promotes |
| AIMS systemd runner | `sentinel/systemd/aims-normal-matrix.service` | disconnect-safe single matrix with low scheduling priority |
| AIMS resume state | `.aims-normal-matrix-active` trên VM, không commit | giữ root qua restart; valid phase được verify, invalid phase chuyển `rejected/` |
| AIMS traffic regimes | `ml-service/set_aims_traffic_regime.sh` | deterministic steady/burst/recovery/toolmix/idle traffic |
| AIMS blind attack contract | `ml-service/aims_blind_attack_contract.json` | frozen source/binary hash, scenarios, seeds, rates and safety boundary |
| AIMS blind matrix | `ml-service/run_aims_blind_matrix.py` | shuffled 8-workload x 5-trial x 5-scenario kernel evaluation; preserves complete misses against rerun/cherry-picking; no promotion |
| Bounded kernel harness | `ml-service/run_kernel_regression.py` | bounded Kubernetes transport, exact-binary fallback, attack acknowledgement, pod preventive-control snapshot và post-injection sensor visibility |
| AIMS blind attack scheduler | `ml-service/run_aims_blind_attack.sh`, `sentinel/systemd/aims-blind-attack.{service,timer}` | waits for exact blind-normal candidate/calibration/split hashes, resumes valid trials and quarantines failures |
| Finite-sample behavior gate | `ml-service/graph_signals.py`, `ml-service/build_phase_dataset.py` | one-sided 95% Wilson lower bound and row-aligned validation event counts prevent low-volume rate noise from becoming kernel evidence |
| Paper statistics | `ml-service/paper_statistics.py` | validates every blind-trial SHA, merges disjoint normal splits, then emits stratified confusion metrics, Wilson interval, latency CDF and deterministic bootstrap CI |
| Frozen AIMS fit-v2 evidence | `validation-evidence/aims-fit-v2-20260805/` | two disjoint normal reports, aggregate plus 40 hash-valid nested blind reports, and byte-reproducible statistics JSON/Markdown |
| Baseline/ablation contract | `ml-service/evaluation_matrix_contract.json` | frozen experiment IDs, seeds and minimum independent trials |
| Baseline/ablation validator | `ml-service/evaluation_matrix_validation.py` | refuses incomplete or incomparable result matrices and blind-set leakage |
| Paired feature-window capture | `SENTINEL_FEATURE_CAPTURE=aggregate|sequence` in `ml-service/anomaly_detector2.py` | opt-in sparse vectors/counts or syscall-name sequence for replaying every baseline on identical windows; never stores arguments/payloads |
| Feature-capture integrity gate | `ml-service/validate_feature_capture.py` | validates schema/privacy, sparse-vector bounds, counts/sequence consistency, duplicate/overlapping windows and source SHA-256 |
| AIMS counterbalanced overhead harness | `sentinel/benchmarks/{measure_phase,compare_overhead,aggregate_counterbalanced_overhead}.py`, `run_aims_overhead_{matrix,counterbalanced}.sh` | 10×30s wrk per phase, six phase orders, zero socket/HTTP-error gate, 18 phase-report hashes, resumability and paired experiment-block bootstrap |

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
