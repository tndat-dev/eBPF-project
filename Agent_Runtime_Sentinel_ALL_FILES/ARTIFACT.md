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
| AIMS normal matrix | `ml-service/run_aims_normal_matrix.sh` | 20 independent phase captures, 24 hours by default, hashes and sensor health |
| AIMS matrix validator | `ml-service/aims_matrix_validation.py` | fail-closed on missing/time-collapsed/tampered or sensor-degraded evidence |
| AIMS systemd runner | `sentinel/systemd/aims-normal-matrix.service` | disconnect-safe single matrix with low scheduling priority |
| AIMS resume state | `.aims-normal-matrix-active` trên VM, không commit | giữ root qua restart; valid phase được verify, invalid phase chuyển `rejected/` |
| AIMS traffic regimes | `ml-service/set_aims_traffic_regime.sh` | deterministic steady/burst/recovery/toolmix/idle traffic |
| AIMS blind attack contract | `ml-service/aims_blind_attack_contract.json` | frozen source/binary hash, scenarios, seeds, rates and safety boundary |
| AIMS blind matrix | `ml-service/run_aims_blind_matrix.py` | shuffled 8-workload x 5-trial x 5-scenario kernel evaluation; no promotion |
| Paper statistics | `ml-service/paper_statistics.py` | confusion metrics, Wilson interval, latency CDF and deterministic bootstrap CI |
| Baseline/ablation contract | `ml-service/evaluation_matrix_contract.json` | frozen experiment IDs, seeds and minimum independent trials |
| Baseline/ablation validator | `ml-service/evaluation_matrix_validation.py` | refuses incomplete or incomparable result matrices and blind-set leakage |

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
