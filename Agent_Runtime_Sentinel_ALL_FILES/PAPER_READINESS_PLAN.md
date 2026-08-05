# Agent Runtime Sentinel — Paper Readiness Plan

## Mục tiêu khoa học

Không claim đơn thuần "eBPF + GAT". Claim cần kiểm chứng là: **evidence graph
kết hợp MCP semantic action và kernel runtime evidence cải thiện phát hiện
agent misuse trên Kubernetes dưới TLS, so với syscall-only và semantic-only,
trong khi giữ false-positive/overhead ở mức đo được.**

## Threat model

- Agent hoặc MCP client có thể bị prompt-injection, gọi tool quá quyền, đọc
  secret, delete resource, lateral movement hoặc chạy process bất thường.
- Attacker có thể gửi traffic TLS hợp lệ và tạo drift traffic; không giả định
  bypass kernel/hypervisor hoặc chiếm control plane.
- Probe chỉ attach process/PID trong scope; plaintext không được persist.
- Response mặc định là alert. Enforcement chỉ là thí nghiệm riêng, có rollback
  và phải báo cáo false-positive impact.

## Benchmark cần tạo

Mỗi trace phải có `run_id`, agent ID, workload, kernel/Cilium/Tetragon version,
timestamp monotonic, scenario, label, seed và hash artifact. Tách train,
validation, test **theo thời gian và agent**, không random split event.

Normal matrix tối thiểu:

1. 3 agent/tool profile khác nhau.
2. 4 traffic regime: steady, burst hợp lệ, idle/recovery, tool mix shift.
3. 5 run độc lập mỗi regime, kéo dài đủ để quan sát drift.

Split AIMS syscall đã đóng băng trước candidate fit:

- bốn phase run 01: train và development calibration 20% theo thời gian;
- tám phase run 02--03: independent validation, cấm fit/tune threshold;
- tám phase run 04--05: blind normal test, chỉ mở sau khi model và rule freeze;
- mọi candidate mới được tạo sau khi xem holdout phải mang release ID mới và
  cần evaluation độc lập mới; không được tái dùng kết quả cũ như blind test.

Contract máy đọc được là `ml-service/aims_candidate_split_contract.json`.
Builder lưu hash contract/phase/array/metadata vào dataset manifest và từ chối
phase sai role, vì vậy split này là protocol thực thi được chứ không chỉ mô tả.

Trạng thái thực thi ngày 04-08-2026: normal matrix AIMS đã đóng băng đủ 20
phase, `86414.760802s`, 135.378 workload windows và toàn bộ `SHA256SUMS` pass.
Fit-v2 chỉ dùng run-01 đã pass development gate. Independent run-02--03 đã
pass 8/8 phase, 54.151 windows, 0 alert/detection; report SHA-256 bắt đầu bằng
`c08d5bc3`. Blind-normal run-04--05 cũng pass 8/8 phase, 54.166 windows,
0 alert/detection; report SHA-256 bắt đầu bằng `eb1d8b8b`. Blind attack đã giữ
9/40 workload-trial, 44/45 scenario detect và đang resume bằng bounded
transport. Đây chưa phải kết quả cuối: baseline/ablation và overhead vẫn bị khóa theo thứ tự gate. Không
được dùng run-02--05 để tune lại fit-v2.

Sau bounded fallback, trial thứ 8 có một miss `namespace_probe` khỏe về sensor
và attack acknowledgement. Fit-v2 vì vậy đã fail frozen promotion recall 1,0.
Runner được sửa để giữ vĩnh viễn complete detection failure, không rerun đến
khi pass; matrix vẫn chạy hết cho failure analysis và confidence interval.

Attack matrix tối thiểu, 5 run/scenario:

1. secret exfiltration;
2. over-privileged kubectl;
3. production delete simulation không thực thi;
4. lateral movement simulation;
5. container escape/privilege attempt an toàn.

## Baseline và ablation bắt buộc

| ID | Hệ thống | Câu hỏi trả lời |
|---|---|---|
| B1 | Tetragon syscall-only + threshold V1 | mốc triển khai hiện hữu |
| B2 | Tetragon + EVT-POT per-pod, không MCP graph | adaptive threshold có đủ không |
| B3 | MCP semantic-only graph | kernel evidence đóng góp gì |
| B4 | Evidence graph không GAT | attention/GAT đóng góp gì |
| Full | TLS uprobe + graph + GAT + EVT-POT | kết quả hệ thống đề xuất |

Ablation: shared baseline thay per-agent; bỏ review gate; bỏ two-window
confirmation; bỏ kernel evidence. Không dùng synthetic traffic để train model
chính; synthetic chỉ được phép làm controlled stress test.

## Metrics và tiêu chí công bố

- Precision, recall, F1, FPR theo agent, workload và regime.
- Detection latency CDF: kernel event → fast alert và kernel event → confirmed
  alert; inference/ingest tách riêng.
- CPU, memory, throughput, p50/p95/p99 workload latency cho baseline,
  Tetragon-only và full system.
- Scalability theo pod count/event rate; robustness với drift và threshold
  poisoning.
- 95% confidence interval hoặc bootstrap CI cho metric chính.

Không claim zero false positive hoặc production enforcement an toàn nếu chưa có
normal soak độc lập và confidence interval tương ứng.

## Artifact bundle

- Pinned container/image digest, kernel matrix, Helm values, manifests.
- One-command scripts: deploy, collect, label, train, replay, benchmark,
  generate figures.
- Derived snapshots không chứa plaintext; raw sensitive traces có policy access.
- Seeds, expected result ranges, SHA-256 manifests, environment inventory.
- `ARTIFACT.md`, `ETHICS.md`, `REPRODUCE.md` và appendix mapping mỗi claim tới
  script/data/figure.

## Gate theo thứ tự

1. Thu capture MCP TLS từ PID lab theo normal matrix; review/label.
2. Train candidate trên clean set; holdout per-agent/time.
3. Chạy B1–B4–Full và attack matrix.
4. Chạy overhead/scalability, bootstrap CI, failure analysis.
5. Đóng artifact bundle; review ethics và reproducibility.
6. Chỉ sau đó viết claim paper và cân nhắc enforcement evaluation.
