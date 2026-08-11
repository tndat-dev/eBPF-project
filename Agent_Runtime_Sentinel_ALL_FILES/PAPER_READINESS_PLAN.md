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

Trạng thái thực thi ngày 05-08-2026: normal matrix AIMS đã đóng băng đủ 20
phase, `86414.760802s`, 135.378 workload windows và toàn bộ `SHA256SUMS` pass.
Fit-v2 chỉ dùng run-01 đã pass development gate. Independent run-02--03 đã
pass 8/8 phase, 54.151 windows, 0 alert/detection; report SHA-256 bắt đầu bằng
`c08d5bc3`. Blind-normal run-04--05 cũng pass 8/8 phase, 54.166 windows,
0 alert/detection; report SHA-256 bắt đầu bằng `eb1d8b8b`. Blind attack đã hoàn
tất 40/40 workload-trial và detect 195/200 scenario; report aggregate SHA-256
`b14c3abd...`. Năm miss đều là `namespace_probe` trên workload có Localhost
seccomp/AppArmor. Candidate bị từ chối promotion; không được dùng run-02--05
hay blind attack này để tune lại fit-v2.

Aggregate terminal được giữ byte-immutable cả khi promotion fail. Timer của
experiment đã disable; chạy lại runner trả exit 8 nhưng SHA-256 vẫn
`b14c3abd...`. Bản từng bị thay riêng `resumed_at` được giữ dưới `rejected/` để
audit, không được dùng làm paper input.

Derived statistics kiểm đủ hash 40 report: recall 0,975 (Wilson 95% CI
0,9428--0,9893), F1 mô tả 0,9873; gộp 108.182 eligible normal window có 0
observed alert, Wilson upper bound 3,5508e-5/window. Fast early-warning n=75 có
p50 0,453s, p95 0,761s; ML confirmation n=195 có p50 18,550s, p95 20,587s;
inference riêng p50 40,101ms. Năm miss cũng là năm fast-path expected không
matched, trong khi attack ack và sensor health đều pass.

Failure analysis cho thấy workload miss dùng `Localhost` seccomp
`profiles/aims-runtime.json` và AppArmor `aims-restricted`; post-injection ML
window không có suspicious syscall mass. Đây vẫn là end-to-end false negative,
đồng thời chỉ ra observability gap khi preventive control chặn syscall trước
điểm probe. Harness V8 ghi pod security profile và post-injection sensor signal
để không đánh đồng attack process chạy với attack feature đã tới detector.

Counterbalanced overhead campaign `20260805T063700Z` đã chạy đủ sáu phase-order
nhưng bị quality audit reject vì non-2xx/socket error làm throughput biểu kiến
nhảy sai. Harness mới fail-closed trên từng warm-up/repetition, kiểm hash 18
phase report và dùng tải bền vững `wrk -t2 -c8`; campaign V2
`20260805T093000Z` đã hoàn tất đủ sáu block/180 repetition, zero failed response
và aggregate validator pass. Local regeneration giống byte-for-byte collector
output (`323bd581...`). Full-vs-no-tracing median p99 effect là 2,702%, block
bootstrap CI [-2,249%; 4,767%]; chưa phát hiện effect khác 0 và vẫn chỉ là một
cluster campaign.

Baseline/ablation V8 phải dùng paired replay thay vì inject lại riêng cho từng
method. Runtime có capture opt-in `aggregate` (sparse vector + syscall counts)
hoặc `sequence` (thêm ordered syscall names cho fast-path/rule ablation), mặc
định `off`. Artifact cấm process arguments, payload, file content và network
data. Capture mới phải được freeze/hash trước evaluation; evidence V7 cũ không
đủ feature windows nên không được bịa baseline result từ decision summary.

Contract V8 draft ngày 05-08 được thay trước khi capture bởi
`v8-paired-replay-20260811` sau khi tách telemetry và khóa schema v2, với seed mới
`1901,3203,4703,6701,9001`. Normal gate tách đúng 20 traffic phase và 5
independent run; không gọi 20 phase là 20 run. Syscall và agent-runtime có thể
validate độc lập bằng `--track`, nhưng mỗi track vẫn fail nếu thiếu bất kỳ
baseline/ablation nào hoặc capture/dataset/split/environment hash khác nhau.

Normal capture V8 bắt đầu sạch lúc `2026-08-11T06:00:57Z` bằng systemd. Root
snapshot code/unit/vocab, endpoint probe và traffic error logs theo phase; một
partial preflight trước đó đã quarantine và cấm sử dụng. Run-01 là fit-only,
run-02--06 mới là năm independent evaluation run. Campaign cần khoảng 28,8 giờ
và chưa tạo metric model mới khi còn active.

Một reader Tetragon exit giữa phase đầu làm `stream_failures=1`; collector đã
fail-closed, quarantine toàn phase và systemd retry từ `07:14:35Z`. Hai phase
thu lại đầu tiên pass continuity; ETA mới khoảng `2026-08-12T12:05Z`. Pipeline
hậu kỳ đã có native role V8: chỉ run-01 được fit, toàn bộ run-02--06 là một
terminal independent evaluation, không chia/tune hậu nghiệm. Patch này chỉ
deploy sau capture; isolated VM tests đạt `31 passed`.
Post-capture runner còn giữ cùng experiment lock và bắt buộc calibration
provenance hash-bind fit dataset/candidate trước terminal replay.
Timer handoff đã được cài thực tế lúc `12:01:12Z`; staging checksum 12/12 và
focused VM suite `30 passed`. Integration start trong khi collector active trả
75, không tạo completion marker và không sửa runtime source.
Run-01 đã hoàn tất đủ bốn phase sạch lúc `12:05Z`; run-02 evaluation bắt đầu
với live capture context/hash/schema đúng contract. Không train candidate khi
20 evaluation phase còn đang được thu.

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
