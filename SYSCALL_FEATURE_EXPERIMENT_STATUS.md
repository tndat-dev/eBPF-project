# Trạng thái thực nghiệm chọn kênh syscall

Cập nhật hiện hành qua SSH: **14/10/2026, 03:14 UTC+7**. C1 `attempt-000002` và
C2 `attempt-000002` đều terminal `completed`, **608/608 fits**, `errors=[]`, 19
workload × 32 variants; không còn fit process nào chạy. C1 có prediction/score
`.npz`, không có pickle. C2 có 608 model pickle, tổng **2,362,081,485 byte**.
Manifest gốc có đường dẫn sai `models/models/<file>.pkl`; đã tạo sidecar
`/mnt/sentinel-pulse-archive/syscall-variant-artifacts-c2/runs/attempt-000002/VARIANT_MODEL_MANIFEST.derived.json`
trên NFS sau khi xác minh binding
START/RESULTS/TERMINAL và hash/size đủ 608 model. SHA-256 sidecar là
`4c379dcabd8ea2c8ca0c19f9e13e186dfa9fe63f0df1ea1a2d4d591e946c4408`; file gốc
không đổi. Đã nạp tuần tự 608/608 pickle bằng C2 venv khớp Python 3.12.3,
scikit-learn 1.9.1, NumPy 2.5.3; mọi object có estimator `predict_proba` và
calibration scores. Sau đó đã **replay 608/608 model** bằng đúng C2 venv:
score sai lệch lớn nhất **0**, conformal p-value và quyết định khớp prediction
đã seal. Artifact: `/mnt/sentinel-pulse-archive/syscall-variant-replay-c3/TERMINAL.json`.
Replay dùng context cũ đã xem; chưa phải phép đo chất lượng độc lập.

## Job C3 đã triển khai

`pulse-syscall-capture-c3.service` trên `.234` đang **active/running, enabled,
NRestarts=0**, source `b14f888c28e1d7d8752d19fd4d88457d38063a3a`. Trạng thái
`collecting`, đang thu `selection-recovery`. Đã chấp nhận **4/10 phase (40%)**:
selection steady, toolmix, peak, burst — tương đương **12/30 capture worker**.
Chưa có rejected attempt trong bốn phase này. Output:
`/mnt/sentinel-pulse-archive/syscall-capture-c3-r2`.

Ba worker đã build histogram loader/object và projected counter. Coordinator
tự đợi soak đủ 86.400 giây/node, rồi thu selection qua **steady, toolmix, peak,
burst, recovery**; tiếp theo thu năm regime thành **holdout riêng**. Mỗi regime
300 giây baseline + 600 giây probe + 300 giây post, ba worker song song.
Probe thu full-ID histogram 1 giây và feature legacy 249 chiều/500 ms.
Chi tiết cấu hình, receipt, recovery, giới hạn và lệnh xem ở
[SYSCALL_CAPTURE_C3.md](SYSCALL_CAPTURE_C3.md).

Soak `normal-a1-20261013` đã có terminal **`completed_observation` trên cả ba
worker**, không còn tiến trình capture. Số đo trực tiếp:

| Worker | Boundary exposure | Tiến độ / 86.400 s | Capture errors | Capacity pauses |
|---|---:|---:|---:|---:|
| `.237` / worker1 | 86.400,249 s | 100% | 0 | 0 |
| `.238` / worker4 | 86.400,297 s | 100% | 0 | 0 |
| `.239` / worker3 | 86.400,390 s | 100% | 0 | 0 |

Tổng **33.149.479 feature rows** trong capture soak. Shadow vẫn active và giữ
nguyên source/model/policy: worker1 còn đọc backlog, row cuối có event age
**7.627,28 s**; worker4 row cuối `candidate-model-unavailable`, chênh
`processed_at - window_end` **16.515,10 s**. Worker3 đã đọc tới cuối capture,
row cuối có event age **0,01164 s**. Đây là mẫu row cuối, không phải p95 hay
kernel-to-alert. **100% capture không có nghĩa 100% đánh giá/model stable.**

C3 còn khoảng hai giờ thu holdout cùng chuyển phase/copy. Kiểm tra khoảng
**05:30–06:00 ngày 14/10 (UTC+7)** nếu không phải retry. Đây là ETA capture,
không phải cam kết hoàn thành blind evaluation hoặc công bố syscall tối ưu.

**38 regression tests pass** cho campaign, sidecar, histogram/cohort, manifest,
paired statistics và feature compatibility audit. Smoke sidecar thực trên cgroup
riêng ở control plane đã tạo **22 feature rows**, schema legacy đúng, malformed=0,
exit=0; không dùng smoke này để train/evaluate. Service có checkpoint và khởi động cùng VM; mất SSH/laptop
không dừng job. Worker reboot làm attempt dở được ghi nhận và thu bổ sung;
không bỏ các phase đã hoàn tất. Không có zero-alert gate.

Evidence đọc qua SSH: `/home/dat/pulse-syscall-capture-c3/inspection-20261014-0315.json`.
Preflight mới `sentinel_pulse/variant_capture_audit.py` chỉ đọc capture đã seal,
kiểm tra schema/identity/revision/cadence và history bốn window liền kề; không
chấm score hoặc chọn feature trên holdout. Code audit triển khai riêng dưới
`/home/dat/pulse-syscall-audit-c3-20261014/source`, không sửa source C3 đang chạy.
Audit đã xong 12 capture selection: 313.318 rows, 269.036 context đủ điều kiện
đầu vào, 6.592 warming, 37.659 thiếu model C2, 31 ngoài biên probe; 2.492 history
gap resets. Không có mismatch schema/revision hoặc collector integrity flag
trong phần đã audit. Đây không phải kết luận false-positive/recall.

## Những bằng chứng vẫn cần hoàn tất

So sánh START C1/C2 cho thấy cả sáu input hash giống nhau, cùng 19 workload,
split/history/alpha/window và cùng hash của `model.py`, `features.py`,
`train.py`, `encoding.py`; chỉ experiment driver có hash khác. Vì vậy đây là
hai lần chạy trên cùng dữ liệu/model logic, **không phải xác nhận độc lập**.
Các ablation vẫn exploratory; precision, recall, kernel-to-alert và confusion
matrix chưa được đo bằng blind set mới.

C2 attempt-000001 được giữ với lỗi `NameError: os is not defined`; attempt-000002
hoàn tất sạch. C1 attempt-000001 được giữ với lỗi checkpoint ranking mismatch;
attempt-000002 hoàn tất và tái sử dụng 59 fit đã xác minh. Unit C2 báo
`active (exited)` vì `Type=oneshot`; terminal xác nhận đã kết thúc, không phải job
còn chạy.

## Audit phục vụ blind evaluation — 12/10/2026

Đã đọc trực tiếp output `/home/dat/sentinel-pulse-syscall-feature-c1/runs/attempt-000002`
trên VM: có đủ 608 prediction `.npz` (thư mục tổng **9,9 MB**) nhưng **không có
classifier pickle nào**. Trường `serialized_estimator_bytes` chỉ là kích thước
ước lượng từ `pickle.dumps(estimator)` trong lúc fit; tổng **2.335.533.494 byte**
là ước lượng cho estimator, không phải model bundle đã lưu. `train_seconds` cộng
trên 608 fit cũ là **19.501,4 giây tích lũy**, không phải wall-clock duration.

Output C1 không đủ để chạy lại model; **C2 hiện đã lưu đầy đủ**
`PulseExtraTrees` cùng SHA-256; checkpoint score-only không được tính là fit có
thể tái sử dụng. Khi đủ 608 artifact, job tạo `VARIANT_MODEL_MANIFEST.json`
bind workload, variant, mask, file hash, train/calibration dataset và run. Đây
vẫn là bundle phát triển, không phải serving artifact hay promotion.

Regression syscall-feature/campaign: **36 test pass**. Khởi động C2 lần đầu bị
launcher bỏ qua checkpoint `completed` dù thiếu manifest; lần kế tiếp integrity
check chặn vì `features.py` hiện tại khác source C1. Không fit nào chạy trong hai
lần đó. Đã sửa launcher và tạo nhánh refit từ đúng source ML C1
(`8976daa`), giữ nguyên hash `features.py`, `model.py`, `train.py`, `encoding.py`;
nhánh `experiment/syscall-variant-artifacts-8976` tại commit `4628e7b` đã push.

Trạng thái hiện hành: `pulse-syscall-variant-models-c2.service` đã chạy xong trên
`.234`; terminal attempt-000002 xác nhận 608/608, không lỗi. NFS
`10.1.16.233:/sentinel-pulse` mount tại `/mnt/sentinel-pulse-archive`; output C2
nằm riêng ở đó. Job đã được giới hạn CPU 150%, RAM 4 GiB. Manifest hiện tại có
đường dẫn artifact lặp `models/`; audit đã xác minh đủ 608 artifact qua đường dẫn
và hash trong `RESULTS.json`. Manifest gốc không bị thay đổi. Sidecar dẫn xuất
đã được phát hành trên NFS với provenance; load và replay 608/608 đã hoàn tất.

Unit riêng cho lần refit có lưu artifact tại
[`pulse-syscall-variant-models-c2.service`](sentinel_pulse/systemd/pulse-syscall-variant-models-c2.service).
Nó dùng VM venv đã có, CPU quota 150%, RAM tối đa 4 GiB, output riêng trên NFS
và refit lại score-only checkpoint mà không nhận nhầm score cũ thành model.

SSH snapshot 12/10: sáu node Kubernetes đều `Ready`; trước cleanup, production
có 31 pod terminal Evicted và Velero có 53 pod terminal Evicted do các đợt
DiskPressure/ephemeral-storage. Đã lưu nguyên nhân và hiện trạng sau cleanup ở
[CLUSTER_READINESS.md](CLUSTER_READINESS.md); không tính các khoảng này là normal
hay TN. Trước attack phải đăng ký exact target pod/UID/container của replica
hiện Ready và ghi health context. Không có attack nào được tiêm trong lượt này.

Protocol
[`syscall-selection-evaluation-v1.json`](sentinel_pulse/protocol/syscall-selection-evaluation-v1.json)
đang ở trạng thái `planned_not_executed`: chưa có normal test độc lập mới,
binary/case blind mới, confusion matrix hay kernel-to-alert cho từng biến thể.
Sau khi C2 được seal, cần freeze model/policy; thu normal độc lập; đăng ký hash
binary/case và lịch trial trước khi chạy; giữ cùng trial/seed/rate cho mọi biến
thể; chấm TP/FP/TN/FN cùng uncertain/missing telemetry. Replay paired dùng để
so sánh confusion/inference; **không** đại diện kernel-to-alert. Latency thật
cần trial live, đo từ timestamp syscall injection đã bind tới alert và giữ
miss/censored trong mẫu số. Không tune trên blind set rồi gọi lần chạy lại là
blind xác nhận.

## Phạm vi đã triển khai

Module [syscall_feature_experiment.py](sentinel_pulse/syscall_feature_experiment.py), điều phối bởi [syscall_feature_campaign.py](sentinel_pulse/syscall_feature_campaign.py), chạy từ checkout sạch, đóng băng commit `8976daa457580f60345ded588f28f7662d256853`. Kiểm tra hash model manifest, normal training dataset, training contract, analysis và context archive trước khi fit.

Mỗi workload có 32 biến thể: full, bỏ lần lượt bốn kênh tường minh của từng syscall trong 29 syscall, bỏ toàn bộ kênh tường minh, và giữ top-16 theo phần training cộng whitelist nhạy cảm. Mask áp dụng tại cả bốn vị trí temporal. Hash bins/aggregate vẫn giữ, nên đây không phải loại toàn bộ thông tin của syscall đó.

19 workload có holdout × 32 biến thể = **608 fit dự kiến**. Holdout thiếu notification/payment; không tuyên bố phủ 21/21. Top-16 dùng proxy `expm1(log_count)` từ float32 trên training prefix, không phải histogram full-ID exact mới. Calibration/holdout không tham gia chọn top-16.

Scientific stack cài riêng trên VM trùng job host: Python 3.12.3, scikit-learn 1.9.1, NumPy 2.5.3, joblib 1.6.0, SciPy 1.18.1. Software khác reference original; không gọi là tái lập bit-for-bit model production. Timing của các fit nhập từ host giữ provenance riêng, **không gộp với timing VM**.

## Chạy ngầm và phục hồi

Job C2 đã chạy qua systemd trên VM `.234`, độc lập SSH/laptop. Attempt
`attempt-000002` hiện có terminal `completed_fits=608/608` (12/10/2026 18:04 UTC).
Đọc `STATUS.json`
và journal để cập nhật số fit, không ước lượng hoàn thành từ CPU time.

| Thành phần | Giá trị |
|---|---|
| Unit | `pulse-syscall-variant-models-c2.service`, `active (exited)` sau khi oneshot hoàn tất; enabled tại `multi-user.target`, user `dat` |
| Giới hạn tài nguyên | CPU quota 150%, RAM tối đa 4 GiB, không swap, nice 15 |
| Input | `/home/dat/sentinel-pulse-syscall-feature-c1/inputs` |
| Checkout C2 | `/home/dat/eBPF-project-syscall-variants-c2`, commit `ce4177a`, ML module hashes khớp checkpoint C1 |
| Output campaign | `/mnt/sentinel-pulse-archive/syscall-variant-artifacts-c2/runs` trên NFS `.233` |
| Attempt hiện hành | `attempt-000002`; attempt-000001 lỗi được giữ nguyên, checkpoint C1 không sửa |
| Terminal | `completed`, 608/608, errors rỗng; không tự promotion |
| Tự phục hồi | Restart on failure sau 60 giây, boot enablement; lỗi binding/checksum exit 65 để điều tra |

Output có START, STATUS, RESULTS, prediction/model artifacts, SHA-256 manifest và TERMINAL. Raw data không đưa vào Git. Campaign dùng single-writer lock, checkpoint và output riêng; job `Type=oneshot` hiển thị `activating/start` trong lúc fit, không có startup deadline 120 giây. Mất SSH/laptop không dừng job; VM reboot thì systemd tiếp tục từ checkpoint. Job này là offline experiment, không gắn collector và không inject attack.

```bash
# Trên VM .234, lệnh chỉ đọc
systemctl status pulse-syscall-variant-models-c2.service --no-pager
journalctl -u pulse-syscall-variant-models-c2.service -n 20 --no-pager
cat /mnt/sentinel-pulse-archive/syscall-variant-artifacts-c2/runs/attempt-000002/STATUS.json
```

## Giới hạn kết luận và bảo vệ soak

- Holdout normal độc lập với training nhưng đã được xem trong phân tích trước: kết quả **exploratory**, cần tập đánh giá mới để xác nhận lựa chọn.
- Raw model anomaly rate không phải policy alert FPR. TP/FP/TN/FN, precision, attack recall và kernel-to-alert giữ `null` khi chưa có ground truth/phép đo tương ứng. Inference timing trên host có quota không phải latency production.
- C3 đang chờ capture soak hoàn tất trước khi đổi traffic hoặc attach probe worker. Model/policy/raw seals của soak giữ nguyên. Exact-ID pilots trước đó là các run riêng đã kết thúc.
- Soak đang chạy là một normal capture có thể cung cấp tập đánh giá tương lai nếu protocol freeze/adjudication cho phép; chưa tính nó là holdout hợp lệ khi chưa chốt trước phân tích, nhãn và điều kiện tách biệt. Các khoảng thiếu telemetry/hạ tầng không được tính là normal/TN.
- Thêm collector pilot tách biệt `ebpf/syscall_histogram.bpf.c` + loader: per-ID counts theo cgroup, map cap 65.536 keys, drop counter và duration bắt buộc; Make target không đụng collector đang cài. Nhánh `experiment/syscall-id-histogram-pilot` đã push qua commit `f50dfad` (histogram race/snapshot hardening ở `cb6c94e`). Worker3 và worker1 (Ubuntu 24.04.4, kernel 6.8.0-138, clang 18.1.3, libbpf) build thành công; binary từ chối thiếu tham số (exit 2) trước khi load/attach. Loader SHA-256 `e744b99bc01c9633a4a8b44738f337c6b6545b8d5feabd0de4e7d55d203ba23d`; object worker3 `b8c13be88076036b5eff367a7c563bce17c7e932f1623224b75a32010ed922ee`, worker1 `6785c33cb190b0f72b8fdeef4a64cffc2a505d8507c06270c4e518f3de62ced4`.
- Đã thêm harness `sentinel_pulse/syscall_histogram_pilot.py` và analyzer
  `sentinel_pulse/syscall_histogram_analysis.py`: START/raw/terminal/seal,
  snapshots metadata, host/cgroup metrics, receipt traffic preregistered, kiểm
  tra interval regime/integrity. Đã thêm cohort aggregator để gộp nhiều capture
  độc lập mà không gộp revision/regime hay double-count run chồng thời gian.
  Mười regression test mới pass trên host bằng
  `PYTHONPATH=. python3 -m pytest -q tests/test_sentinel_pulse_syscall_histogram_pilot.py`.
- Exact-ID pilot độc lập trên worker1 + worker3 đã hoàn tất exit 0: 236 chu kỳ
  tổng, 3.350.093 syscall entries; analyzer hợp lệ 2/2, cohort không loại run.
  Raw/ANALYSIS/COHORT/checksum lưu ngoài Git trên NFS. Chỉ hai capture steady
  ngắn, chưa có A/B overhead, syscall ranking, blind attack hay precision/recall.
  Kết quả/giới hạn và top syscall ID ghi trong `syscall_analysis.md`/runbook.
- Cluster snapshot 12/10 13:36 UTC xác nhận 6/6 node Ready, 100/100
  Deployment/StatefulSet/DaemonSet đủ replica, 238 pod Running đều Ready và 11
  Job pod Succeeded. Không còn pod Failed/Pending; incident DiskPressure cũ
  vẫn được lưu, không tính vào normal/TN. C2 và soak cũ không bị thay đổi.
- Vòng full-ID histogram/cross-OS chưa có dữ liệu; kế hoạch cấp VM trong [SYSCALL_EXPERIMENT_VM_PLAN.md](SYSCALL_EXPERIMENT_VM_PLAN.md). Giữ nguyên scope Linux native x86_64 hiện tại đến khi kiểm chứng nền tảng khác.
