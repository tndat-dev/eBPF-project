# Trạng thái thực nghiệm chọn kênh syscall

Cập nhật trạng thái: **12/10/2026**. C1 lịch sử đã hoàn tất **608/608 fit** trên
VM `.234`, nhưng chỉ lưu prediction/score chứ không có model pickle. Refit C2
để tạo đủ artifact hiện đang chạy; đây chưa phải blind recall hay kết quả
confusion matrix.

## Audit phục vụ blind evaluation — 12/10/2026

Đã đọc trực tiếp output `/home/dat/sentinel-pulse-syscall-feature-c1/runs/attempt-000002`
trên VM: có đủ 608 prediction `.npz` (thư mục tổng **9,9 MB**) nhưng **không có
classifier pickle nào**. Trường `serialized_estimator_bytes` chỉ là kích thước
ước lượng từ `pickle.dumps(estimator)` trong lúc fit; tổng **2.335.533.494 byte**
là ước lượng cho estimator, không phải model bundle đã lưu. `train_seconds` cộng
trên 608 fit cũ là **19.501,4 giây tích lũy**, không phải wall-clock duration.

Do đó chưa thể đem 608 biến thể cũ chạy blind từ output hiện có. C2 lưu đầy đủ
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

Trạng thái SSH mới nhất: systemd job `pulse-syscall-variant-models-c2.service`
đang chạy nền trên `.234`; `attempt-000002` đã ghi **37/608 fit**, đang fit
`drop_mmap` cho `production/aims-kafka-dual-role:kafka`. C2 tiếp tục chạy riêng;
không bị pilot syscall-ID đụng vào. Có model artifacts trong output;
thư mục khoảng 24 MiB, RSS đỉnh khoảng 1 GiB. `attempt-000001` được giữ nguyên với lỗi
`NameError` trong writer artifact; lần fit đầu không được ghi nhận và artifact
không được seal. Writer đã sửa, smoke test trên VM pass. NFS
`10.1.16.233:/sentinel-pulse` mount tại
`/mnt/sentinel-pulse-archive`, còn khoảng **344 GiB**; output C2 nằm riêng ở đó.
Job giới hạn CPU 150%, RAM 4 GiB. Cần theo dõi tiếp STATUS/log và xác minh
terminal + manifest SHA sau khi hoàn tất.

Unit riêng cho lần refit có lưu artifact tại
[`pulse-syscall-variant-models-c2.service`](sentinel_pulse/systemd/pulse-syscall-variant-models-c2.service).
Nó dùng VM venv đã có, CPU quota 150%, RAM tối đa 4 GiB, output riêng trên NFS
và refit lại score-only checkpoint mà không nhận nhầm score cũ thành model.

SSH snapshot cùng ngày: sáu node Kubernetes đều `Ready`, nhưng namespace
`production` còn pod trạng thái `Evicted`, `Error`, `ContainerStatusUnknown`;
các bản ghi cũ không được coi là workload bình thường hoặc xóa để làm sạch
kết quả. Trước attack phải đăng ký lại exact target pod/UID/container trên
những replica hiện Ready và ghi health context. Không có attack nào được tiêm
trong lượt kiểm tra này.

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

Job C2 hiện chạy qua systemd trên VM `.234`, độc lập SSH/laptop. Attempt
`attempt-000002` đang ở workload `production/aims-kafka-dual-role:kafka`, biến thể
`drop_mmap`; `completed_fits=37/608` tại lần kiểm tra mới nhất (12/10/2026
12:11:36 UTC). Đọc `STATUS.json`
và journal để cập nhật số fit, không ước lượng hoàn thành từ CPU time.

| Thành phần | Giá trị |
|---|---|
| Unit đang chạy | `pulse-syscall-variant-models-c2.service`, enabled tại `multi-user.target`, user `dat` |
| Giới hạn tài nguyên | CPU quota 150%, RAM tối đa 4 GiB, không swap, nice 15 |
| Input | `/home/dat/sentinel-pulse-syscall-feature-c1/inputs` |
| Checkout C2 | `/home/dat/eBPF-project-syscall-variants-c2`, commit `ce4177a`, ML module hashes khớp checkpoint C1 |
| Output campaign | `/mnt/sentinel-pulse-archive/syscall-variant-artifacts-c2/runs` trên NFS `.233` |
| Attempt hiện hành | `attempt-000002`; attempt-000001 lỗi được giữ nguyên, checkpoint C1 không sửa |
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
- Không attach collector mới, inject attack, deploy subset hoặc tune model/policy. Soak production đã completed lúc 12:42:20 ngày 07/10; model/policy/raw seals giữ nguyên, không relaunch soak. [Trạng thái soak](SOAK_OBSERVATION_STATUS.md).
- Soak normal 24 giờ đã kết thúc lúc 12:42:20 ngày 07/10 theo receipt cũ; không có soak hay blind attack đang chạy tại snapshot 12/10. Sáu node đều Ready, nhưng `production` có 20 Evicted, 5 Error, 6 ContainerStatusUnknown và 4 Completed; worker3 có workload AIMS/traffic generator đang chạy. Không gộp pod lỗi/unknown vào normal hoặc TN.
- Thêm collector pilot tách biệt `ebpf/syscall_histogram.bpf.c` + loader: per-ID counts theo cgroup, map cap 65.536 keys, drop counter và duration bắt buộc; Make target không đụng collector đang cài. Nhánh `experiment/syscall-id-histogram-pilot` đã push qua commit `cb6c94e`. Build lại chính commit này trên worker3 (.239; Ubuntu 24.04.4, kernel 6.8.0-138, clang 18.1.3, libbpf 1.4) thành công với `-Wall -Wextra -Werror`; binary từ chối thiếu tham số (exit 2) trước khi load/attach. SHA-256 object `cee7d00dfeb27e909642c5d7e2d18bf02da3421d4ea15d1805f21b4b7f40a4c0`, loader `e744b99bc01c9633a4a8b44738f337c6b6545b8d5feabd0de4e7d55d203ba23d`.
- **Chưa attach probe và chưa có histogram/overhead result.** Lý do: production hiện chỉ có một phần workload/traffic ổn định trên worker3, 31 pod còn Evicted/Error/Unknown và 4 Completed; chưa có receipt điều khiển regime để gọi đây là normal-selection evidence. Runbook pilot yêu cầu capture riêng bounded sau khi có START + metadata/traffic binding. Cần tiếp tục cấu hình capture/evidence harness, rồi chạy instrumentation pilot; không thay đổi soak đã hoàn tất hoặc C2.
- Vòng full-ID histogram/cross-OS chưa có dữ liệu; kế hoạch cấp VM trong [SYSCALL_EXPERIMENT_VM_PLAN.md](SYSCALL_EXPERIMENT_VM_PLAN.md). Giữ nguyên scope Linux native x86_64 hiện tại đến khi kiểm chứng nền tảng khác.
