# Trạng thái thực nghiệm chọn kênh syscall

Cập nhật trạng thái: **12/10/2026**. Job exploratory normal-only trước đó đã
hoàn thành **608/608 fit** trên VM `.234`; kết quả này chưa phải blind recall.

## Audit phục vụ blind evaluation — 12/10/2026

Đã đọc trực tiếp output `/home/dat/sentinel-pulse-syscall-feature-c1/runs/attempt-000002`
trên VM: có đủ 608 prediction `.npz` (thư mục tổng **9,9 MB**) nhưng **không có
classifier pickle nào**. Trường `serialized_estimator_bytes` chỉ là kích thước
ước lượng từ `pickle.dumps(estimator)` trong lúc fit; tổng **2.335.533.494 byte**
là ước lượng cho estimator, không phải model bundle đã lưu. `train_seconds` cộng
trên 608 fit cũ là **19.501,4 giây tích lũy**, không phải wall-clock duration.

Do đó chưa thể đem 608 biến thể cũ chạy blind từ output hiện có. Source host đã
được sửa để mỗi fit mới lưu đầy đủ `PulseExtraTrees` cùng SHA-256; checkpoint
chỉ mang sang fit có model artifact thật và bỏ qua score-only fit cũ. Khi đủ
608 artifact, job sẽ tạo `VARIANT_MODEL_MANIFEST.json` bind workload, variant,
mask, file hash, train/calibration dataset và fit run. Đây vẫn là bundle phát
triển, không phải serving artifact hay promotion.

Regression syscall-feature/campaign: **34 test pass** trên virtualenv tạm của
host. Chưa chạy lại refit 608 biến thể trên VM; chưa có file model bundle,
normal test mới, attack binary/case blind mới, confusion matrix mới hay latency
kernel-to-alert cho từng biến thể.

Unit riêng cho lần refit có lưu artifact đã được thêm tại
[`pulse-syscall-variant-models-c2.service`](sentinel_pulse/systemd/pulse-syscall-variant-models-c2.service).
Nó dùng VM venv đã có, CPU quota 150%, RAM tối đa 4 GiB, output riêng trên NFS
và resume từ score-only attempt cũ nhưng không tái dùng các fit đó. Unit chưa
được cài/bật trên VM tại thời điểm cập nhật file này.

SSH snapshot cùng ngày: sáu node Kubernetes đều `Ready`, nhưng namespace
`production` còn pod trạng thái `Evicted`, `Error`, `ContainerStatusUnknown`;
các bản ghi cũ không được coi là workload bình thường hoặc xóa để làm sạch
kết quả. Trước attack phải đăng ký lại exact target pod/UID/container trên
những replica hiện Ready và ghi health context. Không có attack nào được tiêm
trong lượt kiểm tra này.

Đánh giá đúng cần hai mức: (1) freeze 608 model artifact, capture một bộ normal
độc lập và blind attack mới, replay **cùng trace/seed/rate** qua mọi biến thể
để so sánh paired confusion matrix; (2) đo **kernel-to-alert thực tế** bằng
live execution từng biến thể với policy/runtime cố định. Offline replay có thể
đo inference nhưng không được gọi là kernel-to-alert. Tập blind đã mở không
được dùng để tune rồi báo lại như xác nhận độc lập.

## Phạm vi đã triển khai

Module [syscall_feature_experiment.py](sentinel_pulse/syscall_feature_experiment.py), điều phối bởi [syscall_feature_campaign.py](sentinel_pulse/syscall_feature_campaign.py), chạy từ checkout sạch, đóng băng commit `8976daa457580f60345ded588f28f7662d256853`. Kiểm tra hash model manifest, normal training dataset, training contract, analysis và context archive trước khi fit.

Mỗi workload có 32 biến thể: full, bỏ lần lượt bốn kênh tường minh của từng syscall trong 29 syscall, bỏ toàn bộ kênh tường minh, và giữ top-16 theo phần training cộng whitelist nhạy cảm. Mask áp dụng tại cả bốn vị trí temporal. Hash bins/aggregate vẫn giữ, nên đây không phải loại toàn bộ thông tin của syscall đó.

19 workload có holdout × 32 biến thể = **608 fit dự kiến**. Holdout thiếu notification/payment; không tuyên bố phủ 21/21. Top-16 dùng proxy `expm1(log_count)` từ float32 trên training prefix, không phải histogram full-ID exact mới. Calibration/holdout không tham gia chọn top-16.

Scientific stack cài riêng trên VM trùng job host: Python 3.12.3, scikit-learn 1.9.1, NumPy 2.5.3, joblib 1.6.0, SciPy 1.18.1. Software khác reference original; không gọi là tái lập bit-for-bit model production. Timing của các fit nhập từ host giữ provenance riêng, **không gộp với timing VM**.

## Chạy ngầm và phục hồi

Checkpoint giữ **59/608 fit đã đo trên host**. Các fit đó được xác minh prediction SHA, START, input, software và ML source trước khi tái dùng. Chỉ fit các biến thể còn thiếu/error; không chạy lại 59 fit từ đầu. Progress hiện hành đọc từ STATUS của attempt mới nhất bên dưới; chưa suy chất lượng toàn campaign từ vài workload đầu.

Kiểm tra SSH ngày **08/10/2026 09:06 ICT**: attempt `000002` terminal
`state=completed`, **608/608 fit (100%)**, `errors=[]`, không còn đợi training.
Thời điểm kết thúc ghi trong terminal: **18:55:09 ngày 07/10 ICT**. Receipt
và checksum START/STATUS/TERMINAL: [inspection.json](validation-evidence/pulse-improvement-20261008/inspection.json),
phần `ablation`. Boot recovery đã cấu hình, chưa reboot VM để test vì không
muốn gián đoạn cụm. Chưa deploy subset vào candidate production.

| Thành phần | Giá trị |
|---|---|
| Unit trên VM | `pulse-syscall-feature-c1.service`, enabled tại `multi-user.target`, process chạy user `dat` |
| Giới hạn tài nguyên | CPU quota 150%, RAM tối đa 4 GiB, không swap, nice 15 |
| Input | `/home/dat/sentinel-pulse-syscall-feature-c1/inputs` |
| Checkout source frozen | `/home/dat/sentinel-pulse-syscall-feature-c1/source` |
| Output campaign | `/home/dat/sentinel-pulse-syscall-feature-c1/runs` |
| Attempt hiện hành | `attempt-000002`; các attempt cũ giữ nguyên |
| Checkpoint host nhập trên VM | `/home/dat/sentinel-pulse-syscall-feature-c1/imported-host-attempt` |
| Tự phục hồi | Restart on failure, retry 60 giây, boot enablement; lỗi binding/checksum exit 65 để điều tra |

Output gồm START, STATUS, RESULTS, prediction archives có checksum và TERMINAL. Raw dataset/archive không đưa vào Git. Campaign giữ single-writer flock, tạo attempt mới khi phục hồi, không ghi đè receipt cũ. Hoàn thành thì boot lại không train lại. Unit `Type=oneshot` hiển thị `activating/start` trong khi process training chạy; startup deadline là infinity, không có timeout 120 giây. Khi VM shutdown không thể tính toán, nhưng sau boot service tiếp tục checkpoint; đóng SSH hoặc tắt laptop không dừng process VM.

```bash
# Trên VM .234, lệnh chỉ đọc
systemctl status pulse-syscall-feature-c1.service --no-pager
systemctl is-enabled pulse-syscall-feature-c1.service
journalctl -u pulse-syscall-feature-c1.service -n 20 --no-pager
cat /home/dat/sentinel-pulse-syscall-feature-c1/runs/attempt-000002/STATUS.json
```

## Nguyên nhân gián đoạn đã xác minh

Job cũ là transient user unit trên tndat-Dell. `last -x` ghi host shutdown **10:25**, boot lại **13:21** ngày 07/10; journal cùng lúc dừng default target, job thí nghiệm và user manager. Process nhận SIGTERM, ghi terminal `interrupted`, **59/608 fit**, không có lỗi fit được ghi. Đây là shutdown toàn host, không phải bằng chứng người dùng gửi stop riêng cho job. [Journal](validation-evidence/syscall-resume-20261007/host-shutdown-journal.txt).

Attempt đầu trên VM giữ 59 fit nhưng dừng vì kiểm tra proxy float64 quá chặt. Cùng dataset SHA và gap **1,25 giây**, proxy `read` frontend: host `76804.0012292337`, VM `76804.00122923369`, chênh **1 ULP**, `1,4551915228366852e-11`; ranking/retained set giống nhau. Kafka không có chênh. Đây là roundoff khi tính/reduce cross-CPU, chưa quy cho instruction cụ thể.

Bản sửa cho tối đa 8 ULP nhưng ranking/mask/retained set phải giống hệt; zero-count không được đổi. Input hash, phần mềm và model/feature/training source vẫn phải trùng. Chênh lệch ghi trong `resume_training_proxy_roundoff`; không đổi model production. Attempt lỗi giữ tại [receipt VM đầu](validation-evidence/syscall-resume-20261007/vm-STATUS.json), không sửa thành success. Lỗi integrity/binding khác vẫn dừng và báo rõ, không bỏ validation để ép chạy.

## Giới hạn kết luận và bảo vệ soak

- Holdout normal độc lập với training nhưng đã được xem trong phân tích trước: kết quả **exploratory**, cần tập đánh giá mới để xác nhận lựa chọn.
- Raw model anomaly rate không phải policy alert FPR. TP/FP/TN/FN, precision, attack recall và kernel-to-alert giữ `null` khi chưa có ground truth/phép đo tương ứng. Inference timing trên host có quota không phải latency production.
- Không attach collector mới, inject attack, deploy subset hoặc tune model/policy. Soak production đã completed lúc 12:42:20 ngày 07/10; model/policy/raw seals giữ nguyên, không relaunch soak. [Trạng thái soak](SOAK_OBSERVATION_STATUS.md).
- Vòng full-ID histogram/cross-OS chưa chạy; kế hoạch cấp VM trong [SYSCALL_EXPERIMENT_VM_PLAN.md](SYSCALL_EXPERIMENT_VM_PLAN.md). Giữ nguyên scope Linux native x86_64 hiện tại đến khi kiểm chứng nền tảng khác.
