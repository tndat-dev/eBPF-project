# Trạng thái thực nghiệm chọn kênh syscall

Cập nhật: 08/10/2026. Job **đã hoàn thành 608/608 fit** trên **systemd hệ thống VM `dat@10.1.16.234`**, không phụ thuộc host/terminal/SSH. Đây là exploratory normal-only, chưa phải xác nhận blind recall.

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
