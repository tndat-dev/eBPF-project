# Sai khác rolling profile trong đánh giá syscall C4

## Kết luận hiện hành

Đã xác minh từ provenance có SHA-256: normal dataset dùng cho C2 có profile
**exact-ebpf-500ms-rolling-10** trên cả ba node. Sidecar C3 lại đăng ký và tạo
feature với **rolling 5**. Tên/chiều vector vẫn là 249 nên kiểm tra schema,
identity, revision và cadence ban đầu không bắt được sai khác ngữ nghĩa này.
Đây là **lỗi tích hợp preprocessing của luồng đánh giá**, không phải bằng
chứng LSTM/ExtraTrees hay hạ tầng tự nhiên hoạt động sai.

58 cột bị ảnh hưởng: 29 rolling_mean và 29 rolling_std. C4 đã thực sự chấm
608 model; full tạo 145.820 raw flags / 334.655 context. **43,57% này không
được dùng làm FPR, precision, chất lượng model hoặc bằng chứng chọn syscall**
vì input preprocessing không tương đương training. Chưa chứng minh profile
mismatch giải thích toàn bộ số flag; cần phép chấm sửa đúng để đối chiếu.

C5 chỉ so thống kê reference/selection, đã hoàn tất. Các mean/std rolling
trong C5 cũng chịu confound này; không gọi chênh lệch đó là drift tự nhiên hay
causal feature importance. Tần suất full-ID C3 và số lượng entry không phụ
thuộc rolling transform, nên vẫn là descriptive frequency evidence hợp lệ.

## Bằng chứng

- [Verdict riêng](validation-evidence/pulse-parallel-completion-20261014/c4-profile-verdict.json)
  bind C4 terminal, capture START và ba capture-manifest training bằng SHA-256.
- Training dataset manifest SHA-256:
  `d97318dae77551b71d54cd1198cf01ffdaa3ab108ac7c55d68d477bcb0acc414`.
- Capture-manifest gốc nằm dưới
  `/home/dat/sentinel-pulse-evidence/dataset-r10/pulse500-data-20260928T142929Z/nodes/`;
  file profile/provenance nhỏ vẫn cần để xác minh, không phải yêu cầu giữ runtime V8.
- C3 START ghi `parallel_feature_capture.rolling_windows=5`; source sidecar
  cũ truyền 5 vào `capture.run`. Không sửa lại START để giả vờ đã thu rolling-10.
- C4/C5 raw và terminal giữ nguyên. Verdict nằm riêng; kết quả không bị xóa.

## C6 đã hoàn tất — preprocessing được sửa, model giữ nguyên

Receipt terminal ghi `completed_profile_repair` cho đủ 30 capture selection và
holdout. Replay rolling-5 khớp nguyên bản; rolling-10 tạo derived features riêng.
Toàn bộ 191 feature ngoài rolling giữ nguyên, không sửa raw/C3 gốc. Sau đó chấm
đủ **608/608 model** trên holdout đã sửa preprocessing; không fit lại model,
đổi alpha hoặc chọn feature theo kết quả.

Kết quả C6: **11.989/334.655 raw-positive contexts (3,5825%)**. Đây là mô tả
đầu ra model, chưa adjudicate normal/health nên **không phải FPR, precision hay
confusion matrix**. Candidate syscall selection vì vậy vẫn chưa có blind attack
đánh giá theo cùng preprocessing.

Evidence/output:

- Derived features: `/mnt/sentinel-pulse-archive/syscall-feature-profile-repair-c6`.
- Corrected scoring: `/mnt/sentinel-pulse-archive/syscall-variant-normal-c6-corrected`.
- Host receipts: `validation-evidence/pulse-c6-completion-evidence-20261014/`.

Không gọi C6 là dataset blind mới: đây là sửa transform của cùng capture đã
chấm sai profile. Target profile được xác định từ provenance trước training,
không được chọn theo score. Nhãn normal/health, fresh blind attack, confusion
matrix cùng đơn vị và kernel-to-alert vẫn cần hoàn tất sau correction.

## Ngăn tái diễn

Source phát triển đã bổ sung loader kiểm tra profile từ chuỗi provenance,
không chỉ checksum tên cột/chiều vector. Auditor khai báo profile mismatch;
evaluator từ chối profile chưa khớp nếu chưa có correction proof. Collector
cho campaign mới mặc định rolling-10 và ghi profile trong START. Không áp
source mới vào C3 đã seal hoặc sửa runtime Pulse đang canary.

[feature_profile.py](sentinel_pulse/feature_profile.py),
[repair_legacy_profile.py](sentinel_pulse/repair_legacy_profile.py),
[evaluator](sentinel_pulse/variant_independent_normal.py).
