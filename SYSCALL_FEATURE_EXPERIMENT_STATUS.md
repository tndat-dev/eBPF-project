# Thí nghiệm chọn syscall — trạng thái, kết quả và nhật ký

Cập nhật **19/10/2026 10:41 (UTC+7)**. Thí nghiệm này chạy song song với [Sentinel Pulse](SENTINEL_PULSE_STATUS.md) và là đầu vào để chọn feature cho Pulse. Nó không tự đổi candidate đang chạy. RCA nằm ở [báo cáo riêng](RCA_RUNTIME_STATUS.md).


## Tên gọi và đường dẫn thật trên cụm

Báo cáo dùng tên mô tả. Thư mục và unit có từ trước giữ tên cũ trên đĩa, vì config và hash bằng chứng tham chiếu tới chúng. Trên NFS có symlink tên mô tả trỏ tới từng thư mục, nên đường dẫn trong báo cáo dùng được trực tiếp.

| Tên trong báo cáo | Là gì | Thư mục / unit thật |
|---|---|---|
| `pulse-soak-baseline` | Soak 48 giờ của candidate gốc | `/mnt/sentinel-pulse-archive/matched-parallel-20261015` |
| `pulse-attack-dev` | Ma trận tấn công development 315 cặp | `matched-parallel-r3-20261015` |
| `pulse-attack-dev-rabbitmq` | 15 cặp RabbitMQ bổ sung | `matched-parallel-r5-rabbit-20261015` |
| `syscall-arms` | Thí nghiệm 11 cấu hình syscall (693 model) | `matched-parallel-r4-20261015` |
| `pulse-candidate-baseline` / `pulse-candidate-recalibrated` | Candidate gốc / candidate hiệu chỉnh lại | `runtime-f95867d-20261012` / `runtime-recal-c1-20261018` |
| `pulse-live-recalibrated` | Lượt live: candidate hiệu chỉnh lại + `policy-1win-a3` (đang chạy) | `matched-r6-20261018`; unit `pulse-matched-worker-r6-20261018` |
| `…/campaign-main`, `…/campaign-rca` | Campaign 315 cặp / campaign 105 cặp đánh giá RCA | `coordinator-runtime-r6-d791d24-20261019` / `coordinator-rca-followup-20261019` |
| `policy-1win-a3` | Chính sách 1 cửa sổ, alpha×3 | `sentinel_pulse/protocol/policy-1win-a3.json` (SHA-256 `f6107351…`) |
| `pulse-stable-candidate` | Lượt kế tiếp, ứng viên cho bản stable | `/mnt/sentinel-pulse-archive/pulse-stable-candidate` (tạo khi chạy) |
| `rca-subscriber` | Bản RCA tốt nhất, đang chạy | unit `rca-subscriber`, `/var/lib/sentinel-pulse-rca/rca-subscriber` |
| `rca-followup`, `rca-followup-v1`, `rca-flow`, `rca-runtime-v1` | Các bản RCA cũ (lịch sử) | `/var/lib/sentinel-pulse-rca/runtime-events-…` (có symlink cùng tên) |

## 1. Câu hỏi nghiên cứu và kết luận hiện tại

**Câu hỏi:** bộ 29 syscall tường minh của Pulse có nên thêm, bớt hay thay nhóm nào để phát hiện tốt hơn, khi giữ cùng ngân sách cảnh báo nhầm và cùng độ trễ?

**Kết luận hiện tại (development, cập nhật 20/10):**

- Đặt 11 cấu hình về **cùng số đợt cảnh báo trên normal** (sau khi hiệu chỉnh lại p-value giống Pulse) thì các cấu hình 29 syscall khác nhau chỉ trong phạm vi nhiễu.
- Mở rộng ra toàn bộ syscall (`plus_all_*`) làm tăng recall khi ngân sách rộng, nhưng đồng thời tăng control dương và chậm hơn khi ngân sách chặt.
- Bỏ cặp exec (`drop_exec_pair`) luôn kém nhất.
- **Không cấu hình nào đạt ngân sách 0,1 hay 1 đợt/replica-giờ** chỉ bằng chỉnh ngưỡng.
- **Dưới k2of2, đúng chính sách Pulse đang chạy (20/10, mục 5.9):**
  - ngân sách 1 đợt/replica-giờ đạt được cho mọi cấu hình;
  - base29 ở mức đó: recall 91–93%, control 0–1%, p95 2,3–2,8 s;
  - không cấu hình nào tốt hơn;
  - thêm syscall làm chậm phát hiện (p95 tới 5 s).
- **Khoảng tin cậy bootstrap (20/10, mục 5.7)** xác nhận các ý trên:
  - `drop_exec_pair` kém hơn base29 6,7–10,6 điểm recall, CI loại trừ 0;
  - `plus_all_*` tăng recall 6–8 điểm ở ngân sách rộng, nhưng khoảng cách với binary vô hại giảm 17–23 điểm, CI loại trừ 0;
  - các cấu hình 29 syscall khác không phân biệt được với base29.

Hệ quả (bảng bằng chứng theo từng thành phần feature nằm ở [Pulse mục 4b](SENTINEL_PULSE_STATUS.md)):
- **Giữ `base29` cho candidate Pulse kế tiếp.** Chọn syscall không phải nút thắt; gánh cảnh báo phải giải ở calibration và cách gộp theo thời gian.
- Theo luật chọn của protocol v2 (mục 6), kết quả là **inconclusive**: không có cấu hình nào thỏa ngân sách cảnh báo, nên không có căn cứ chọn bộ nhỏ hơn hay lớn hơn.

## 2. Thuật ngữ

| Thuật ngữ | Nghĩa |
|---|---|
| Syscall ID / ABI | Số định danh syscall theo kiến trúc (x86-64); không dùng nguyên cho ARM/Windows |
| Kênh tường minh (explicit channel) | Feature riêng cho một syscall, ví dụ log-count và tỷ lệ của `connect` |
| Full-ID histogram/delta | Số đếm của mọi syscall ID, kể cả ngoài 29; dùng để thử thêm kênh offline |
| Cấu hình (arm) | Một biến thể bộ feature; không phải một attack |
| Addition / ablation | Thêm kênh / bỏ kênh (bỏ cả nhóm tương đương) để đo đóng góp |
| Seed | Hạt ngẫu nhiên đã khóa (73021, 73022, 73023); báo cáo đủ cả 3 seed, không chọn seed tốt nhất |
| Matched / paired | Mọi cấu hình được chấm trên cùng dữ liệu, cùng container, cùng interval |
| Holdout | Dữ liệu normal sau khi đóng băng, không dùng để fit |
| Hiệu chỉnh lại | Tính lại p-value bằng normal gần hơn, model giữ nguyên |
| Ngân sách cảnh báo (budget) | Số đợt cảnh báo trên normal cho phép mỗi replica-giờ |
| Recall@budget | Recall khi mỗi cấu hình được chỉnh ngưỡng để dùng đúng cùng một ngân sách |
| Đợt cảnh báo (episode) | Các cửa sổ dương của một container cách nhau < 15 s gộp làm một |
| Raw positive | Model gắn cờ; chưa có ground truth nên chưa gọi là FP |
| Block bootstrap / CI | Lấy mẫu lại theo khối để ước lượng bất định, không coi cửa sổ chồng lấn là độc lập |

## 3. 29 syscall đến từ đâu?

- Danh sách nằm trong `TRACKED_SYSCALLS` ([sentinel_pulse/collector/features.py](sentinel_pulse/collector/features.py)) và được đối chiếu với [sentinel_pulse/ebpf/pulse_counter_ids.h](sentinel_pulse/ebpf/pulse_counter_ids.h).
- Tên và ID khớp [bảng ABI Linux x86-64 v6.8](https://raw.githubusercontent.com/torvalds/linux/v6.8/arch/x86/entry/syscalls/syscall_64.tbl). Bảng ABI chỉ chứng minh ánh xạ là đúng, không chứng minh nên chọn đúng 29 syscall này.

| Nhóm | Syscall tường minh |
|---|---|
| File/I/O | read, write, open, close, chmod, openat |
| Bộ nhớ | mmap, mprotect |
| Mạng | socket, connect, accept, sendto, recvfrom, accept4, recvmmsg, sendmmsg |
| Process | clone, execve, execveat, clone3 |
| Quyền / namespace / sandbox | ptrace, setuid, setgid, capset, pivot_root, mount, unshare, setns, seccomp |

- Các ID khác vẫn đóng góp vào tổng, 64 bin băm syscall và 64 bin băm cặp syscall liền nhau. Vì vậy bỏ một kênh tường minh chỉ đo giá trị *tăng thêm* của kênh đó.
- **Tần suất trên dữ liệu chọn (C3):** 185.303.624 lượt gọi, 135 ID quan sát được; 29 ID này chiếm 35,7% lượt gọi.
- Bảy kênh bằng 0 trên normal: ptrace, pivot_root, mount, unshare, recvmmsg, setns, execveat. Không loại chúng chỉ vì hiếm: pulse-live-recalibrated cho thấy chính các syscall hiếm này (ptrace, setns, execveat) là thứ tách attack khỏi process vô hại.

## 4. Thiết kế syscall-arms (matched với Pulse)

**Luồng:** capture cùng snapshot 500 ms với Pulse → phần dữ liệu chọn đã niêm phong → chia theo thời gian → feature của từng cấu hình → fit ExtraTrees + support theo workload và seed → calibration. Không dùng dữ liệu attack để fit.

| Cấu hình | Vai trò |
|---|---|
| base29 | Bộ hiện tại của Pulse (mốc tham chiếu) |
| plus_top8 / plus_top16 / plus_top32 | Thêm syscall theo thứ hạng tần suất trên phần training |
| plus_security | Thêm 15 syscall bảo mật hiếm (module, kexec, keyctl, bpf, userfaultfd, io_uring…) |
| plus_all_observed | Thêm mọi ID quan sát được trên phần training |
| plus_all_defined_native | Thêm toàn bộ ID native ABI đã đăng ký |
| drop_accept_pair / drop_open_pair / drop_exec_pair / drop_clone_pair | Bỏ từng cặp tương đương |

Tổng 693 model = 21 workload × 11 cấu hình × 3 seed. Fit xong 15/10 05:22 UTC; 693 artifact đã được audit hash (`R4_FIT_AUDIT.json`).

## 5. Kết quả

### 5.1 Holdout syscall-arms với calibration gốc (xong 16/10)

- **Dữ liệu:** 24 giờ normal sau khi đóng băng (15/10 05:38 → 16/10 05:38 UTC); 147 segment, 500,8 workload-giờ hợp lệ, đủ 21 workload.
- **Bằng chứng:** `validation-evidence/results-20261018/syscall-arms-normal-holdout-TERMINAL.json`.

| Cấu hình | Đợt / workload-giờ (3 seed) | Trung bình |
|---|---|---:|
| plus_top16 | 16,97 · 18,10 · 20,57 | 18,55 |
| plus_top32 | 17,26 · 20,32 · 18,92 | 18,83 |
| base29 | 19,77 · 20,17 · 18,48 | 19,47 |
| drop_exec_pair | 19,87 · 21,80 · 20,80 | 20,82 |

Mọi cấu hình đều ~19–20 đợt/giờ, và chênh lệch giữa các cấu hình nhỏ hơn dao động giữa các seed. Calibration lệch theo thời gian chi phối mọi cấu hình như nhau, nên chưa so sánh được.

### 5.2 Xuất điểm đầy đủ (xong 19/10 02:21)

- **Job:** `pulse-r4-score-dump-*` chấm lại 147 segment bằng đúng 693 model. Job lưu điểm tree/support của **mọi** cửa sổ (evaluator đã đăng ký chỉ giữ cửa sổ dương).
- **Kiểm chứng:** số đếm của từng segment khớp evaluator đã đăng ký; 0 segment lệch.
- **Đầu ra:** `/mnt/sentinel-pulse-archive/syscall-arms/score-dump/` (2,7 GB).

### 5.3 Replay attack pulse-attack-dev cho mọi cấu hình (xong 18/10)

- **Dữ liệu:** 693 model × 630 interval (315 attack + 315 control) của pulse-attack-dev, dựng lại từ full-ID delta mà matched worker đã ghi. Mọi cấu hình được chấm trên cùng interval, không phải chạy attack riêng cho từng cấu hình.
- **Đầu ra:** `arm-replay-pulse-attack-dev/`.

| Alpha | Recall | Control dương | p95 (≈ kernel → cửa sổ dương) |
|---|---|---|---|
| ×1 | 0,93–0,96 (`drop_exec_pair` 0,87) | 3–4% | 2,1–3,4 s — **vượt 2 s** |
| ×5 | 0,98–1,00 | 12–16% | 0,9–1,5 s |
| ×10 | 0,99–1,00 | 22–27% | 0,79–1,1 s |

### 5.4 So sánh ở cùng ngân sách cảnh báo (xong 19/10 10:15)

**Phương pháp** (`syscall_study/arm_budget.py`, job `pulse-r4-arm-budget-holdout`, đầu ra `arm-budget-holdout/`):
1. Hiệu chỉnh lại p-value của từng model bằng 20% đầu holdout.
2. Đếm số đợt cảnh báo trên 80% còn lại với các hệ số alpha từ 0,5 đến 30.
3. Chấm pulse-attack-dev với cùng calibration.
4. Nội suy recall và control dương tại đúng ngân sách B (đợt/replica-giờ).

| Cấu hình | B=5: recall / control / p95 | B=12: recall / control / p95 | B=18: recall / control / p95 |
|---|---|---|---|
| `base29` | 0,900 / 1,8% / 2,05 s | 0,927 / 4,8% / 1,53 s | 0,930 / 6,9% / 1,52 s |
| `drop_clone_pair` | 0,897 / 1,8% / **1,30 s** | 0,934 / 4,7% / 1,23 s | 0,941 / 7,8% / 1,14 s |
| `plus_security` | 0,900 / 1,9% / 1,94 s | 0,926 / 4,8% / 1,53 s | 0,932 / 7,9% / 1,35 s |
| `drop_accept_pair` | 0,902 / 1,8% / 2,07 s | 0,925 / 4,9% / 1,53 s | 0,930 / 7,3% / 1,47 s |
| `drop_open_pair` | 0,895 / 1,8% / 2,10 s | 0,925 / 4,8% / 1,50 s | 0,929 / 7,3% / 1,50 s |
| `plus_top8` | 0,887 / 1,7% / 2,08 s | 0,919 / 5,3% / 1,87 s | 0,925 / 7,2% / 1,33 s |
| `plus_top16` | 0,886 / 2,0% / 2,02 s | 0,921 / 5,1% / 1,81 s | 0,928 / 7,6% / 1,33 s |
| `plus_top32` | 0,883 / 1,8% / 2,33 s | 0,907 / 5,0% / 1,75 s | 0,921 / 7,6% / 1,70 s |
| `plus_all_defined_native` | 0,888 / 4,2% / 3,18 s | **0,987** / 8,2% / 1,22 s | 0,990 / 11,0% / 0,99 s |
| `plus_all_observed` | 0,885 / 3,9% / 3,81 s | 0,981 / 8,5% / 1,99 s | 0,984 / 11,5% / 1,27 s |
| `drop_exec_pair` | 0,806 / 1,8% / 1,87 s | 0,852 / 4,6% / 1,50 s | 0,875 / 7,4% / 1,46 s |

- Mức thấp nhất đạt được là 2,8–4,2 đợt/replica-giờ, ở alpha×0,5. Ngân sách 0,1 và 1 không đạt được.
- Lưu ý về pulse-attack-dev:
  - Các kịch bản pulse-attack-dev đã lộ khi phát triển Pulse, nên đây là development.
  - pulse-attack-dev chưa có đối chứng binary vô hại. pulse-live-recalibrated cho thấy phần lớn recall đến từ "có process mới", nên recall tuyệt đối ở trên là lạc quan.
  - So sánh tương đối giữa các cấu hình vẫn có giá trị.

### 5.5 Trên campaign pulse-live-recalibrated có binary vô hại (xong 19/10 ~13:40)

- **Dữ liệu:** replay 693 model trên 420 cặp của pulse-live-recalibrated (315 cặp chính + 105 cặp tiếp nối), tổng 1.260 interval gồm attack, binary vô hại và control. Dùng full-ID delta mà worker pulse-live-recalibrated đã ghi.
- **So sánh ở cùng ngân sách:** calibration lấy từ holdout syscall-arms như mục 5.4.
- **Đầu ra:** `pulse-live-recalibrated/analysis/arm-{replay,budget}/`.

Ở cùng ngân sách (đợt/replica-giờ), mỗi ô ghi: recall / control dương / **binary vô hại dương** / p95.

| Cấu hình | B=5 | B=12 | B=18 |
|---|---|---|---|
| `base29` | 0,894 / 2,4% / **0,617** / 2,58 s | 0,913 / 5,9% / **0,728** / 1,74 s | 0,916 / 9,2% / 0,764 / 1,66 s |
| `drop_clone_pair` | 0,891 / 1,9% / 0,613 / 2,22 s | 0,918 / 4,5% / 0,725 / 1,47 s | 0,927 / 7,8% / 0,785 / 1,10 s |
| `plus_security` | 0,891 / 2,2% / 0,619 / 2,53 s | 0,914 / 5,7% / 0,730 / 1,68 s | 0,916 / 8,5% / 0,767 / 1,32 s |
| `plus_top8` | 0,881 / 2,4% / 0,588 / 2,77 s | 0,909 / 6,4% / 0,693 / 2,06 s | 0,913 / 9,0% / 0,745 / 1,39 s |
| `plus_all_defined_native` | 0,877 / 4,8% / **0,830** / 3,05 s | 0,991 / 8,1% / **0,973** / 1,74 s | 0,992 / 11,2% / 0,984 / 0,94 s |
| `plus_all_observed` | 0,882 / 5,2% / 0,849 / 3,81 s | 0,989 / 8,6% / 0,975 / 3,31 s | 0,990 / 10,9% / 0,983 / 1,02 s |
| `drop_exec_pair` | 0,798 / 2,6% / 0,575 / 2,50 s | 0,845 / 5,9% / 0,708 / 1,84 s | 0,857 / 8,6% / 0,752 / 1,75 s |

- **Không cấu hình nào tách attack khỏi process vô hại tốt hơn hẳn.** Ở mọi cấu hình, tỉ lệ dương của binary vô hại tăng theo recall.
- Khoảng cách recall − binary vô hại ở B=5:

  | Cấu hình | recall − benign |
  |---|---|
  | `plus_top8` | 0,29 |
  | `base29`, `drop_clone_pair`, `plus_security` | ~0,28 |
  | `drop_exec_pair` | 0,22 |
  | `plus_all_*` | **0,03–0,05** |

  Thêm toàn bộ syscall chỉ làm model nhạy hơn với *mọi* process mới, kể cả process vô hại. Đây là bằng chứng để **không** chọn `plus_all_*`, dù recall của chúng cao hơn.
- Kết luận củng cố mục 1: giữ `base29`. Việc tách ác ý khỏi bất thường không giải được bằng chọn syscall; cần đặc trưng khác (tham số syscall, độ bền tín hiệu) hoặc tầng RCA.
- Ở ngân sách ≤ 8, p95 của hầu hết cấu hình > 2 s.
- Từ 13:00, worker pulse-live-recalibrated ghi thêm 17/5/18 cadence gap trùng lúc job này đọc NFS. Các cửa sổ đó đã tự động không tính là normal.

### 5.6 Lỗi khóa trial và kế hoạch khoảng tin cậy (19/10 17:52)

- **Lỗi khóa trial (của mình).** `arm_attack_replay` dùng khóa `(tag, trial_id)`, mà `trial_id` (ví dụ `"12:attack"`) đánh số lại từ đầu trong mỗi campaign. pulse-attack-dev với pulse-attack-dev-rabbitmq, và campaign pulse-live-recalibrated chính với campaign tiếp nối, có thể trùng khóa trên cùng workload. Khi đó cửa sổ của trial này ghi đè trial kia, trial bị chấm sai hoặc thành unknown.
  - Ước tính ảnh hưởng ~5% số trial của các workload trùng. Kết luận ở 5.3–5.5 khó thay đổi, nhưng sẽ được chạy lại.
  - **Sửa:** khóa gồm cả đường dẫn campaign (`trial_key`); `arm_budget` từ chối replay cũ dùng khóa trần.
- **Khoảng tin cậy** (`syscall_study/arm_bootstrap.py`):
  - Ở mỗi ngân sách, mỗi cấu hình dùng hệ số alpha của riêng nó.
  - Kết quả mỗi trial lấy trung bình 3 seed, so ghép cặp theo trial với base29.
  - Bootstrap lấy mẫu lại theo **workload**, 10.000 lần.
  - Báo cáo: recall, tỉ lệ binary vô hại, khoảng cách recall − benign, chênh lệch so với base29 kèm CI 95%, và cận dưới một phía 95% của chênh recall. Cận dưới này là điều kiện "không kém hơn −3 điểm" của protocol v2.
- **Lịch:** chạy trên `.235` lúc 18:30–18:55 thì **phải dừng**: tải lên NFS server làm worker pulse-live-recalibrated tăng cadence gap, và replay 693 model làm master2 treo (xem [Pulse](SENTINEL_PULSE_STATUS.md) mục 8b). Đã dời sang **20/10 02:20 trên `.234`** (`syscall-arms-bootstrap`, MemoryMax 32 GB, ghi vào `syscall-arms-bootstrap/`), sau khi pulse-live-recalibrated kết thúc. Thư mục `bootstrap-20261020/` chỉ chứa replay dở, không dùng.
  - Thư viện: thư mục `/home/dat/pylib-sklearn19` (numpy 2.5.2, scikit-learn 1.9.0, scipy 1.18.0, giống hệt `.234`). Venv sẵn có trên `.235` là sklearn 1.8.0 nên không dùng.
  - Các bước: chạy lại hai replay (pulse-attack-dev, pulse-live-recalibrated), `arm_budget` có ghi kết quả từng trial, rồi bootstrap.
  - Đầu ra: `syscall-arms/syscall-arms-bootstrap/` (kết quả ở mục 5.7).

### 5.7 Khoảng tin cậy bootstrap theo protocol v2 (xong 20/10 09:55)

- **Dữ liệu:**
  - Replay chạy lại với khóa trial có campaign: pulse-attack-dev 598 trial ghép cặp; pulse-live-recalibrated 1.238 trial ghép cặp, có binary vô hại.
  - 21 workload, 3 seed.
  - Bootstrap 10.000 lần, lấy mẫu lại theo workload.
- **Ngân sách:** `arm_budget` thử 0,1 / 1 / 5 / 18 đợt/replica-giờ. **Không cấu hình nào đạt 0,1 hay 1**, kể cả base29. Chỉ ngân sách 5 và 18 có hệ số alpha cho mọi cấu hình. Ngân sách 12 trong danh sách mặc định của bootstrap không có trong `arm_budget`, nên bị bỏ qua.
- **Biên nhận:** `validation-evidence/results-20261019/syscall/BOOTSTRAP-pulse-attack-dev.json`, `BOOTSTRAP-pulse-live-recalibrated.json`.

**Chênh recall so với base29** (điểm [CI 95%]; NI = cận dưới một phía 95% > −3 điểm):

| Cấu hình | attack-dev, ngân sách 5 | attack-dev, ngân sách 18 | live, ngân sách 5 | live, ngân sách 18 |
|---|---|---|---|---|
| base29 (recall) | 89,5% | 92,9% | 89,1% | 91,3% |
| drop_accept_pair | +0,5 [−0,7; +1,8] NI | −0,3 [−0,7; 0] NI | −0,2 [−1,0; +0,9] NI | −0,2 [−0,7; 0] NI |
| drop_open_pair | −0,3 [−1,3; +0,6] NI | 0 NI | −0,7 [−1,6; 0] NI | −0,1 [−0,3; 0] NI |
| drop_clone_pair | −0,1 [−1,0; +0,9] NI | +0,9 [−0,3; +3,1] NI | −0,2 [−1,3; +0,9] NI | +0,7 [−0,5; +2,6] NI |
| plus_security | +0,3 [−0,3; +1,2] NI | −0,2 [−0,6; 0] NI | −0,4 [−1,2; +0,2] NI | 0 [−0,2; +0,2] NI |
| plus_top8 | −1,2 [−3,9; +0,5] | −0,3 [−0,9; 0] NI | −1,7 [−4,2; +0,2] | −0,2 [−0,6; +0,2] NI |
| plus_top16 | −1,6 [−4,4; +0,2] | −0,1 [−0,3; 0] NI | −1,8 [−4,3; 0] | −0,2 [−0,6; +0,2] NI |
| plus_top32 | −2,0 [−6,1; +1,5] | −1,1 [−2,9; +0,1] NI | −2,2 [−5,9; +0,8] | −1,1 [−3,0; +0,6] NI |
| plus_all_defined_native | −7,8 [−19,6; +2,8] | **+6,1 [+0,7; +12,5]** NI | −8,5 [−19,6; +1,7] | **+7,9 [+0,6; +16,1]** NI |
| plus_all_observed | −9,4 [−21,6; +1,8] | +5,4 [0; +11,9] NI | −9,1 [−20,1; +1,0] | **+7,7 [+0,5; +15,9]** NI |
| drop_exec_pair | **−9,8 [−14,1; −5,3]** | **−7,4 [−11,4; −3,5]** | **−10,6 [−14,7; −5,9]** | **−6,7 [−10,9; −2,7]** |

**Trên pulse-live-recalibrated có binary vô hại**, chênh khoảng cách (recall − tỉ lệ binary vô hại dương) so với base29:
- `plus_all_defined_native`: −22,4 [−34,1; −9,2] điểm ở ngân sách 5 và −16,6 [−28,1; −5,7] ở ngân sách 18. `plus_all_observed`: −23,3 [−34,3; −11,0] và −16,7 [−27,9; −6,0].
  - Ở ngân sách 18, recall tăng 8 điểm nhưng binary vô hại bị gắn cờ tới 98% (base29: 74%). Cấu hình này chỉ nhạy hơn với *mọi* process mới, không bắt attack tốt hơn.
- Mọi cấu hình 29 syscall khác có CI của chênh khoảng cách chứa 0.
- Tỉ lệ control idle dương ở ngân sách 18: base29 6,3%, `plus_all_*` 10–11%, `plus_top*` 7,5–8,5%.

**Kết luận:**
1. **`drop_exec_pair` kém hơn base29 có ý nghĩa thống kê** (CI loại trừ 0 ở cả 4 ô; cận dưới tới −14 điểm). Cặp exec là phần cần thiết của bộ syscall.
2. **`plus_all_*` không tốt hơn.** Recall tăng ở ngân sách rộng, nhưng khoảng cách với binary vô hại giảm có ý nghĩa thống kê. Ở ngân sách chặt, chúng không đạt NI.
3. Các cấu hình bỏ một cặp (`drop_accept/open/clone_pair`) và `plus_security` **không kém hơn** base29 (NI ở cả 4 ô) nhưng **cũng không tốt hơn**. `plus_top8/16/32` không đạt NI ở ngân sách 5.
4. **Theo luật protocol v2:** điều kiện ngân sách 0,1 đợt/workload-giờ không cấu hình nào đạt, nên kết quả vẫn là **inconclusive** và **giữ base29**. Nếu bỏ điều kiện ngân sách (chỉ tham khảo, ngoài protocol), bộ nhỏ hơn đạt NI là bỏ một cặp. Mức tiết kiệm chỉ 2 bin, không đủ lý do để đổi candidate.

### 5.8 Recall theo từng kịch bản tấn công (20/10 11:13)

- **Cách tính:** dùng lại output của `arm_budget` (5.7) cho cả hai tập. Script `scripts/analysis/arm_scenarios.py`.
  - Mỗi cấu hình dùng hệ số alpha khớp ngân sách của nó.
  - Recall = TP / (TP + FN), gộp 3 seed, bỏ unknown.
  - Mỗi ô có 165–180 trial (pulse-attack-dev) hoặc 240–249 trial (pulse-live-recalibrated), đã nhân 3 seed.
- **Biên nhận:** `syscall/arm-scenarios-pulse-live-recalibrated.json`, `syscall/arm-scenarios-pulse-attack-dev.json`.

**pulse-live-recalibrated** (recall theo kịch bản):

| Cấu hình | mprotect | ptrace | execveat | setns | seccomp | Binary vô hại dương |
|---|---:|---:|---:|---:|---:|---:|
| *Ngân sách 18* | | | | | | |
| base29 | 79,1% | 100% | 100% | 100% | 77,4% | 72–78% |
| drop_exec_pair | 78,3% | 100% | **66,2%** | 100% | 77,8% | 69–76% |
| plus_top32 | 79,1% | 100% | 100% | 100% | 72,0% | |
| plus_all_defined_native | **98,4%** | 98,8% | 100% | 100% | **98,8%** | **96–100%** |
| *Ngân sách 5* | | | | | | |
| base29 | 75,5% | 100% | 100% | 100% | 70,0% | 56–62% |
| drop_exec_pair | 75,9% | 100% | **48,7%** | 100% | 66,7% | 53–58% |
| plus_top8/16/32 | 72–75% | 100% | 100% | 100% | **60–64%** | |
| plus_all_defined_native | 74,7% | **82,1%** | **75,0%** | 95,2% | 75,7% | 71–78% |

pulse-attack-dev cho cùng mẫu hình (ví dụ `drop_exec_pair` ở `execveat`: 66,1% ở ngân sách 18 và 55,0% ở ngân sách 5; `plus_all_*` ở `ptrace`: 79–81% ở ngân sách 5).

**Đọc bảng:**
1. **`drop_exec_pair` chỉ mất recall ở `execveat_resolution_probe`.** Bốn kịch bản còn lại gần như không đổi. Toàn bộ mức kém 6,7–10,6 điểm ở 5.7 đến từ đúng kịch bản dùng `execveat`. Cặp exec là feature mang tín hiệu riêng cho lớp attack này, không phải nhiễu.
2. **`ptrace` và `setns` được mọi cấu hình 29 syscall bắt 100%.** Đây là các syscall gần như không xuất hiện trong normal.
3. **Điểm yếu chung là `mprotect` (75–82%) và `seccomp` (70–83%).** Hai kịch bản này dùng syscall phổ biến trong normal. Thêm syscall top-N không giúp; `plus_top*` còn làm `seccomp` kém đi 6–11 điểm ở ngân sách 5.
4. **`plus_all_*` bắt `mprotect`/`seccomp` gần 98% ở ngân sách 18, nhưng binary vô hại cũng bị gắn cờ 96–100%.** Cấu hình này nhạy với mọi process mới, không riêng attack. Ở ngân sách 5, nó còn **mất** recall ở `ptrace` (82%) và `execveat` (75%), vì tín hiệu của vài syscall hiếm bị loãng giữa ~300 feature.
5. Tỉ lệ binary vô hại dương gần như không đổi giữa các kịch bản. Binary vô hại giống nhau ở mọi kịch bản; chỉ workload chứa nó thay đổi.

### 5.9 Dưới xác nhận k2of2, đúng chính sách Pulse đang chạy (xong 20/10 11:50)

- **Lý do:** các mục 5.4–5.8 dùng quyết định 1 cửa sổ, trong khi Pulse chạy `policy-2of2-a10`. Để bằng chứng khớp đúng cấu hình Pulse, cả 11 cấu hình được đánh giá lại với cùng luật xác nhận 2/2 cửa sổ trên normal holdout lẫn trên cửa sổ attack/control.
- **Code:**
  - `arm_budget.py --confirm-k 2 --confirm-n 2` (bản vector hóa, khớp `ConfirmationState` của Pulse; có test so sánh);
  - `arm_bootstrap.py` nay chạy mọi ngân sách có điểm khớp của base29.
- **Job:** `syscall-arms-k2of2` (.234, nice 19, đọc NFS một lần lúc chép 3,5 GB về đĩa local; chạy song song lượt live mà không ảnh hưởng). Cộng thêm bootstrap cho mọi ngân sách.
- **Biên nhận:** `syscall/k2of2/` (`RESULTS-*`, `BOOTSTRAP-all-*`, `arm-scenarios-k2of2-*`).

**Thay đổi lớn: với k2of2, ngân sách 1 đợt/replica-giờ đạt được cho cả 11 cấu hình.** Dưới quyết định 1 cửa sổ thì không cấu hình nào đạt. Ngân sách 0,1 vẫn không cấu hình nào đạt.

**Ngân sách 1 đợt/replica-giờ, pulse-live-recalibrated** (có binary vô hại; 1.238 trial ghép cặp, 21 workload):

| Cấu hình | α | Đợt/replica-giờ | Recall | Binary vô hại | Control | p95 trễ* | Chênh recall [CI 95%] | Không kém (−3 điểm) |
|---|---:|---:|---:|---:|---:|---:|---|:-:|
| **base29** | 3 | 0,95 | **91,2%** | 72,8% | 1,0% | 2,27 s | — | — |
| drop_clone_pair | 3 | 0,94 | 91,4% | 72,0% | 0,2% | 1,82 s | +0,2 [−0,5; +1,3] | có |
| drop_open_pair | 3 | 0,87 | 91,3% | 72,3% | 1,0% | 2,27 s | +0,1 [0; +0,3] | có |
| plus_security | 3 | 0,95 | 91,2% | 72,2% | 1,0% | 2,07 s | 0 [−0,2; +0,2] | có |
| drop_accept_pair | 3 | 0,95 | 90,9% | 72,9% | 1,0% | 2,08 s | −0,3 [−0,7; 0] | có |
| plus_top8 | 2 | 0,95 | 90,1% | 63,8% | 0% | 2,93 s | −1,1 [−2,3; −0,1] | có |
| plus_top16 | 1,5 | 0,74 | 89,1% | 66,8% | 0% | 3,05 s | −2,1 [−4,3; −0,4] | không |
| plus_top32 | 1,5 | 0,98 | 87,4% | 62,2% | 0,2% | 2,99 s | −3,8 [−7,3; −0,9] | không |
| plus_all_defined_native | 1 | 0,70 | 89,3% | 84,4% | 0,2% | **5,00 s** | −1,9 [−12,2; +7,8] | không |
| plus_all_observed | 1 | 0,79 | 88,4% | 84,8% | 0% | **5,04 s** | −2,8 [−13,4; +7,4] | không |
| drop_exec_pair | 3 | 0,90 | **84,1%** | 69,9% | 1,0% | 2,59 s | **−7,1 [−11,5; −2,7]** | không |

\* p95 của (cửa sổ dương đầu tiên − thời điểm sự kiện kernel), là cận dưới của kernel → preview.

pulse-attack-dev (598 trial) cho cùng thứ tự: base29 recall 92,6%, control 0%, p95 2,76 s; `drop_exec_pair` −6,3 [−10,0; −2,9]; `plus_top16/32` −2,2/−3,4 (CI loại trừ 0); `plus_all_*` không đạt NI, p95 3,9 s.

**Theo kịch bản (ngân sách 1, pulse-live-recalibrated):**
- base29: `ptrace`/`execveat`/`setns` 100%, `mprotect` 78,7%, `seccomp` 77,4%.
- `drop_exec_pair` chỉ mất ở `execveat` (64,6%).
- `plus_top32` làm `seccomp` tụt còn 60,1%.
- `plus_all_defined_native` nâng `mprotect`/`seccomp` lên ~86%, nhưng làm `ptrace`/`execveat` tụt còn 85–88% và gắn cờ 84% binary vô hại.

**Kết luận (development):**
1. **Kết luận chọn bộ syscall không đổi dưới chính sách Pulse đang chạy.** Không cấu hình nào tốt hơn base29. Các cấu hình bỏ một cặp và `plus_security` không kém hơn nhưng cũng không tốt hơn.
2. **`drop_exec_pair` kém có ý nghĩa** ở mọi ngân sách, mọi tập dữ liệu, với cả hai luật quyết định.
3. **Thêm syscall làm chậm phát hiện.**
   - `plus_top*` có p95 2,9–3,1 s, `plus_all_*` 5,0 s, so với base29 2,3 s.
   - Lý do: cấu hình nhiều feature phải dùng α nhỏ hơn mới giữ được ngân sách, nên cần nhiều bằng chứng hơn trước khi đủ 2 cửa sổ dương.
   - Với ràng buộc p95 < 2 s của Pulse, đây là lý do thứ hai, độc lập, để không mở rộng bộ syscall.
4. `plus_top8` giảm tỉ lệ binary vô hại dương (63,8% so với 72,8%; khoảng cách tốt hơn +8,0 [+0,7; +19,5] điểm), nhưng recall thấp hơn 1,1 điểm và chậm hơn 0,7 s. Nhận xét này rút ra sau khi xem số, chỉ một tập dữ liệu, chưa kiểm lặp lại; không đủ để đổi bộ syscall.
5. **Theo luật protocol v2:** điều kiện ngân sách 0,1 vẫn không cấu hình nào đạt, nên kết luận chính thức vẫn là **inconclusive**. Nếu áp luật với ngân sách 1 (chỉ tham khảo, ngoài protocol), bộ nhỏ nhất không kém hơn là bỏ một cặp. Mức tiết kiệm 2 kênh không đáng để fit lại candidate.
6. **Hệ quả cho Pulse:** giữ `base29`, không fit lại.
   - Calibration mới (đầu holdout) kết hợp k2of2 đạt ~1 đợt/replica-giờ, trong khi lượt live của Pulse với calibration c1 cũ ở mức ~8.
   - Đó là bằng chứng rằng **calibration cũ** là nguyên nhân chính của gánh cảnh báo. Phép thử làm mới calibration định kỳ + k2of2 cho Pulse đã được đăng ký ở Pulse 5.7d.

Bằng chứng: [`validation-evidence/results-20261019/syscall/`](validation-evidence/results-20261019/README.md); các bảng nội suy là `receipts/arm-table-*.json` (`scripts/analysis/arm_matched_table.py`).

## 5B. Thí nghiệm nhóm feature `feature-groups` (đăng ký 20/10 12:01; fit xong, chờ chấm điểm)

**Vì sao cần.** Thí nghiệm syscall chỉ thay đổi 29 syscall tường minh. Mọi cấu hình đều giữ nguyên bin băm syscall, bin băm cặp syscall, tổng hợp, rolling-10 và 3 cửa sổ lịch sử. Các phần đó, cùng cách gộp p-value, chưa có bằng chứng. Bộ feature Pulse đang dùng phải có bằng chứng cho **từng** phần.

**Thiết kế.** Mỗi cấu hình bỏ đúng một phần, mọi thứ khác giữ nguyên:
- **Dữ liệu fit:** dữ liệu chọn của syscall-arms, cùng cách chia train/calibration, cùng chỉ số mẫu (context được cắt từ context `base29` của syscall-arms), cùng 3 seed. Không dùng dữ liệu attack.
- **Đánh giá:** khoảng holdout 24 giờ của syscall-arms; replay hai bộ campaign (pulse-attack-dev, và pulse-live-recalibrated có binary vô hại); xác nhận k2of2 như Pulse; so ở cùng ngân sách (chính là 1, phụ là 5 đợt/replica-giờ); bootstrap ghép cặp theo workload.
- **Kiểm tự động:** `base29` của thí nghiệm mới phải cho đúng dự đoán như `base29` của syscall-arms (`REFERENCE_CHECK.json`).

| Cấu hình | Bỏ phần nào | Số cột còn lại |
|---|---|---:|
| base29 | không bỏ (vector Pulse đầy đủ, mốc tham chiếu) | 249 × 4 |
| drop_log_counts | log-count của 29 syscall (cột 0–28) | 220 |
| drop_ratios | tỉ lệ của 29 syscall (29–57) | 220 |
| drop_aggregates | 5 tổng hợp (58–62) | 244 |
| drop_syscall_bins | 64 bin băm syscall (63–126) | 185 |
| drop_transition_bins | 64 bin băm cặp syscall (127–190) | 185 |
| drop_rolling | rolling-10 mean/std (191–248) | 191 |
| drop_all_bins | cả hai nhóm bin | 121 |
| bins_only | chỉ giữ tổng hợp + hai nhóm bin, bỏ toàn bộ kênh syscall tường minh | 133 |
| history1 / history2 | 1 hoặc 2 cửa sổ lịch sử thay cho 3 | 249 × 2 / × 3 |
| base29@tree, base29@support | chỉ dùng p-value nhánh tree, hoặc chỉ nhánh support; không cần fit lại. Nhánh support chỉ nhìn vector hiện tại, nên đây cũng là phép thử "không dùng lịch sử" | — |

**Luật quyết định**, đăng ký trước mọi lần fit trong [`feature-group-evaluation-v1.json`](sentinel_pulse/protocol/feature-group-evaluation-v1.json) (SHA-256 `d40153d8…`):
- **Cần thiết:** khi bỏ đi, recall giảm (CI 95% nằm hẳn dưới 0) trên **cả hai** bộ attack; **hoặc** khoảng cách attack − binary vô hại giảm (CI dưới 0) trên pulse-live-recalibrated; **hoặc** p95 trễ tăng ≥ 0,2 s trên cả hai bộ.
- **Có thể bỏ:** recall không kém hơn (cận dưới một phía 95% > −3 điểm) trên cả hai bộ, khoảng cách không kém hơn 3 điểm, và p95 không chậm thêm quá 0,2 s.
- **Chưa kết luận:** không thuộc hai trường hợp trên.
- **Hệ quả cho Pulse:** giữ bộ hiện tại trừ khi có phần "có thể bỏ". Ngay cả khi đó, phần ấy chỉ là ứng viên rút gọn, phải fit lại, đóng băng và chạy live trước khi đổi.
- **Không kiểm (ghi là giới hạn):** độ dài cửa sổ 500 ms (cần capture mới), độ dài rolling 10 và số bin 64 (là siêu tham số), họ model.

**Lịch:**
- Giai đoạn A, fit 33 model × 21 workload = 693 model. Đang chạy từ 12:03 trên `.234`: CPU tối đa 6 core, nice 19, đọc NFS một lần lúc chép 1,3 GB về đĩa local, model ghi ra đĩa local.
- Biến thể p-value theo nhánh: đang chạy trên điểm sẵn có.
- Giai đoạn B, chấm holdout và replay attack: phải đọc capture qua NFS, nên chạy sau khi pulse-stable-candidate kết thúc (21/10).

### 5B.0 Fit và kiểm tái lập (xong 20/10 12:33; kiểm lại 15:25)

- **Fit:** đủ 693/693 model (11 cấu hình × 21 workload × 3 seed); không workload nào thiếu dữ liệu. Thời gian 12:03–12:33 trên `.234`, 2 giờ 51 phút CPU (giới hạn 6 core, nice 19); lượt live không bị ảnh hưởng. Model nằm trên đĩa local `.234` (`/var/tmp/feature-groups/study`).
- **Kiểm tái lập base29** (`fit-REFERENCE_CHECK.json`):
  - *Lần kiểm đầu báo **không khớp*** (`fit-REFERENCE_CHECK-v1-strict.json`, 20/21 workload). Mình điều tra trước khi dùng bất kỳ kết quả nào.
  - Kết quả điều tra trên cả 63 model base29:
    - điểm tree và điểm support **trùng khớp từng bit**;
    - calibration của nhánh support trùng khớp;
    - mảng điểm calibration của nhánh tree lệch tối đa **3,9e-16**: lúc fit, điểm này được cộng song song (`n_jobs=-1`), thứ tự cộng đổi bit cuối.
  - Phép kiểm dùng chính các context calibration, nên điểm trùng đúng với giá trị calibration và lệch 1e-16 đẩy điểm hoà sang bậc hạng bên cạnh. Có 421/6.300 p-value tree lệch đúng 1/1501; cờ cảnh báo vẫn trùng hoàn toàn.
  - Phép kiểm đã sửa (v2) báo riêng từng thành phần. Tiêu chí: điểm trùng từng bit, calibration support trùng, calibration tree lệch ≤ 1e-12. Kết quả: **tái lập đúng** (`reproduces_syscall_arms_base29: true`).
  - Trên dữ liệu holdout và attack, điểm hầu như không bao giờ trùng đúng giá trị calibration, nên ảnh hưởng thực tế bằng 0.

### 5B.1 Kết quả: nhánh p-value (xong 20/10 12:11)

- **Dữ liệu:** điểm đã xuất của base29 (syscall-arms) và replay sẵn có, k2of2.
- **Biên nhận:** `syscall/feature-groups/branches/` (`RESULTS-*`, `BOOTSTRAP-branches-*`).

| Biến thể | Tập | Ngân sách | Recall (base29 → biến thể) | Chênh recall [CI 95%] | Binary vô hại | p95 trễ |
|---|---|---:|---|---|---|---|
| chỉ tree | attack-dev | **1** | 92,6% → 64,4% | **−28,2 [−42,5; −15,2]** | — | 2,76 → 3,83 s |
| chỉ tree | live-recalibrated | **1** | 91,2% → 60,0% | **−31,2 [−45,4; −17,4]** | 72,8% → 56,7% | 2,27 → 3,87 s |
| chỉ support | attack-dev | **1** | 92,6% → 87,4% | **−5,2 [−10,6; −1,1]** | — | 2,76 → 2,31 s |
| chỉ support | live-recalibrated | **1** | 91,2% → 84,1% | **−7,1 [−14,9; −0,8]** | 72,8% → 58,4% | 2,27 → 2,21 s |
| chỉ tree | cả hai | 5 | 97,1/94,8% → 81,3/79,4% | −15,8 / −15,4 (CI dưới 0) | | +0,9 / +1,3 s |
| chỉ support | cả hai | 5 | 97,1/94,8% → 96,6/95,8% | −0,5 [−4,1; +2,3] / +1,1 [−2,3; +4,7] | 78,0% → 80,9% | ±0 |

**Theo luật đăng ký, ở ngân sách chính 1 đợt/replica-giờ:**
- **Nhánh support: cần thiết.** Bỏ nó (chỉ dùng tree), recall giảm 28–31 điểm, CI dưới 0 trên cả hai tập; p95 chậm thêm 1,1–1,6 s.
- **Nhánh tree, tức lịch sử thời gian: cần thiết.** Bỏ nó (chỉ dùng support), recall giảm 5–7 điểm, CI dưới 0 trên cả hai tập.

**Nói rõ:**
- Kết luận về nhánh tree **phụ thuộc ngân sách**. Ở ngân sách 5, chỉ dùng support không kém hơn (−0,5 và +1,1 điểm).
- Ở ngân sách 1, chỉ dùng support gắn cờ binary vô hại ít hơn (58,4% so với 72,8%), nhưng chênh khoảng cách +7,4 [−0,8; +17,6] chưa có ý nghĩa thống kê.
- Nghĩa là nhánh tree bổ sung tín hiệu đúng ở vùng ngưỡng chặt mà Pulse cần, đổi lại nhạy hơn với process mới.

## 6. Luật chọn (protocol v2) và đánh giá theo luật

Protocol [syscall-selection-evaluation-v2.json](sentinel_pulse/protocol/syscall-selection-evaluation-v2.json) đăng ký các điều kiện:
- **Endpoint chính:** recall theo trial ở ngân sách cảnh báo khác 0.
- **Ngân sách cảnh báo:** cận trên một phía 95% ≤ **0,1 đợt/workload-giờ hợp lệ**.
- **Luật chọn:** chọn bộ tường minh nhỏ nhất có cận dưới 95% của chênh recall so với base29 > −3 điểm phần trăm, đồng thời thỏa ngân sách. Nếu thiếu power hoặc coverage thì kết luận **inconclusive**.

**Đánh giá hiện tại:** không cấu hình nào thỏa ngân sách 0,1, kể cả sau khi hiệu chỉnh lại. Vì vậy theo protocol kết quả là **inconclusive** và giữ base29. Chưa chạy blind paired attack cho các cấu hình, vì điều kiện mở bước đó (ngân sách cảnh báo) chưa đạt.

## 7. Tiến độ và việc tiếp theo

| Bước | Trạng thái |
|---|---|
| Full-ID capture, tần suất, ablation/addition khám phá (C2–C6, A2) | Có |
| Fit 693 model matched, audit hash | Có |
| Holdout 24 giờ với calibration gốc | Có (5.1) |
| Xuất điểm đầy đủ | Có (5.2) |
| Replay attack pulse-attack-dev cho mọi cấu hình | Có (5.3) |
| So sánh ở cùng ngân sách sau hiệu chỉnh lại | Có (5.4) → giữ base29 |
| Replay mọi cấu hình trên campaign pulse-live-recalibrated + campaign tiếp nối (420 cặp, có binary vô hại) | **Có (5.5)**: không cấu hình nào tách attack khỏi process vô hại tốt hơn hẳn; `plus_all_*` tách kém nhất |
| Khoảng tin cậy bootstrap theo protocol v2 | **Có (5.7)**: `drop_exec_pair` kém có ý nghĩa; `plus_all_*` giảm khoảng cách với binary vô hại có ý nghĩa; các cấu hình 29 syscall khác không phân biệt được với base29 |
| Recall theo kịch bản tấn công | **Có (5.8)**: `drop_exec_pair` chỉ mất ở `execveat`; `mprotect`/`seccomp` là điểm yếu chung |
| 11 cấu hình dưới xác nhận k2of2 (chính sách Pulse hiện tại) | **Có (5.9)**: ngân sách 1 đạt được; base29 vẫn tốt nhất; thêm syscall làm chậm p95 |
| Kết luận cuối cho báo cáo đồ án | **Có (5.9, mục 1)** |
| Blind paired attack theo protocol v2 | Chưa (điều kiện ngân sách chưa đạt) |
| Đưa thay đổi feature vào Pulse | Không đổi: giữ base29 |

Nếu cải tiến calibration hoặc gộp thời gian của Pulse hạ được gánh cảnh báo, phải áp lại cùng phương pháp cho cả 11 cấu hình bằng `arm_budget.py` trên điểm đã xuất. Không cần chấm lại model.

## 8. Nguồn code, dữ liệu và lệnh kiểm tra

- **Code (`sentinel_pulse/syscall_study/`):**
  - `matched_study.py` — fit;
  - `matched_holdout.py` — evaluator holdout;
  - `score_dump.py` — xuất điểm;
  - `arm_attack_replay.py` — replay attack;
  - `arm_budget.py` — so ở cùng ngân sách; cả hai đã báo thêm tỉ lệ dương của binary vô hại (`6ab3dd4`).
- **Dữ liệu trên NFS:** `/mnt/sentinel-pulse-archive/syscall-arms/`:
  - `syscall-matched-study/` — model;
  - `normal-holdout-evaluation/`;
  - `score-dump/`;
  - `arm-replay-pulse-attack-dev/`;
  - `arm-budget-holdout/`.
- **Bằng chứng cũ:** `validation-evidence/syscall/` (chọn syscall, C6).

```bash
python3 scripts/ssh_lab.py python3 -m json.tool \
  /mnt/sentinel-pulse-archive/syscall-arms/arm-budget-holdout/RESULTS.json | head
```

## 9. Nhật ký

| Thời điểm | Việc đã làm | Kết quả / bằng chứng |
|---|---|---|
| 15/10 05:22 UTC | Fit xong 693 model syscall-arms, audit hash | `R4_FIT_AUDIT.json` |
| 16/10 13:03 | Holdout 24 giờ chấm xong (147 segment) | mục 5.1 |
| 18/10 ~15:19 | Khởi động xuất điểm đầy đủ 693 model | `dc781fe` |
| 18/10 ~15:44 | Replay attack pulse-attack-dev cho mọi cấu hình | `f2f8976` |
| 19/10 02:17 | Đọc kết quả replay attack | mục 5.3 |
| 19/10 02:18 | Viết `arm_budget.py` (286 test pass), snapshot `a9cc061`, chạy job | `a9cc061` |
| 19/10 02:21 | Xuất điểm worker1 xong; khớp evaluator đã đăng ký | mục 5.2 |
| 19/10 02:23 | Kết quả sơ bộ: sau hiệu chỉnh lại, alpha×1 cho 5,7–7,3 đợt/replica-giờ | — |
| 19/10 10:15 | Job xong; nội suy ở cùng ngân sách → giữ base29, kết quả inconclusive theo protocol v2 | mục 5.4, 6 |
| 19/10 10:41 | Viết lại báo cáo này theo trạng thái hiện hành | file này |
| 19/10 10:50 | `arm_attack_replay --workers-root` (replay trên capture khác syscall-arms) + chỉ số binary vô hại trong replay và arm-budget; hẹn job `syscall-arms-on-pulse-live (job)` chạy sau campaign tiếp nối | `6ab3dd4`, `scripts/syscall_arms_on_pulse_live.sh` |
| 19/10 ~12:50–13:40 | Job `syscall-arms-on-pulse-live (job)` chạy sau campaign tiếp nối (37 phút CPU) | `arm-{replay,budget}/` |
| 19/10 16:27 | Đọc kết quả trên pulse-live-recalibrated kèm tỉ lệ dương của binary vô hại: giữ `base29`, loại `plus_all_*` | mục 5.5 |
| 19/10 17:52 | Phát hiện và sửa lỗi khóa trial trùng giữa các campaign; viết `arm_bootstrap.py` (303 test pass); hẹn job chạy lại + bootstrap 02:15 | `3e2d2e4`; mục 5.6 |
| 19/10 17:57 | Đưa kết quả replay/arm-budget và bảng nội suy (biên nhận JSON) vào repo | `validation-evidence/results-20261019/` |
| 19/10 18:30 | Bỏ việc chờ pulse-live-recalibrated (không phụ thuộc dữ liệu); chạy job chạy lại + bootstrap trên `.235` với thư viện đúng phiên bản | mục 5.6 |
| 19/10 18:55 | Dừng job trên `.235` (tranh NFS, master2 treo); dời sang 02:20 trên `.234` | mục 5.6 |
| 20/10 02:20–03:18 | Job `syscall-arms-bootstrap` trên `.234`: replay lại cả hai tập với khóa trial theo campaign (xong 02:42 / 03:12), budget pulse-attack-dev xong 03:18, rồi **lỗi** ở bước bootstrap: campaign pulse-attack-dev không có control binary vô hại nên cột `benign_rate` rỗng ở mọi lần lấy mẫu (`IndexError` trong `np.percentile`) | journal `syscall-arms-bootstrap` |
| 20/10 09:44 | Sửa `arm_bootstrap.py`: cột không có trial thì ghi `None`; thêm tỉ lệ dương của control idle (`control_rate`, `control_diff`) cho cả hai tập; test cho campaign không có binary vô hại (308 test pass) | `6a5c5fa` |
| 20/10 09:46 | Chạy tiếp từ chỗ lỗi (`syscall-arms-bootstrap-resume`, snapshot `runtime-6a5c5fa-20261020`): bootstrap pulse-attack-dev, rồi budget + bootstrap pulse-live-recalibrated. Hai replay và budget pulse-attack-dev giữ nguyên | đang chạy |
| 20/10 09:55 | Bootstrap xong: `drop_exec_pair` kém có ý nghĩa, `plus_all_*` giảm khoảng cách với binary vô hại có ý nghĩa, các cấu hình khác không khác base29; theo protocol v2 vẫn inconclusive, giữ base29 | mục 5.7; `syscall/BOOTSTRAP-*.json` |
| 20/10 11:13 | Bảng recall theo kịch bản (dùng output 5.7, job nhẹ trên `.234`): `drop_exec_pair` chỉ mất recall ở `execveat`; `mprotect`/`seccomp` là điểm yếu chung; `plus_all_*` nhạy với mọi process mới | mục 5.8; `syscall/arm-scenarios-*.json` |
| 20/10 11:10 | Thêm xác nhận k-of-n vào `arm_budget` (bản vector hóa, khớp `ConfirmationState`, 311 test pass); chạy 11 cấu hình dưới k2of2 như Pulse đang dùng (`syscall-arms-k2of2` trên `.234`: chép score dump và replay về đĩa local với băng thông giới hạn, nice 19, tối đa 2 core) | `aa66def`; đang chạy |
| 20/10 11:21 | Nối kết quả về Pulse: bảng bằng chứng theo từng thành phần feature trong báo cáo Pulse (mục 4b) | Pulse mục 4b |
| 20/10 11:50 | k2of2 xong: ngân sách 1 đạt được; base29 không bị cấu hình nào vượt; `drop_exec_pair` kém; thêm syscall làm chậm p95 (5 s với `plus_all_*`). Kết luận cuối ở 5.9 | mục 5.9; `syscall/k2of2/` |
| 20/10 12:01 | Đăng ký trước thí nghiệm nhóm feature (`feature-group-evaluation-v1.json`): 10 cấu hình fit + 2 biến thể p-value; luật cần thiết / có thể bỏ / chưa kết luận | mục 5B; `740a8b4` |
| 20/10 12:03 | Bắt đầu fit (`syscall-feature-groups-fit`) và biến thể p-value theo nhánh (`syscall-feature-groups-branches`) trên `.234` | mục 5B |
| 20/10 12:11 | Biến thể nhánh p-value xong: nhánh support cần thiết (bỏ đi recall −28–31 điểm); nhánh tree/lịch sử cần thiết ở ngân sách 1 (−5–7 điểm), không kém hơn ở ngân sách 5 | mục 5B.1 |
| 20/10 12:33 | Fit xong 693/693 model nhóm feature; kiểm tái lập lần đầu báo không khớp | mục 5B.0 |
| 20/10 15:25 | Điều tra: điểm trùng từng bit, chỉ calibration tree lệch ≤ 3,9e-16 do cộng song song; sửa phép kiểm báo riêng từng thành phần → tái lập đúng | mục 5B.0; `650c445` |
