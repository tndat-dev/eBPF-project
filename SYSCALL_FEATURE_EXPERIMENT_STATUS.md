# Thí nghiệm chọn syscall — trạng thái, kết quả và nhật ký

Cập nhật **19/10/2026 10:41 (UTC+7)**. Thí nghiệm này chạy song song với [Sentinel Pulse](SENTINEL_PULSE_STATUS.md) và là đầu vào để chọn feature cho Pulse. Nó không tự đổi candidate đang chạy. RCA nằm ở [báo cáo riêng](RCA_RUNTIME_STATUS.md).

## 1. Câu hỏi nghiên cứu và kết luận hiện tại

**Câu hỏi:** bộ 29 syscall tường minh của Pulse có nên thêm, bớt hay thay nhóm nào để phát hiện tốt hơn, khi giữ cùng ngân sách cảnh báo nhầm và cùng độ trễ?

**Kết luận hiện tại (development, 19/10):**

- Đặt 11 cấu hình về **cùng số đợt cảnh báo trên normal** (sau khi hiệu chỉnh lại p-value giống Pulse) thì các cấu hình 29 syscall khác nhau chỉ trong phạm vi nhiễu.
- Mở rộng ra toàn bộ syscall (`plus_all_*`) làm tăng recall khi ngân sách rộng, nhưng đồng thời tăng control dương và chậm hơn khi ngân sách chặt.
- Bỏ cặp exec (`drop_exec_pair`) luôn kém nhất.
- **Không cấu hình nào đạt ngân sách 0,1 hay 1 đợt/replica-giờ** chỉ bằng chỉnh ngưỡng.

Hệ quả:
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
- Bảy kênh bằng 0 trên normal: ptrace, pivot_root, mount, unshare, recvmmsg, setns, execveat. Không loại chúng chỉ vì hiếm: R6 cho thấy chính các syscall hiếm này (ptrace, setns, execveat) là thứ tách attack khỏi process vô hại.

## 4. Thiết kế R4 (matched với Pulse)

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

### 5.1 Holdout R4 với calibration gốc (xong 16/10)

- **Dữ liệu:** 24 giờ normal sau khi đóng băng (15/10 05:38 → 16/10 05:38 UTC); 147 segment, 500,8 workload-giờ hợp lệ, đủ 21 workload.
- **Bằng chứng:** `validation-evidence/results-20261018/r4-normal-holdout-TERMINAL.json`.

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
- **Đầu ra:** `/mnt/sentinel-pulse-archive/matched-parallel-r4-20261015/score-dump-20261018/` (2,7 GB).

### 5.3 Replay attack R3/R5 cho mọi cấu hình (xong 18/10)

- **Dữ liệu:** 693 model × 630 interval (315 attack + 315 control) của R3/R5, dựng lại từ full-ID delta mà matched worker đã ghi. Mọi cấu hình được chấm trên cùng interval, không phải chạy attack riêng cho từng cấu hình.
- **Đầu ra:** `arm-attack-replay-r3r5-20261018/`.

| Alpha | Recall | Control dương | p95 (≈ kernel → cửa sổ dương) |
|---|---|---|---|
| ×1 | 0,93–0,96 (`drop_exec_pair` 0,87) | 3–4% | 2,1–3,4 s — **vượt 2 s** |
| ×5 | 0,98–1,00 | 12–16% | 0,9–1,5 s |
| ×10 | 0,99–1,00 | 22–27% | 0,79–1,1 s |

### 5.4 So sánh ở cùng ngân sách cảnh báo (xong 19/10 10:15)

**Phương pháp** (`syscall_study/arm_budget.py`, job `pulse-r4-arm-budget-20261019`, đầu ra `arm-budget-20261019/`):
1. Hiệu chỉnh lại p-value của từng model bằng 20% đầu holdout.
2. Đếm số đợt cảnh báo trên 80% còn lại với các hệ số alpha từ 0,5 đến 30.
3. Chấm R3/R5 với cùng calibration.
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
- Lưu ý về R3/R5:
  - Các kịch bản R3/R5 đã lộ khi phát triển Pulse, nên đây là development.
  - R3/R5 chưa có đối chứng binary vô hại. R6 cho thấy phần lớn recall đến từ "có process mới", nên recall tuyệt đối ở trên là lạc quan.
  - So sánh tương đối giữa các cấu hình vẫn có giá trị.

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
| Replay attack R3/R5 cho mọi cấu hình | Có (5.3) |
| So sánh ở cùng ngân sách sau hiệu chỉnh lại | Có (5.4) → giữ base29 |
| Replay mọi cấu hình trên campaign R6 (có binary vô hại) | **Việc tiếp theo**: R6 có full-ID delta, chấm offline được như 5.3, cho biết cấu hình nào tách attack khỏi process vô hại tốt hơn |
| Blind paired attack theo protocol v2 | Chưa (điều kiện ngân sách chưa đạt) |
| Đưa thay đổi feature vào Pulse | Không đổi: giữ base29 |

Nếu cải tiến calibration hoặc gộp thời gian của Pulse hạ được gánh cảnh báo, phải áp lại cùng phương pháp cho cả 11 cấu hình bằng `arm_budget.py` trên điểm đã xuất. Không cần chấm lại model.

## 8. Nguồn code, dữ liệu và lệnh kiểm tra

- **Code (`sentinel_pulse/syscall_study/`):**
  - `matched_study.py` — fit;
  - `matched_holdout.py` — evaluator holdout;
  - `score_dump.py` — xuất điểm;
  - `arm_attack_replay.py` — replay attack;
  - `arm_budget.py` — so ở cùng ngân sách.
- **Dữ liệu trên NFS:** `/mnt/sentinel-pulse-archive/matched-parallel-r4-20261015/`:
  - `syscall-matched-study/` — model;
  - `normal-holdout-evaluation/`;
  - `score-dump-20261018/`;
  - `arm-attack-replay-r3r5-20261018/`;
  - `arm-budget-20261019/`.
- **Bằng chứng cũ:** `validation-evidence/syscall/` (chọn syscall, C6).

```bash
python3 scripts/ssh_lab.py python3 -m json.tool \
  /mnt/sentinel-pulse-archive/matched-parallel-r4-20261015/arm-budget-20261019/RESULTS.json | head
```

## 9. Nhật ký

| Thời điểm | Việc đã làm | Kết quả / bằng chứng |
|---|---|---|
| 15/10 05:22 UTC | Fit xong 693 model R4, audit hash | `R4_FIT_AUDIT.json` |
| 16/10 13:03 | Holdout 24 giờ chấm xong (147 segment) | mục 5.1 |
| 18/10 ~15:19 | Khởi động xuất điểm đầy đủ 693 model | `dc781fe` |
| 18/10 ~15:44 | Replay attack R3/R5 cho mọi cấu hình | `f2f8976` |
| 19/10 02:17 | Đọc kết quả replay attack | mục 5.3 |
| 19/10 02:18 | Viết `arm_budget.py` (286 test pass), snapshot `a9cc061`, chạy job | `a9cc061` |
| 19/10 02:21 | Xuất điểm worker1 xong; khớp evaluator đã đăng ký | mục 5.2 |
| 19/10 02:23 | Kết quả sơ bộ: sau hiệu chỉnh lại, alpha×1 cho 5,7–7,3 đợt/replica-giờ | — |
| 19/10 10:15 | Job xong; nội suy ở cùng ngân sách → giữ base29, kết quả inconclusive theo protocol v2 | mục 5.4, 6 |
| 19/10 10:41 | Viết lại báo cáo này theo trạng thái hiện hành | file này |
