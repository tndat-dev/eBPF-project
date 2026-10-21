# TODO — đồ án Sentinel Pulse

Cập nhật 21/10/2026 21:12. Số liệu và bằng chứng chi tiết: [Pulse](SENTINEL_PULSE_STATUS.md) ·
[syscall](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) · [RCA](RCA_RUNTIME_STATUS.md) · [đánh giá tổng thể và ý tưởng](RESEARCH_IDEAS.md).
Ký hiệu: `[x]` xong · `[~]` đang chạy · `[ ]` chưa làm · **(cần bạn)** là việc chỉ bạn làm được.

## Đang chạy

- [~] **Lượt live `pulse-stable-refreshed`** (21/10 12:22 → 22/10 ~12:30, shadow). Cấu hình luật v2 chọn: `k2of2_a10` + calibration
      làm mới (`4bad16dc…`, `policy-2of2-a10-refreshed`), chấm nhanh, RCA `rca-pulse-stable-refreshed`. Không dừng giữa chừng.
  - [x] Campaign xong (Pulse 5.13a): precision 96,0%, recall 100%, control 4,2%, p95 2,26 s. Đạt 4/4 kỳ vọng ở mức ≤ 3 s, chưa đạt mức < 2 s.
- [~] **`after-stable-refreshed`** (.234, snapshot `399676c`, chạy tuần tự). Giai đoạn campaign xong 19:47. Khi 3 worker xong:
  1. giai đoạn final: gánh cảnh báo toàn normal, lưới `latency3s_fine`, biên Pareto, kết luận CUSUM/Cauchy (5.11a), tripwire A1 (5.16), cadence;
  2. lặp lại baseline trên dữ liệu mới, kèm `tree_ae` và luật chọn bộ chấm (5.15b);
  3. giai đoạn B nhóm feature (syscall 5B);
  4. Pulse 5.7d.

## Việc kế tiếp (theo thứ tự)

1. [ ] 22/10 ~15:00: đọc giai đoạn final theo đúng tiêu chí đã đăng ký (gánh cảnh báo, CUSUM/Cauchy, tripwire A1, Pareto ổn định giữa 2 lượt, phân loại cảnh báo và triage probe 5.18 trên dữ liệu mới).
1b. [ ] Sau lặp lại baseline: đọc chiến lược calibration 5.17 (bản dữ liệu mới) theo luật đã đăng ký.
2. [ ] 22/10 ~18:00: đọc lần lặp lại baseline (5.15b) và kết quả luật chọn bộ chấm.
3. [ ] Chốt cấu hình **ML stable** theo luật đã đăng ký `stable-selection-v1` (Pulse 5.19), theo kết quả 1–2; rule (Falco, tripwire) chỉ báo song song, tích hợp sau cùng. Đăng ký trước khi chạy. Đưa vào campaign tốc độ attack thấp (`ATTACK_RATES=1,3,6`, G4).
4. [ ] Nén `features`/`decisions` của soak 48 giờ, pulse-stable-candidate và pulse-stable-refreshed. Chỉ chạy khi không có lượt live và chuỗi phân tích nặng đã xong.
5. [~] **Ưu tiên chính:** viết luận văn (khối việc lớn nhất còn lại, ~10%). Tổng hợp số liệu và hình cho luận văn từ 3 báo cáo. Đã có 4 hình đầu, tiếng Việt và tiếng Anh (`docs/figures/`, sinh lại bằng `scripts/figures/thesis_figures.py`). Trong repo chưa có bản thảo luận văn.

## Pulse — vấn đề còn mở

- [ ] **Gánh cảnh báo trên normal:** khoảng 4–7 đợt/replica-giờ ở các chính sách khả thi, ngân sách 0,1 (5.8j). Chỉnh ngưỡng không giải được.
  - [ ] Calibration theo (workload, node) (5.6b): đăng ký trước rồi kiểm.
  - [ ] Phân rã theo chế độ tải và theo thời gian. Cần đọc decisions, nên chỉ làm khi không có lượt live.
  - [ ] Review nhãn các đợt kéo dài (ví dụ `auth-service` trên worker3) trước khi coi là báo nhầm.
- [ ] **Tách attack khỏi process vô hại mới (G5):** 94% binary vô hại vẫn bị gắn cờ.
  - [x] Độ bền tín hiệu: T = 5 s, f = 0,7 lặp lại trên lượt mới (tách khoảng 35 điểm, p95 6,5 s, chỉ dùng làm triage). Chờ 1 s: p95 3,23 s, không đạt.
  - [x] Novelty có xét exec (5.7c, 5.8h): 100% cho `ptrace`/`execveat`/`setns`, binary vô hại 0,3%.
  - [~] Tripwire A1 kiểm blind trên lượt mới (5.16).
  - [ ] Thông tin ngoài tần suất: tham số syscall, quan hệ cha–con của process từ Tetragon.
- [~] **Độ trễ:** live p95 2,26 s. CUSUM/Cauchy đưa p95 về 1,70 / 1,46 s trên interval; chờ gánh cảnh báo để kết luận.
- [x] **Bằng chứng gần tối ưu cho chính sách** (5.8j): `k2of2_a10` nằm trên biên ở mức < 2 s. [~] Lưới mịn và độ ổn định giữa các lượt chạy trong giai đoạn final.
- [x] **Baseline trên cùng dữ liệu (5.15a):** AE ngang hoặc hơn về recall và gánh cảnh báo, nhưng không tách được binary vô hại. [~] Lặp lại trên dữ liệu mới (5.15b). [ ] Luật Falco.
- [x] Recall theo tốc độ attack (5.15c): Pulse yếu dần ở 6/s. [ ] Campaign 1–3/s.
- [ ] Recall thấp ở `mprotect` và `seccomp` khi ngân sách chặt (syscall 5.8).
- [ ] Đo độ trễ kernel → cảnh báo đến người nhận thật. Hiện mới đo đến lúc ghi preview.
- [ ] Review nhãn (adjudication) để có ma trận nhầm lẫn đã xác nhận.
- [ ] Luận văn: viết mục mô hình đe dọa + bảng độ phủ ATT&CK (RESEARCH_IDEAS mục 5); nêu recall là cận trên với đường vào qua exec.
- [~] Baseline luật Falco (5.15d): phần trial xong. [ ] Sau lượt live: chép log Falco lần nữa, tính normal theo replica-giờ trên đúng khoảng của Pulse.
- [ ] Kịch bản tấn công thật (G2) **(cần bạn duyệt phạm vi)**: tải rồi chạy, reverse shell trong cụm, đọc token service account, quét port trong namespace, đào coin ngắn.
- [ ] Dataset công khai LID-DS (G3): tạm hoãn; xem lại khi viết paper.

## Thí nghiệm syscall — còn lại

- [~] Giai đoạn B nhóm feature (syscall 5B): chạy trong chuỗi `after-stable-refreshed`, rồi đưa kết quả vào Pulse 4b.
- [~] Pulse 5.7d (làm mới định kỳ + k2of2) chạy cuối chuỗi.
- [ ] Paired blind attack theo protocol v2. Chưa mở được, vì chưa cấu hình nào đạt ngân sách 0,1 đợt/giờ; ghi là giới hạn.

## RCA — còn lại

- [x] Luật `privilege_drop_at_start` trên dữ liệu mới (RCA 5.11): top-1 100%, luật cũ 91,9%.
- [ ] 13% attack không có case riêng (42/315). Đã loại điều kiện 10 s và trần case tiếp nối. Từ lượt sau, STATUS đếm lý do từ chối case tiếp nối.
- [ ] Trigger từ cảnh báo vận hành thật. Pulse vẫn chạy shadow.

## Hạ tầng

- [ ] **(cần bạn)** RAM NFS (`k8s-nfs`): tăng lên 8 GB và đặt reservation. Cần tắt VM, nên chỉ làm khi không có lượt live.
- [ ] **(cần bạn)** Host ESXi đang thu hồi RAM qua balloon: xem mức dùng RAM của host; đặt reservation cho 3 worker nếu host vẫn overcommit.
- [ ] Lặp lại đo overhead A/B (G7); kiểm tra trên kernel/distro khác (hiện chỉ Ubuntu x86-64).

## Quy tắc đang áp dụng

- Không chạy job đọc NFS nặng hoặc tốn RAM trên bất kỳ node nào khi lượt live đang chạy; không chạy trên master2/master3.
- Lượt live chạy hết chu kỳ, không dừng giữa chừng; khoảng thời gian xấu được loại trừ khi phân tích.
- Không thử reboot, mất NFS, backlog hay thao tác nào tác động vào hạ tầng.
- Không cài watcher; khi có job chạy ngầm, ghi giờ cần nhắc.
- Code đồng bộ giữa GitHub `main`, máy local và `/home/dat/eBPF-project` trên .234 và 3 worker (`scripts/sync_cluster_checkouts.sh` sau mỗi lần push).
- Phép đo mới phải đăng ký tiêu chí trước khi có số; không đổi lựa chọn sau khi xem kết quả.
