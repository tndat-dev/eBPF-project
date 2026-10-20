# TODO — đồ án Sentinel Pulse

Cập nhật 20/10/2026 11:43. Số liệu và bằng chứng chi tiết: [Pulse](SENTINEL_PULSE_STATUS.md) ·
[syscall](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) · [RCA](RCA_RUNTIME_STATUS.md).
Ký hiệu: `[x]` xong · `[~]` đang chạy · `[ ]` chưa làm · **(cần bạn)** là việc chỉ bạn làm được.

## Đang chạy

- [~] **Lượt live `pulse-stable-candidate`** (20/10 10:14 → 21/10 ~10:30, shadow). Gồm candidate `ec72d9ea…`, `policy-2of2-a10`,
      chấm điểm nhanh và RCA `rca-pulse-stable-candidate`. Campaign 315 cặp chạy từ 11:49. Không dừng giữa chừng.
- [~] **`pulse-stable-candidate-analysis`** (.234, đã hẹn): giai đoạn *campaign* khi campaign xong (RCA, attack vs binary vô hại);
      giai đoạn *final* khi 3 worker xong (5.7b refresh vs as_run, 5.7c novelty có xét exec, cadence gap, đối chiếu chấm nhanh với sklearn).

## Việc kế tiếp (theo thứ tự)

1. [x] Kết quả `syscall-arms-k2of2`: base29 giữ nguyên; bảng bằng chứng Pulse 4b và kết luận syscall 5.9 đã cập nhật (20/10 11:50).
2. [x] Campaign xong: Pulse 5.8a (precision 92,2%, recall 97,8%, control 8,4%, p95 1,85 s); RCA 5.10 (86,7% có case, top-1 99,6% sau khi sửa luật hạ quyền).
3. [ ] Sáng 21/10, sau khi lượt live kết thúc: đánh giá pulse-stable-candidate theo kỳ vọng ghi trong file chính sách; đọc 5.7b và 5.7c
      theo đúng tiêu chí đã đăng ký; quyết định bản stable.
4. [ ] Nén `features`/`decisions` của soak 48 giờ (pulse-soak-baseline) và của pulse-stable-candidate. Chỉ chạy khi không có lượt live.
5. [ ] Tổng hợp số liệu và hình cho luận văn từ 3 báo cáo. Trong repo chưa có bản thảo luận văn.

## Pulse — vấn đề còn mở

- [ ] **Gánh cảnh báo trên normal**: ~8 đợt/replica-giờ với k2of2_a10, ngân sách 0,1.
  - Đã biết (Pulse 5.6, 5.6b):
    - phân bố rộng: trung vị theo workload 4,65, không workload nào bằng 0;
    - worker3 gấp 2,7–4,7 lần khi calibration cũ;
    - làm mới calibration mỗi giờ chỉ giảm 16–23%.
  - [ ] Đăng ký trước và kiểm calibration theo (workload, node) trên dữ liệu pulse-stable-candidate. Ước tính còn ~4–5 đợt/replica-giờ, vẫn xa ngân sách.
  - [ ] Phân rã tiếp theo chế độ tải (steady/peak/burst…) và theo thời gian. Cần đọc decisions, nên chỉ làm khi không có lượt live.
  - [ ] Review nhãn các đợt kéo dài (ví dụ `auth-service` trên worker3, trung bình ~23 s mỗi đợt) trước khi coi là báo nhầm.
- [ ] **Tách attack khỏi process vô hại mới**: 80–92% binary vô hại bị gắn cờ ở mức 1.
  - [x] Xác nhận mức 2 bằng độ bền tín hiệu (Pulse 5.8b): T = 5 s, f = 0,7 → precision 97,3%, control 2,6%, vô hại 64,6%, p95 6,5 s trên lượt stable (chưa blind).
  - [ ] Kiểm mức 2 trên lượt live kế tiếp theo đăng ký (T = 5 s, f = 0,7 chính; f = 0,5 phụ).
  - Hai hướng đã loại: thêm syscall (thí nghiệm syscall) và novelty thuần (5.5b).
  - [~] Novelty có xét exec (5.7c) chạy tự động sau lượt live.
  - [ ] Hướng tiếp: thông tin ngoài tần suất (tham số syscall, quan hệ cha–con của process từ Tetragon).
- [ ] **Độ trễ**: k2of2_a10 có p95 2,43 s trên development, vượt mục tiêu 2 s; p99 4–5 s.
  - [ ] Đo lại trên pulse-stable-candidate (chấm nhanh) rồi phân rã đuôi p99: backlog, warming sau reset, ghi NFS.
- [ ] Recall thấp ở `mprotect` (75–82%) và `seccomp` (70–83%), là điểm yếu chung của mọi bộ syscall (syscall 5.8).
- [ ] Đo độ trễ kernel → cảnh báo đến người nhận thật. Hiện mới đo đến lúc ghi preview.
- [ ] Review nhãn (adjudication) để có ma trận nhầm lẫn đã xác nhận.
- [ ] Blind test thật sự độc lập: kịch bản tấn công mới, chưa dùng khi phát triển.

## Thí nghiệm syscall — còn lại

- [~] **Thí nghiệm nhóm feature (syscall 5B):** fit đang chạy (20/10 12:03); biến thể p-value theo nhánh đang chạy; chấm holdout + replay sau lượt live (21/10); rồi đưa kết quả vào Pulse 4b.

- [x] 11 cấu hình dưới k2of2 (syscall 5.9): ngân sách 1 đạt được, base29 tốt nhất, thêm syscall làm chậm p95.
- [x] Kết luận cuối (syscall 5.9) và bảng bằng chứng Pulse 4b.
- [ ] Pulse 5.7d (làm mới định kỳ + k2of2) chạy sau lượt live 21/10.
- [ ] Paired blind attack theo protocol v2. Chưa mở được, vì điều kiện ngân sách 0,1 đợt/giờ chưa cấu hình nào đạt; ghi là giới hạn.

## RCA — còn lại

- [x] Đánh giá trên campaign pulse-stable-candidate (RCA 5.10).
- [ ] Kiểm luật `privilege_drop_at_start` trên lượt live kế tiếp (đã sửa sau khi xem số).
- [ ] 13% attack không có case riêng (31 gộp sau case binary vô hại, 9 gộp sau case khác).
- [ ] Trigger từ cảnh báo vận hành thật. Pulse vẫn chạy shadow.

## Hạ tầng

- [ ] **(cần bạn)** Memory reservation 4 GB cho VM `k8s-nfs`: lúc 11:33 balloon vẫn giữ 2,5 GB, cần kiểm tra lại trong vCenter.
      Tăng RAM NFS lên 8 GB sau khi lượt live kết thúc (cần tắt VM).
- [ ] **(cần bạn)** Host ESXi đang thu hồi RAM qua balloon: 51–81 GB trên mỗi VM. Xem mức dùng RAM của host; đặt reservation cho 3 worker nếu host vẫn overcommit.
- [ ] Lặp lại đo overhead A/B; kiểm tra trên kernel/distro khác (hiện chỉ Ubuntu x86-64).

## Quy tắc đang áp dụng

- Không chạy job đọc NFS nặng hoặc tốn RAM trên bất kỳ node nào khi lượt live đang chạy; không chạy trên master2/master3.
- Lượt live chạy hết chu kỳ, không dừng giữa chừng; khoảng thời gian xấu được loại trừ khi phân tích.
- Không thử reboot, mất NFS, backlog hay thao tác nào tác động vào hạ tầng.
- Code đồng bộ giữa GitHub `main`, máy local và `/home/dat/eBPF-project` trên .234 và 3 worker (`scripts/sync_cluster_checkouts.sh` sau mỗi lần push).
- Phép đo mới phải đăng ký tiêu chí trước khi có số; không đổi lựa chọn sau khi xem kết quả.

## Đã xong (tóm tắt theo ngày)

**20/10**
- [x] pulse-live-recalibrated chạy hết 24 giờ; chọn chính sách theo luật đăng ký trước (k2of2_a10, ghi rõ không đạt kỳ vọng p95); khởi chạy pulse-stable-candidate.
- [x] Refresh calibration định kỳ (Pulse 5.6), novel-syscall (5.5b, không đạt), gánh cảnh báo theo workload/node (5.6b).
- [x] Syscall: bootstrap protocol v2 (5.7), recall theo kịch bản (5.8), bảng bằng chứng feature trong Pulse 4b, k-of-n trong `arm_budget`.
- [x] RCA: độ trễ preview → case p50 2,22 s / p95 2,47 s trên 2.364 case.
- [x] NFS: nén pulse-live-recalibrated (73,4 GB), mở rộng online 344 → 685 GB.
- [x] Cụm:
  - sửa 4 pod giữ mount ext4 hỏng (redis, minio, vault-2, tempo), unseal vault-2;
  - dọn pod chết, 47 unit cũ, 28 checkout cũ;
  - đồng bộ code trên 4 VM.
- [x] CI GitHub Actions chạy pytest trên bộ thư viện ghim giống cụm.

**19/10**
- [x] Lượt live pulse-live-recalibrated + campaign có binary vô hại (precision 89,1%, recall 92,8%, binary vô hại 80,7%, p95 1,90 s).
- [x] Chấm điểm nhanh khớp từng bit (~4,9×); sửa rò tiến trình `tetra getevents`.
- [x] RCA: case tiếp nối (11% → 72% attack có case), flow 3% → 87%, đọc decision qua SSH.
- [x] Sự cố cụm 18:40–19:12 (job nặng làm master2 treo), khôi phục và rút quy tắc.
- [x] Dọn ổ worker (~530 GB), gỡ detector v8 và tài nguyên v8.
- [x] Đổi tên mô tả cho mọi lượt chạy, script và báo cáo.

**18/10**
- [x] Tái cấu trúc repo (gỡ ~580 file cũ, 6 package), kiểm tra tương đương 214.449 cửa sổ, 0 sai khác.
- [x] Soak 48 giờ, holdout syscall-arms, nghiên cứu xác nhận k-of-n, hiệu chỉnh lại p-value (8,1% → 0,35% cửa sổ bị gắn cờ).
- [x] Đăng ký `policy-1win-a3`; hợp nhất vào `main` (push thẳng).
