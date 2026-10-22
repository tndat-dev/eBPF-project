# TODO — đồ án Sentinel Pulse

Cập nhật 22/10/2026 22:53. Số liệu và bằng chứng chi tiết: [Pulse](SENTINEL_PULSE_STATUS.md) ·
[syscall](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) · [RCA](RCA_RUNTIME_STATUS.md) · [rule, tách khỏi ML](RULE_INTEGRATION_STATUS.md) · [đánh giá tổng thể và ý tưởng](RESEARCH_IDEAS.md).
Ký hiệu: `[x]` xong · `[~]` đang chạy · `[ ]` chưa làm · **(cần bạn)** là việc chỉ bạn làm được.

## Đang chạy

- [x] **`after-stable-refreshed`**: final, baseline lặp lại, chiến lược calibration (Pulse 5.13b, 5.15b, 5.17) và nén 3 lượt (NFS 291 → 85 GB) xong 16:17.
- [x] **`pulse-stable-selection-1022`**: replay cấu hình gộp đạt (16:28).
- [~] **`pulse-stable-confirm-launcher`** (chính sách `cap`, `93dd1478`): chờ `feature-groups-primary-1022` rồi khởi chạy lượt live xác nhận.
- [~] **`feature-groups-primary-1022`**: nhóm feature trên holdout chính, 3 node song song + replay `pulse-attack-dev` (chậm hơn dự kiến vì nhiều job cùng đọc NFS; xong ~00:30–01:30 23/10).
- [~] **`after-stable-confirm`** (snapshot `1e2ae7f`): chờ lượt xác nhận; giai đoạn campaign (kỳ vọng theo tốc độ, RCA) rồi final (gánh live + CI, test blind 5.22, lý do nghi phạm RCA, phân loại cảnh báo), rồi nén.
- [x] **`pulse-57d-1022`**: 5.7d xong (`rolling-12-1` −37% trên soak 48 giờ).
- [~] **`syscall-cusum-1022`**: 11 cấu hình syscall + nhóm feature dưới CUSUM `cap` (SYSCALL 5C; bản `keep` xong, cùng kết luận).
- [x] **CUSUM nhớ alarm sang trial sau** (5.19 bổ sung 1): phát hiện trước khi chạy live, sửa bằng `cap`, đóng băng lại.
- [x] **`pulse-burden-levers-1022`** (Pulse 5.22): xong 17:26; đề xuất cho cả 2 mức độ trễ (chiết khấu theo replica), chờ test blind.

## Việc kế tiếp (theo thứ tự)

1. [x] 16:28: replay cấu hình gộp đạt (5.19 bước 3); đóng băng `policy-cusum-b3-h6.json` (`9bf0b216…`).
2. [x] Kết quả `burden-reduction-v1` (5.22): đề xuất mức < 2 s (2,2–2,3 đợt) và ≤ 3 s (1,5–1,7 đợt); test blind trên lượt xác nhận.
3. [~] Lượt live xác nhận `pulse-stable-confirm` (5.19 bước 4, `stable-confirmation-v1` + bổ sung 1, chính sách `cap`): tự khởi chạy khi job nhóm feature xong (~00:30–01:30 23/10), chạy 24 giờ. Kèm tốc độ 1, 3/s (G4); test blind cho 5.22; dữ liệu cho so sánh có/không rule.
3b. [ ] **Ngay sau lượt xác nhận (cần làm tay, trong 1–2 ngày):** chép log Falco khỏi 3 worker (`/var/log/pods/falco_falco-*/falco`) và giữ tới khi so sánh có/không rule xong.
4. [ ] Sáng 23/10: đọc nhóm feature trên holdout chính (syscall 5B, gộp theo luật bổ sung) và bản CUSUM `cap` (5C).
5. [ ] **Sau khi ML hoàn thiện** (stable đóng băng, 5.22 quyết xong, lượt live xác nhận xong): tích hợp rule và **so sánh không có rule với có rule** trên cùng dữ liệu ([RULE_INTEGRATION_STATUS](RULE_INTEGRATION_STATUS.md) R6). Trong lượt live xác nhận: giữ log Falco, chạy tripwire trên normal, RCA gắn nhãn triage mọi case.
6. [ ] Viết luận văn **chỉ sau khi** bằng chứng của cả Pulse, thí nghiệm syscall và RCA đầy đủ (quyết định 22/10). Đã có 4 hình (`docs/figures/`, sinh lại bằng `scripts/figures/thesis_figures.py`).

## Pulse — vấn đề còn mở

- [~] **Gánh cảnh báo, control, false positive:** CUSUM b3/h6 giảm còn 5,32 đợt/replica-giờ (−21%, 5.13b), ngân sách 0,1. Chỉnh ngưỡng không giải được (CUSUM đã tối ưu khi bằng chứng cố định). Đang thử bằng chứng tốt hơn: calibration theo lớp launch, so với replica khác, so với lịch sử của chính container (5.22).
  - [x] Calibration theo (workload, node) (5.6b): là `mondrian-6-1` của 5.17; không thắng trên dữ liệu mới, không thắng trên soak (p95).
  - [x] Phân rã theo thời gian (5.23): 90 phút traffic thay đổi gấp ~2 lần traffic ổn định; không drift trong 20 giờ. [ ] Một lượt có chế độ traffic rải suốt lượt để đo gánh dưới traffic biến động (cho paper).
  - [ ] Review nhãn các đợt kéo dài (ví dụ `auth-service` trên worker3) trước khi coi là báo nhầm.
- [ ] **Tách attack khỏi process vô hại mới (G5):** 94% binary vô hại vẫn bị gắn cờ.
  - [x] Độ bền tín hiệu: T = 5 s, f = 0,7 lặp lại trên lượt mới (tách khoảng 35 điểm, p95 6,5 s, chỉ dùng làm triage). Chờ 1 s: p95 3,23 s, không đạt.
  - [x] Novelty có xét exec (5.7c, 5.8h): 100% cho `ptrace`/`execveat`/`setns`, binary vô hại 0,3%.
  - [x] Tripwire A1 (rule) đạt blind: xem [phần rule](RULE_INTEGRATION_STATUS.md) R3.
  - [ ] Thông tin ngoài tần suất: tham số syscall, quan hệ cha–con của process từ Tetragon.
- [x] **Độ trễ:** CUSUM b3/h6 đạt blind (5.13b): p95 1,70 s, mức < 2 s, gánh còn giảm. Cauchy trượt (gánh +16%).
- [x] **Bằng chứng gần tối ưu cho chính sách** (5.8j, 5.13b): lưới mịn trên 2 lượt; gánh thấp nhất trong tập khả thi ổn định (~4 đợt); CUSUM trội mọi k-of-n ở mức < 2 s.
- [x] **Baseline trên cùng dữ liệu (5.15a, 5.15b):** AE và `tree_ae` không thay base29 trên dữ liệu mới (tách kém khoảng 26 điểm).
- [x] Recall theo tốc độ attack (5.15c): Pulse yếu dần ở 6/s. [ ] Campaign 1–3/s.
- [ ] Recall thấp ở `mprotect` và `seccomp` khi ngân sách chặt (syscall 5.8).
- [ ] Đo độ trễ kernel → cảnh báo đến người nhận thật. Hiện mới đo đến lúc ghi preview.
- [x] Review nhãn (5.20): 4.766 cảnh báo normal, không case nào có dấu hiệu độc hại; người gán không độc lập.
- [ ] Khi viết luận văn: mục mô hình đe dọa + bảng độ phủ ATT&CK (RESEARCH_IDEAS mục 5); nêu recall là cận trên với đường vào qua exec.
- [x] Baseline luật Falco: chuyển sang [phần rule](RULE_INTEGRATION_STATUS.md) R2 (trial và normal xong).
- [ ] Kịch bản tấn công thật (G2): để mở. Claude không tự dựng phần này (22/10); nếu làm cho paper thì chủ đồ án tự triển khai trong môi trường riêng.
- [ ] Dataset công khai LID-DS (G3): tạm hoãn; xem lại khi viết paper.

## Thí nghiệm syscall — còn lại

- [x] Giai đoạn B nhóm feature trên holdout thứ hai (syscall 5B.2, tạm thời): không thành phần nào bỏ được; Pulse 4b đã cập nhật.
- [~] Giai đoạn B trên holdout chính và `pulse-attack-dev`: chạy lại trong `feature-groups-primary-1022`, rồi gộp theo luật bổ sung.
- [x] Pulse 5.7d xong (`rolling-12-1` −37% trên soak).
- [~] 5C: 11 cấu hình + nhóm feature dưới CUSUM `cap` (`syscall-cusum-1022`); bản `keep` xong, cùng kết luận.
- [ ] Paired blind attack theo protocol v2. Chưa mở được, vì chưa cấu hình nào đạt ngân sách 0,1 đợt/giờ; ghi là giới hạn.

## RCA — còn lại

- [x] Luật `privilege_drop_at_start` trên dữ liệu mới (RCA 5.11): top-1 100%, luật cũ 91,9%.
- [ ] 13% attack không có case riêng (42/315). Đã loại điều kiện 10 s và trần case tiếp nối. Từ lượt sau, STATUS đếm lý do từ chối case tiếp nối.
- [x] Baseline binary mang qua các lượt (RCA 5.12): seed từ khoảng normal của 2 lượt trước, dùng từ lượt `pulse-stable-confirm`. [ ] Kiểm hiệu quả trên lượt đó.
- [x] Nhãn triage probe trên mỗi case (chỉ là nhãn), chạy từ lượt sau.
- [ ] Trigger từ cảnh báo vận hành thật. Pulse vẫn chạy shadow.

## Hạ tầng

- [x] Collector 1 s đã dừng, tắt và xóa dữ liệu (22/10 12:47).
- [x] Đã xóa `/var/tmp/pulse-live-copy`, `falco-baseline` và 4 snapshot không dùng (22/10). [ ] Sau khi chốt kết luận: `/var/tmp/feature-groups`, `/var/tmp/syscall-cusum`; giữ `/var/tmp/burden-levers` (bảng cửa sổ cho test blind và so sánh rule) và `/var/tmp/baselines` (model baseline).
- [x] Nén `pulse-stable-candidate`, `pulse-stable-refreshed`, soak 48 giờ (NFS 291 → 85 GB, 22/10 16:17).

- [ ] **(cần bạn)** RAM NFS (`k8s-nfs`): tăng lên 8 GB và đặt reservation. Cần tắt VM, nên chỉ làm khi không có lượt live.
- [ ] **(cần bạn)** Host ESXi đang thu hồi RAM qua balloon: xem mức dùng RAM của host; đặt reservation cho 3 worker nếu host vẫn overcommit.
- [x] Đo overhead A/B (G7, Pulse 5.21): ~250–450 ns mỗi syscall khi theo dõi, ~80–230 ns khi không (microbenchmark, worker4). [ ] Kiểm trên kernel/distro khác (hiện chỉ Ubuntu x86-64).

## Quy tắc đang áp dụng

- Không chạy job đọc NFS nặng hoặc tốn RAM trên bất kỳ node nào khi lượt live đang chạy; không chạy trên master2/master3.
- Lượt live chạy hết chu kỳ, không dừng giữa chừng; khoảng thời gian xấu được loại trừ khi phân tích.
- Không thử reboot, mất NFS, backlog hay thao tác nào tác động vào hạ tầng.
- Không cài watcher; khi có job chạy ngầm, ghi giờ cần nhắc.
- Code đồng bộ giữa GitHub `main`, máy local và `/home/dat/eBPF-project` trên .234 và 3 worker (`scripts/sync_cluster_checkouts.sh` sau mỗi lần push).
- Phép đo mới phải đăng ký tiêu chí trước khi có số; không đổi lựa chọn sau khi xem kết quả.
- Rule (Falco, tripwire) chỉ quyết định song song với ML, tích hợp sau cùng, khi ML đã stable.
- Chỉ giữ tài nguyên còn được tham chiếu; dọn đồ thừa của job ngay; không đụng file cá nhân và backup của chủ đồ án.
