# TODO — đồ án Sentinel Pulse

Cập nhật 19/10/2026. Trạng thái và số liệu chi tiết: [Pulse](SENTINEL_PULSE_STATUS.md) ·
[syscall](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) · [RCA](RCA_RUNTIME_STATUS.md).
Ký hiệu: `[x]` xong · `[~]` đang làm · `[ ]` chưa làm · **(cần bạn quyết)** là thao tác
xóa/dừng trên máy chung hoặc công khai lên GitHub.

## Đã xong (phiên 18/10)

- [x] Đọc toàn bộ repo và đối chiếu với trạng thái thật trên cụm qua SSH.
- [x] Kiểm tra đồng bộ GitHub ↔ máy local ↔ cụm (kết quả ở mục "Đồng bộ code" trong STATUS).
- [x] Tái cấu trúc code: gỡ các thế hệ thí nghiệm đã kết thúc (~580 file, ~77 nghìn dòng),
      gom helper dùng chung, chia `sentinel_pulse/` thành 6 package; tag
      `archive/pre-refactor-20261018` giữ nguyên cây cũ. Test: 257 pass (local và trên .234).
- [x] Thu kết quả soak Pulse 48 giờ (cả 3 worker đã kết thúc bình thường 16/10).
- [x] Thu kết quả chấm holdout syscall-arms của thí nghiệm syscall (147 segment, 500,8 workload-giờ).
- [x] Gọn `validation-evidence/`: 59 → 11 thư mục, nhóm theo pulse/syscall/rca.
- [x] Nghiên cứu "xác nhận k-of-n" trên dữ liệu development: replay pulse-attack-dev đã tái lập
      đúng ma trận công bố; có bảng recall/độ trễ cho 21 chính sách.
- [x] Đo số đợt cảnh báo trên soak 48 h cho 21 chính sách k-of-n: tốt nhất vẫn 12 đợt/giờ.
- [x] Hiệu chỉnh lại p-value (c1): cửa sổ normal bị gắn cờ 8,1% → 0,35%, precision pulse-attack-dev
      79,8% → 97,8%, recall 99,3% → 91,3%, p95 1,61 → 2,91 s.
- [x] Kiểm tra tương đương sau refactor: 214.449 cửa sổ, 0 sai khác.
- [x] Lưới alpha nới rộng sau hiệu chỉnh (c2): không chính sách nào đạt đủ 4 kỳ vọng.
- [x] Đăng ký `policy-1win-a3` (1 cửa sổ, alpha×3, p95 1,97 s) gắn với candidate `ec72d9ea…`.
- [x] Đối chứng chạy binary vô hại (fixture pulse-live-recalibrated + campaign), xếp hạng nghi phạm RCA + đánh giá top-k,
      replay attack cho mọi cấu hình syscall (đang chạy `pulse-r4-arm-attack-replay-20261018`).

## Ưu tiên 0 — Giảm cảnh báo trên dữ liệu bình thường

- [x] Giảm độ trễ xử lý: chấm điểm forest nhanh ~4,9× và khớp từng bit (`fast_forest.py`, 19/10).
- [~] Lượt pulse-stable-candidate: job `pulse-stable-candidate-selection` (20/10 02:10) đo gánh cảnh báo và calibration làm mới trên pulse-live-recalibrated;
      luật chọn đã đăng ký trong SENTINEL_PULSE_STATUS mục 5.7; sau đó `recalibrate_bundle` + `scripts/launch_run.sh`
      (chấm điểm nhanh, chính sách 2 cửa sổ nếu đạt luật, RCA có case tiếp nối).
- [ ] **Mới (19/10):** đặc trưng/luật tách attack khỏi process vô hại mới (binary vô hại bị gắn cờ 80,7%);
      độ bền tín hiệu trong 15 s là dấu hiệu mạnh nhưng chậm.

Đây là điểm nghẽn chung: candidate hiện tại bật cờ ở ~8% cửa sổ normal (mức danh
nghĩa 0,17%), mọi cấu hình syscall ở syscall-arms đều ~19–20 đợt cảnh báo/giờ (ngân sách 0,1).

- [x] Chọn chính sách trên dữ liệu development (pulse-live-recalibrated: 1 cửa sổ, alpha×3); ghi thành file protocol (JSON, có SHA-256) **trước** khi thử mới.
      Ràng buộc: p95 kernel → cảnh báo < 2 s (càng thấp càng tốt) → ưu tiên hiệu chỉnh
      lại p-value; k-of-n tối đa 2 cửa sổ.
- [ ] Giảm độ trễ đuôi: p99 hiện 4,75 s (p95 1,61 s) — tìm nguyên nhân (backlog chấm điểm,
      cửa sổ warming sau reset, độ trễ ghi NFS).
- [ ] Tìm nguyên nhân p-value lệch: theo workload, theo chế độ tải (steady/peak/burst…),
      theo thời gian (drift), theo node; so với thời điểm calibration gốc.
- [ ] Thiết kế cơ chế làm mới calibration trong vận hành (cửa sổ trượt bao lâu, loại
      khoảng nghi tấn công thế nào), vì hiệu chỉnh lại là đòn bẩy lớn nhất đã đo được.
- [ ] Cải thiện độ trễ và recall với tấn công tốc độ thấp (seccomp probe, mprotect churn
      6 lần/giây): xem đặc trưng nào phản ứng chậm, cân nhắc kênh tường minh từ thí nghiệm syscall.
- [ ] Nếu vẫn chưa đủ: calibration theo chế độ tải, tăng cỡ tập calibration, hoặc fit lại
      model với normal đa dạng hơn (model syscall-arms fit lại chỉ gắn cờ 0,64% cửa sổ).

## Ưu tiên 1 — Chuẩn bị lượt chạy live tiếp theo

- [x] Chứng minh code refactor chấm điểm trùng khớp bản đóng băng (receipt
      `validation-evidence/results-20261018/scorer-equivalence-0117901.json`).
- [ ] Snapshot commit mới lên NFS làm `frozen_source` cho lượt chạy live kế tiếp.
- [x] Bundle candidate đã hiệu chỉnh lại (`ec72d9ea…`) và policy preview v2 (alpha + k-of-n) trong live path.
- [ ] Đăng ký tham số policy v2 đã chọn rồi chạy live (vẫn shadow).
- [ ] Fresh blind attack + normal độc lập cho candidate + chính sách mới.
- [x] Campaign pulse-live-recalibrated xong 19/10 09:52 (capture chạy đến 20/10 02:04): precision 89,1%, recall 92,8%, binary vô hại 80,7%, p95 1,90 s.
- [~] Chạy lượt live pulse-live-recalibrated (profile `pulse-live-recalibrated`, 24 h, không ghi raw.jsonl — xem STATUS mục 5.9): normal soak mới + campaign attack có `benign_exec_control: true` (fixture pulse-live-recalibrated),
      bật policy RCA flow và subscriber r3 có `binary_baseline_frozen_at`.
- [ ] Đo độ trễ kernel → cảnh báo đến người nhận thật (hiện mới đo đến lúc ghi preview).
- [ ] Review nhãn (adjudication) để có ma trận nhầm lẫn đã xác nhận, không chỉ nhãn kỳ vọng.

## Ưu tiên 1 — Thí nghiệm chọn syscall (chạy song song, là đầu vào feature cho Pulse)

- [x] syscall-arms holdout: không cấu hình nào đạt ngân sách cảnh báo; khác biệt giữa các cấu hình
      (18,6–20,8 đợt/giờ) nằm trong dao động giữa các seed → chưa chọn được bộ syscall.
- [x] Xuất điểm đầy đủ của 693 model trên holdout (`pulse-r4-score-dump-*`), khớp evaluator đã đăng ký.
- [x] Replay attack pulse-attack-dev cho cả 11 cấu hình (`arm-replay-pulse-attack-dev`): ở alpha×1 p95 2,1–3,4 s; `drop_exec_pair` kém nhất.
- [x] So 11 cấu hình ở cùng ngân sách cảnh báo sau hiệu chỉnh lại (`arm-budget-holdout`): không cấu hình nào
      đạt ≤ 1 đợt/giờ; khác biệt trong nhiễu; giữ `base29` cho Pulse.
- [x] Replay 11 cấu hình trên pulse-live-recalibrated (có binary vô hại): không cấu hình nào tách attack khỏi process vô hại; `plus_all_*` tệ nhất → giữ `base29`.
- [ ] Paired blind attack cho các cấu hình còn lại theo protocol v2; đo cả độ trễ
      kernel → cảnh báo cho từng cấu hình (feature nhiều hơn có thể chậm hơn).
- [ ] Đưa bộ syscall được chọn vào candidate Pulse kế tiếp (fit lại, đóng băng, blind test).

## Ưu tiên 2 — RCA

- [ ] **(cần bạn quyết)** Dừng hay giữ `pulse-rca-runtime-events.service`: đang không nhận
      tín hiệu mới từ 16/10 (Pulse đã dừng) nhưng vẫn dùng ~966 MB / giới hạn 1 GB.
- [x] Tìm nguyên nhân 99,9% case thiếu connect: service dùng connection pool, `connect()` hiếm.
- [x] Code + policy `sentinel-rca-flow-v1` (lấy mẫu tcp/udp_sendmsg 10 s/socket), đã dry-run.
- [x] Áp dụng policy flow + chạy subscriber rca-flow (`rca-flow (unit cũ)`) cùng lượt pulse-live-recalibrated (19/10 02:14).
- [x] Sửa rò tiến trình `tetra getevents` trong container Tetragon (campaign + RCA), dọn 378 tiến trình mồ côi (19/10).
- [x] Chạy `rca.evaluate_ranking` trên case pulse-live-recalibrated: 36/315 attack có case, top-1 100%.
- [x] RCA case tiếp nối + lưu 20.000: 72% attack có case (pulse-live-recalibrated: 11%), top-1 98,6% sau khi sửa baseline, preview → case p50 7 s.
- [x] RCA: decision hiện ra chậm qua NFS (p95 7,2 s) → stream trên worker qua SSH (p95 0,1 s), bật trong `launch_run.sh` cho pulse-stable-candidate (`08be414`). Đo lại preview → case trong pulse-stable-candidate.
- [x] RCA flow 3% → 78%: nguyên nhân là backlog ~80 s do hook file quá rộng; đã thu hẹp policy (19/10 16:35).
- ~~Thử reboot, mất NFS, backlog~~ — **bỏ theo quyết định của bạn (18/10)**: không thử bất kỳ thao tác nào tác động vào infra.

## Ưu tiên 3 — Dọn cụm

- [ ] **(chạy tay)** `bash /home/dat/cleanup-k8s-20261019.sh` trên .234: bản ghi pod chết, Bookinfo, `default/keycloak` (không phục vụ AIMS, giữ PVC).
- [x] Tài nguyên v8 trên k8s đã không còn (19/10).

- [~] NFS: nén `raw.jsonl` của soak 48 giờ (68,7 GB, kiểm tra seal) — đang chạy trên `.236` từ 18:36.
- [x] Công cụ đọc `.gz` đã kiểm tra seal (`3bb0e74`).
- [~] Nén `features`/`decisions` soak 48 giờ: job `pulse-compress-48h-rest-20261019` (.236), chạy sau các bước phụ thuộc.
- [ ] Nén segment pulse-live-recalibrated đã niêm phong sau khi các phân tích pulse-live-recalibrated xong (sau 20/10).
- [x] Dọn ổ worker (19/10 18:30): ~530 GB dữ liệu thô/checkout cũ, 15 unit cũ. (bạn đã cho phép tự quyết 18/10)

- [x] Gỡ detector v8, unit/timer cũ, 2 TracingPolicy, namespace `sentinel-system`, thư mục v8 (~6,3 GB).
- [ ] **(chạy tay)** Gỡ admission lock `sentinel-experiment-resource-lock`, 2 policy `sentinel-syscalls`,
      workload baseline v8 (`nginx/redis/loadgen/redis-loadgen`, `postgres/postgres-loadgen`).
      Bộ kiểm duyệt quyền của Claude Code chặn 2 lần → chạy `bash /home/dat/cleanup-manual-20261018.sh` trên .234.
- [x] ~~(chạy tay)~~ Đã xóa 19/10 18:30: dữ liệu thô cũ trên worker (~117–194 GB/node trong `/var/lib/sentinel-pulse-*`),
      checkout/bundle cũ trong `/home/dat`, 5 oneshot cũ còn `enabled` và ~90 unit lỗi mỗi worker.
- [ ] ~70 thư mục checkout cũ `/home/dat/eBPF-project-*` trên .234 (~12 GB) → giữ lại
      các thư mục còn được service/evidence tham chiếu, xóa phần còn lại.
- [ ] ~40 unit lỗi trên .234, ~90 unit lỗi mỗi worker (thế hệ cũ) → `reset-failed` và gỡ unit file.
- [ ] `/home/dat/eBPF-project` trên .234: nhánh main cũ, chậm 14 commit, có sửa chưa commit.
- [ ] Ổ đĩa worker4 85%, worker1 80% → kiểm tra dữ liệu thô có thể chuyển sang NFS.

## Ưu tiên 3 — GitHub và chất lượng

- [x] Push nhánh `refactor/repo-cleanup` và tag `archive/pre-refactor-20261018` (18/10).
- [x] Hợp nhất vào `main` (push thẳng, không dùng PR) — `22f365a`, 18/10. Đã bỏ dòng Co-Authored-By khỏi 10 commit ngày 18/10 (force-push).
- [ ] CI (GitHub Actions) chạy pytest với `requirements-lock.txt`.
- [ ] Lặp lại đo overhead A/B; kiểm tra trên kernel/distro khác (hiện chỉ Ubuntu x86-64).
