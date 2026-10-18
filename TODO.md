# TODO — đồ án Sentinel Pulse

Cập nhật 18/10/2026. Trạng thái và số liệu chi tiết: [docs/STATUS.md](docs/STATUS.md).
Ký hiệu: `[x]` xong · `[~]` đang làm · `[ ]` chưa làm · **(cần bạn quyết)** là thao tác
xóa/dừng trên máy chung hoặc công khai lên GitHub.

## Đã xong (phiên 18/10)

- [x] Đọc toàn bộ repo và đối chiếu với trạng thái thật trên cụm qua SSH.
- [x] Kiểm tra đồng bộ GitHub ↔ máy local ↔ cụm (kết quả ở mục "Đồng bộ code" trong STATUS).
- [x] Tái cấu trúc code: gỡ các thế hệ thí nghiệm đã kết thúc (~580 file, ~77 nghìn dòng),
      gom helper dùng chung, chia `sentinel_pulse/` thành 6 package; tag
      `archive/pre-refactor-20261018` giữ nguyên cây cũ. Test: 257 pass (local và trên .234).
- [x] Thu kết quả soak Pulse 48 giờ (cả 3 worker đã kết thúc bình thường 16/10).
- [x] Thu kết quả chấm holdout R4 của thí nghiệm syscall (147 segment, 500,8 workload-giờ).
- [x] Gọn `validation-evidence/`: 59 → 11 thư mục, nhóm theo pulse/syscall/rca.
- [x] Nghiên cứu "xác nhận k-of-n" trên dữ liệu development: replay R3/R5 đã tái lập
      đúng ma trận công bố; có bảng recall/độ trễ cho 21 chính sách.
- [~] Đo số đợt cảnh báo trên soak normal cho 21 chính sách (job đang chạy trên .234).
- [~] Nghiên cứu hiệu chỉnh lại p-value (recalibration) — job đang chạy trên .234.

## Ưu tiên 0 — Giảm cảnh báo trên dữ liệu bình thường

Đây là điểm nghẽn chung: candidate hiện tại bật cờ ở ~8% cửa sổ normal (mức danh
nghĩa 0,17%), mọi cấu hình syscall ở R4 đều ~19–20 đợt cảnh báo/giờ (ngân sách 0,1).

- [ ] Đọc kết quả recalibration + confirmation, chọn **một** chính sách trên dữ liệu
      development; ghi thành file protocol (JSON, có SHA-256) **trước** khi thử mới.
      Ràng buộc: p95 kernel → cảnh báo < 2 s (càng thấp càng tốt) → ưu tiên hiệu chỉnh
      lại p-value; k-of-n tối đa 2 cửa sổ.
- [ ] Giảm độ trễ đuôi: p99 hiện 4,75 s (p95 1,61 s) — tìm nguyên nhân (backlog chấm điểm,
      cửa sổ warming sau reset, độ trễ ghi NFS).
- [ ] Tìm nguyên nhân p-value lệch: theo workload, theo chế độ tải (steady/peak/burst…),
      theo thời gian (drift), theo node; so với thời điểm calibration gốc.
- [ ] Nếu recalibration chưa đủ: calibration theo chế độ tải hoặc làm mới định kỳ,
      tăng cỡ tập calibration, hoặc fit lại model với normal đa dạng hơn.

## Ưu tiên 1 — Chuẩn bị lượt chạy live tiếp theo

- [~] Đóng băng lại source sau refactor (đã sửa lỗi nạp pickle cũ; job
      `pulse-scorer-equivalence-20261018` đang replay 3 segment): chạy scorer mới và scorer đóng băng
      (`runtime-2c1a72d`) trên cùng tập context, chứng minh điểm số trùng khớp,
      lưu receipt rồi dùng commit mới làm `frozen_source`. (Worker sẽ từ chối chạy nếu chưa làm.)
- [ ] Triển khai chính sách đã chọn vào `detector/` + `pipeline/matched_worker.py` (vẫn shadow).
- [ ] Fresh blind attack + normal độc lập cho candidate + chính sách mới.
- [ ] Đối chứng "chạy binary vô hại" (benign-exec) để tách hiệu ứng khởi chạy process khỏi tấn công.
- [ ] Đo độ trễ kernel → cảnh báo đến người nhận thật (hiện mới đo đến lúc ghi preview).
- [ ] Review nhãn (adjudication) để có ma trận nhầm lẫn đã xác nhận, không chỉ nhãn kỳ vọng.

## Ưu tiên 1 — Thí nghiệm chọn syscall (chạy song song, là đầu vào feature cho Pulse)

- [x] R4 holdout: không cấu hình nào đạt ngân sách cảnh báo; khác biệt giữa các cấu hình
      (18,6–20,8 đợt/giờ) nằm trong dao động giữa các seed → chưa chọn được bộ syscall.
- [ ] Áp dụng cùng phương pháp hiệu chỉnh lại/ngưỡng của Pulse cho 11 cấu hình trên cùng
      holdout (development) để so sánh khi cảnh báo nhầm đã thấp hơn.
- [ ] Paired blind attack cho các cấu hình còn lại theo protocol v2; đo cả độ trễ
      kernel → cảnh báo cho từng cấu hình (feature nhiều hơn có thể chậm hơn).
- [ ] Đưa bộ syscall được chọn vào candidate Pulse kế tiếp (fit lại, đóng băng, blind test).

## Ưu tiên 2 — RCA

- [ ] **(cần bạn quyết)** Dừng hay giữ `pulse-rca-runtime-events.service`: đang không nhận
      tín hiệu mới từ 16/10 (Pulse đã dừng) nhưng vẫn dùng ~966 MB / giới hạn 1 GB.
- [ ] 19.142/19.152 case thiếu ngữ cảnh connect: kiểm tra policy connect, selector, cách join.
- [ ] Bộ dữ liệu có nhãn để đo độ đúng RCA; thử reboot, mất NFS, backlog.

## Ưu tiên 3 — Dọn cụm **(cần bạn quyết)**

- [ ] `sentinel-detector.service` (detector v8 cũ, dry-run) vẫn chạy trên .234 và worker1
      từ 01/10, ~750 MB RAM → đề xuất dừng + disable.
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
