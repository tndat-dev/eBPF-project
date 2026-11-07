# Nhật ký làm việc

Mỗi dòng: thời điểm (giờ Việt Nam), việc, kết quả hoặc biên nhận. Trước 07/11 xem nhật ký trong các file trạng thái cũ
(`git show 8b1bc44:SENTINEL_PULSE_STATUS.md`, mục 11).

| Khi | Việc | Kết quả / biên nhận |
|---|---|---|
| 01/11 | Chủ đồ án: chỉ phát triển ML, luật để sau | v2–v4 thành đối chứng luật |
| 02/11 | `lidds-ml-v1` | Âm: 65,2% official |
| 05/11 | `lidds-ml-v2` official | 95,99% / 0,57% / p95 2,32 s (`results-20261105/lidds-ml-v2/`) |
| 06/11 | Bảng chữ token theo chi phí probe, kiểm kê syscall, biến thể token, LSTM lớn, bằng chứng ngưỡng | `results-20261105/ml-exploration/` |
| 06/11 | Báo cáo và slide buổi 06/11 | `docs/Bao_cao_tien_do_30_10-06_11.docx`, `docs/Slide-runtime_security(06_11).pptx` |
| 06/11 | Chủ đồ án nới giới hạn overhead cho probe token | `reports/Thiết kế probe token Pulse.md` mục 5 |
| 07/11 01:00 | `lidds-ml-v3` official (lần chấm thứ 2, đã khai báo) | 97,32% / 0,44% / p95 2,09 s (`results-20261107/lidds-ml-v3/`) |
| 07/11 01:40 | Bản LaTeX theo v3 | 75 trang |
| 07/11 09:00 | Kiểm offline 2: ngưỡng theo khối trên lượt live cuối | Recall cụm 52–78% với riêng cây + support (`results-20261107/ml-block-threshold-live/`) |
| 07/11 | Xoá 4 file trạng thái, thêm `notes/`, dọn repo và cụm | xem dòng dưới |
| 07/11 15:00 | Xoá 4 file trạng thái (nội dung còn ở git `8b1bc44`), thêm `notes/STATE.md` và `notes/WORKLOG.md`; audit bỏ các câu trong file trạng thái, thêm 5 câu cho bảng hệ thống cuối trong bản LaTeX (48/48 khớp); xoá 2 script lỗi thời (`lidds2019_fetch_after_live.sh`, `lidds_v2_after_live.sh`), file tạm cục bộ; `fetch_references.py` bỏ User-Agent giả trình duyệt | commit gộp |
| 07/11 15:40 | Kiểm offline 1 của probe (`probe1f`, token của syscall không có hook phát lúc vào): development 530/544 như `select1f`, báo nhầm 21 so với 19 (thêm ở EPS_CWE-434), CB-DS 0 so với 2 báo nhầm | `results-20261105/ml-exploration/probe-order.txt` |
| 07/11 15:50 | Dọn cụm: `.234` xoá dữ liệu phân tích đã có biên nhận (ml-scores, ml-v1, ml-teacher*, ml-variants, ml-alphabets, ml-select*, ml-inventory, ml-probe-order, v2, v3-window, v4, converted*, script tải dataset, js-diag, baselines/models, snapshot nguồn), unit của lượt `pulse-live-recal-confirm` trên `.234` và 3 worker; xoá bản cục bộ của lượt đó trên 3 worker (33 GB; NFS có đủ 48/48 segment mỗi worker, bản nén có niêm phong) | `/var/tmp/lid-ds-2021` còn archive, `ml-scores-allwin`, `ml-tokens`, `ml-v3-tokens`, `ml-links` |
| 07/11 16:00 | Ablation vòng 2 (3 seed): chọn 45/46 cấu hình theo luật protocol từ biên nhận vòng 1 (chỉ `drop_accept` không vào) | `results-20261107/syscall-loo-stage2/ARMS.json`, `scripts/syscall_loo_stage2.sh` |
