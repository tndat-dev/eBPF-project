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
