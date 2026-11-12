# Tài liệu buổi họp 13/11/2026: cách dựng

- Báo cáo `docs/Bao_cao_tien_do_06_11-13_11.docx`: sửa thẳng trên bản chủ đồ án đã chỉnh. `report_edit.py` chèn phần bổ sung
  (kiến trúc, bảng điểm gắn probe, select1f/probe1f, sự kiện, dòng Code, mục 8.5) vào `word/document.xml` của file đã giải nén;
  `report_toc.py` điền lại số trang của mục lục từ bản PDF.
- Slide `docs/Slide-runtime_security(13_11).pptx`: `make_deck_1311.py` dựng trên mẫu deck 06/11 với nội dung `deck_1311_content.py`
  (đã gồm các thay đổi của `patch_deck.py`).
- Hình: `overview.tex`, `probe.tex` bọc hình TikZ của đồ án (`thesis/figures/tikz-overview.tex`, `tikz-probe.tex`) thành trang
  standalone; `tectonic` rồi `pdftoppm -png -r 220`. Hình không ghi đường dẫn code; đường dẫn code nằm trong chữ và bảng.
