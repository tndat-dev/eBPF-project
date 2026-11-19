# Tài liệu buổi họp 20/11/2026 (tiến độ 13/11 – 20/11): cách dựng

- Hình: `overview.tex`, `probe.tex` bọc thẳng hình TikZ của đồ án (`thesis/figures/tikz-overview.tex`, `tikz-probe.tex`, đã có
  thẻ dòng dõi); `tectonic -o FIG overview.tex` rồi `pdftoppm -png -r 220 -singlefile`. Hình không ghi đường dẫn code.
- Báo cáo `docs/Bao_cao_tien_do_13_11-20_11.docx`: giải nén bản 13/11 chủ đồ án đã chỉnh vào `x/`, `report_build.py FIG` giữ
  trang bìa, style, footer, numbering và thay mục lục cùng nội dung; `../2026-11-13/report_toc.py <soffice.py>` điền số trang
  của mục lục và ghi `out.docx`.
- Slide `docs/Slide-runtime_security(20_11).pptx`: `make_deck_2011.py "docs/Slide-runtime_security(13_11).pptx" OUT
  deck_2011_content.py FIG` dựng trên deck 13/11 của chủ đồ án (layout TIEU_DE, kiểu bảng và bullet).
- Số liệu lấy từ `notes/WORKLOG.md` và biên nhận `validation-evidence/results-20261113` tới `-20261119`; không CI, không biểu đồ.
- Cập nhật 19/11 22:4x: thêm cấu hình t3 (amendment 1), vòng cải thiện D1–D18, lượt live cuối, hình kiến trúc mới (báo cáo 22 trang, slide 24).
