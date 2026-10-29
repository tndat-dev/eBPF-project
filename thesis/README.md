# Luận văn (LaTeX)

Nguồn chính của luận văn. Biên dịch bằng [Tectonic](https://tectonic-typesetting.github.io/) (miễn phí, một file chạy, tự tải package):

```
cd thesis && tectonic main.tex        # -> main.pdf
```

- `main.tex`: trang bìa (các ô `[...]` để chủ đồ án điền), mục lục, danh mục hình/bảng, 8 chương, tài liệu tham khảo.
- `chapters/*.tex`: mỗi chương một file. Bản đầu (29/10) chuyển từ bản nháp Claude Docs bằng pandoc, từ đó sửa trực tiếp ở đây.
- `references.bib`: sinh từ `references/catalog.json` cho các bài luận văn trích; `vnplainnat.bst`: `plainnat` với chữ tiếng Việt ("và cộng sự").
- Hình: `figures/architecture.png` và các PDF trong `docs/figures/vi/` (`scripts/figures/thesis_figures.py`).
- Font TeX Gyre Termes (bản sao Times, có trong bundle của Tectonic); khổ A4, 13 pt, giãn 1,5 dòng, lề 3,5 / 2 / 2,5 / 3 cm. Không ngắt âm tiết (Tectonic không có mẫu ngắt từ tiếng Việt).
- Mọi con số lấy từ các báo cáo `.md` và biên nhận trong `validation-evidence/`.
