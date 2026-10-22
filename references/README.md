# Tài liệu tham chiếu

[`catalog.json`](catalog.json) là danh mục mọi bài báo và nguồn mà báo cáo trích dẫn. Hiện có 75 mục:
- **46 bài đã tải bản PDF;**
- 16 bài chưa tải được;
- 13 mục là dataset, công cụ hoặc trang web, chỉ lưu link.

Mỗi mục ghi tiêu đề, link gốc, loại, báo cáo nào trích, link PDF đã dùng, kích thước và **SHA-256** của bản đã tải.

## Lấy và kiểm tra

```bash
python3 scripts/fetch_references.py               # đọc link từ 4 báo cáo + RESEARCH_IDEAS.md và extra.json, tải PDF còn thiếu
python3 scripts/fetch_references.py --no-download # chỉ dựng lại danh mục
```

- **Nguồn:** mọi link markdown trong 4 báo cáo và `RESEARCH_IDEAS.md`, cộng với [`extra.json`](extra.json). File này chứa các bài kinh điển chỉ được trích bằng tên tác giả và năm (Page 1954, Lorden 1971, Moustakides 1986, Wilson 2019…), và các bài cần link PDF khác: bản arXiv hoặc PMC của cùng bài, hoặc `"pdf_url": "none"` khi đã kiểm tay rằng không có bản công khai.
- **Kiểm PDF:** file phải bắt đầu bằng `%PDF` và có `%%EOF` ở cuối. Ngày 23/10 dòng đầu của từng PDF đã được đối chiếu với tiêu đề bài. Một file lấy từ trang kho của trường là tờ giới thiệu thư viện, không phải bài báo (KubAnomaly), nên đã bị loại.

## Vì sao PDF không nằm trong git

Repo này **công khai** trên GitHub, và phần lớn bài báo không cho phép phát tán lại. Vì vậy:
- `references/pdf/` có trong `.gitignore`;
- bản PDF nằm trên máy chủ đồ án (thư mục này) và bản sao trên NFS của cụm `/mnt/sentinel-pulse-archive/references/pdf/`;
- danh mục có SHA-256, nên bất kỳ bản sao nào cũng kiểm được là đúng file đã dùng.

Nếu muốn PDF nằm ngay trong git thì phải chuyển repo sang private, hoặc dùng một repo private riêng cho tài liệu.

## Bài chưa tải được tự động

Các trang dưới đây chặn tải tự động (Cloudflare, ACM, OpenReview) hoặc cần đăng nhập/trả phí. Muốn bổ sung thì tải bằng trình duyệt, đặt file đúng **tên mong đợi** vào `references/pdf/`, rồi chạy lại `fetch_references.py`. Script sẽ ghi nhận file với `how = placed_by_hand` và SHA-256.

| Bài | Link | Tên file mong đợi | Lý do |
|---|---|---|---|
| Autoencoder có attention cho truy cập file trong container (MDPI 2025) | [link](https://www.mdpi.com/2227-7390/14/6/991) | `` |  |
| CHIDS, CCSW 2022 | [link](https://research.utwente.nl/en/publications/contextualizing-system-calls-in-containers-for-anomaly-based-intr/) | `` |  |
| Class-conditional conformal cho anomaly detection mất cân bằng (MDPI Make) | [link](https://www.citedrive.com/en/discovery/class-conditional-conformal-prediction-for-reliable-anomaly-detection-under-extreme-class-imbalance/) | `` |  |
| CNN trong kernel bằng eBPF | [link](https://link.springer.com/chapter/10.1007/978-981-95-8417-8_34) | `` |  |
| Conformal false-alarm control cho O-RAN | [link](https://icml.cc/virtual/2026/78428) | `` |  |
| Contextualizing system calls in containers | [link](https://www.researchgate.net/publication/365185410_Contextualizing_System_Calls_in_Containers_for_Anomaly-Based_Intrusion_Detection) | `` |  |
| CORTEX | [link](https://neurips.cc/virtual/2025/137134) | `` |  |
| D. J. Wilson. The harmonic mean p-value for combining dependent tests. PNAS 116(4), 2019 | [link](https://doi.org/10.1073/pnas.1814092116) | `` |  |
| Dynamic fixed-point trong eBPF | [link](https://dl.acm.org/doi/fullHtml/10.1145/3674213.3674219) | `` |  |
| E. S. Page. Continuous inspection schemes. Biometrika 41(1/2), 1954 | [link](https://doi.org/10.2307/2333009) | `` |  |
| G. Lorden. Procedures for reacting to a change in distribution. Annals of Mathematical Sta | [link](https://projecteuclid.org/journals/annals-of-mathematical-statistics/volume-42/issue-6/Procedures-for-Reacting-to-a-Change-in-Distribution/10.1214/aoms/1177693055.full) | `` |  |
| G. V. Moustakides. Optimal stopping times for detecting changes in distributions. Annals o | [link](https://projecteuclid.org/journals/annals-of-statistics/volume-14/issue-4/Optimal-Stopping-Times-for-Detecting-Changes-in-Distributions/10.1214/aos/1176350164.full) | `` |  |
| KubAnomaly | [link](https://pure.lib.cgu.edu.tw/en/publications/kubanomaly-anomaly-detection-for-the-docker-orchestration-platfor/) | `` |  |
| Phát hiện cryptojacking bằng Tetragon + ML (Electronics 2025) | [link](https://doi.org/10.3390/electronics14061208) | `` |  |
| ShareAD | [link](https://api.crossref.org/works/10.1145%2F3712195) | `` |  |
| Transformer + phân loại syscall (SBSeg) | [link](https://sol.sbc.org.br/index.php/sbseg/article/view/36676) | `` |  |
