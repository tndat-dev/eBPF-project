# B7 telemetry R3 — canary normal 2 giờ ngày 07-09-2026

`AGGREGATE.json` là bản sao nguyên byte lấy qua SSH từ:

`/home/dat/sentinel-pulse-evidence/canary-b7-telemetry/sentinel-pulse-b7-telemetry-r3-20260907T083400Z/AGGREGATE.json`

SHA-256:

- aggregate: `cebce2686c63c2774b680cbab5613bca49c3940d3d101194f1c58bd9c326e6bb`;
- `FINAL_SHA256SUMS` trên control plane: `5ac33df6645d205f306afcd9653dd280787534b474c375aeb7d84260cb6a9c0e`;
- `START.json`: `cde45a7c43defef7deda0aab53c04acd4bb9973e64630d4efe1ecd1fa17780c3`.

73 entry trong checksum index đã được kiểm chứng trên control plane. Raw
decision, feature, journal và node diagnostics vẫn nằm trong archive trên cụm.

Canary đạt `valid=true`: 517.956 decision, 513.271 decision đã score, 0 alert,
0 detector restart và đủ 20/20 workload-container key. Thời gian quan sát tối
thiểu giữa ba node là 7.201,959 giây. Inference p99 là 30,197 ms;
window-start-to-decision p99 là 0,854 giây, tối đa 1,094 giây.

Ba finalizer đều có bảy integrity counter bằng 0. Snapshot interval p99 lần
lượt là 0,507/0,508/0,509 giây trên worker1/worker3/worker4; tối đa 0,634
giây. Không có chu kỳ 13 giây như B7 R1 trong khoảng quan sát này.

Đây chỉ là canary normal non-formal kéo dài 2 giờ. Kết quả không đo recall,
không đo kernel-to-alert của attack, không chứng minh FPR bằng 0 và không cho
phép promote model.
