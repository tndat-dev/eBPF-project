# Bằng chứng ngày 19/10/2026

Các file nhỏ chép từ NFS (`/mnt/sentinel-pulse-archive/...`) và các biên nhận JSON tính lại bằng script trong
`scripts/analysis/`. Mọi con số trong 3 báo cáo đều phải tìm được ở đây hoặc trên NFS theo đường dẫn ghi trong file.
Nhãn đều là **nhãn kỳ vọng**, chưa review; dữ liệu là **development** (chính sách R6 được chọn trên R3/R5, không phải blind).

## Pulse — lượt live R6 (`pulse-r6/`)

| Con số trong báo cáo | File |
|---|---|
| Cấu hình đăng ký trước: candidate `ec72d9ea…`, chính sách `f6107351…`, 24 h, không raw, benign control | `CONFIG-capture.json`, `CONFIG-campaign-main.json`, `CONFIG-campaign-followup.json` |
| Campaign chính: TP 285, FN 22, FP 35, TN 277, unknown 11; precision 89,1%, recall 92,8%, control 11,2%; binary vô hại 251/311 = 80,7%; p95 1,90 s | `campaign-main-TERMINAL.json` (chi tiết từng cặp: `campaign-main-RESULTS.json.gz`) |
| Campaign tiếp nối: TP 93, FN 11, FP 7, TN 98; 93,0% / 89,4% / 6,7%; binary vô hại 72/102 = 70,6%; p95 2,17 s | `campaign-followup-TERMINAL.json`, `campaign-followup-RESULTS.json.gz` |
| Replay chính sách (k1of1_a3 tái lập kết quả live; k2of2_a5 97,4/95,8/2,6%, p95 2,88 s…) | `policy-replay-default.json`, `policy-replay-looser.json` |
| Theo kịch bản: attack / binary vô hại / control; tỉ lệ cửa sổ dương trong 15 s (trung vị 1,0 / 0,33 / 0) | `../receipts/attack-vs-benign-main.json`, `../receipts/attack-vs-benign-followup.json` |
| Cadence gap theo giờ (230/296 lúc 02h, 17/5/18 lúc 13h…) | `../receipts/cadence-gaps-r6.json` |

Số đo console không còn tái lập được (ghi kèm cách đo trong báo cáo): 301/18/59 client `tetra getevents` mồ côi
(`pgrep -fc` trên từng worker, 19/10 02:05); CPU Tetragon 5,3 → 0,6 core (`kubectl top`); 17,2 đợt/replica-giờ trong
02:07–02:20 (mẫu 7,3 replica-giờ, quá nhỏ để kết luận — số chính thức sẽ là job `pulse-r7-selection` trên 19:00–02:04).

## Kiểm tra tương đương (`equivalence/`)

| Con số | File |
|---|---|
| Snapshot R6 `4ba303a` chấm như bản đóng băng: 27.840 dòng có điểm, 0 sai khác | `r6-snapshot-4ba303a.json` |
| Đường nhanh: 13.505 dòng, 0 sai khác, CPU 42,4 s; đường sklearn 208,9 s | `fast-forest-r6.json`, `sklearn-path-r6.json` |

## RCA (`rca/`, `receipts/rca-*`)

| Con số | File |
|---|---|
| r6: 36/315 attack có case; 88 gộp sau binary vô hại, 130 gộp sau case khác, 48 bị xóa do giới hạn lưu, 13 không có case; preview → case p50 8,4 s / p95 16,6 s | `../receipts/rca-coverage-r6.json` |
| r6: top-1 100% trên 36 case (lưu sẵn và xếp hạng lại) | `r6-RANKING-stored.json`, `r6-RANKING-reranked.json` |
| r6c (99 trial sau khởi động): 71 có case (57 là case tiếp nối), 14 + 5 gộp, 9 không có case; p50 7,0 s / p95 14,5 s; chỉ 2/71 có flow | `../receipts/rca-coverage-r6c-after-warmup.json` |
| r6c: top-1 lưu sẵn 56% (baseline chưa được chép — lỗi script) → xếp hạng lại với baseline đúng 98,6% (72/73) | `r6c-RANKING-stored.json`, `r6c-RANKING-reranked.json`, cấu hình `r6c-config.json` |
| Sau khi thu hẹp policy: 392/449 case có flow (87%) | `../receipts/rca-flow-coverage-after-policy-change.json` |

## Thí nghiệm syscall (`syscall/`, `receipts/arm-table-*`)

| Con số | File |
|---|---|
| Replay R3/R5 cho 11 cấu hình (recall/control/p95 theo alpha) | `arm-replay-r3r5-RESULTS.json` |
| So ở cùng ngân sách (holdout R4 + R3/R5) | `arm-budget-r4holdout-RESULTS.json`, bảng nội suy `../receipts/arm-table-r4holdout-r3r5.json` |
| Trên R6 có binary vô hại; khoảng cách recall − benign | `arm-replay-r6-RESULTS.json`, `arm-budget-r6-RESULTS.json`, `../receipts/arm-table-r6.json` |

**Lưu ý trung thực:** các replay trên dùng khóa trial trần (`"12:attack"`), có thể trùng giữa các campaign
(phát hiện 19/10 17:52, ~5% trial của workload trùng). Job `pulse-syscall-bootstrap-20261020` chạy lại với khóa đã sửa;
kết quả mới sẽ thay thế các file này trong báo cáo.
