# Bằng chứng ngày 19/10/2026

Các file nhỏ chép từ NFS (`/mnt/sentinel-pulse-archive/...`) và các biên nhận JSON tính lại bằng script trong
`scripts/analysis/`. Mọi con số trong 3 báo cáo đều phải tìm được ở đây hoặc trên NFS theo đường dẫn ghi trong file.
Nhãn đều là **nhãn kỳ vọng**, chưa review; dữ liệu là **development** (chính sách `policy-1win-a3` được chọn trên pulse-attack-dev, không phải blind).

## Pulse — lượt live pulse-live-recalibrated (`pulse-r6/`)

| Con số trong báo cáo | File |
|---|---|
| Cấu hình đăng ký trước: candidate `ec72d9ea…`, chính sách `f6107351…`, 24 h, không raw, benign control | `CONFIG-capture.json`, `CONFIG-campaign-main.json`, `CONFIG-campaign-followup.json` |
| Campaign chính: TP 285, FN 22, FP 35, TN 277, unknown 11; precision 89,1%, recall 92,8%, control 11,2%; binary vô hại 251/311 = 80,7%; p95 1,90 s | `campaign-main-TERMINAL.json` (chi tiết từng cặp: `campaign-main-RESULTS.json.gz`) |
| Campaign tiếp nối: TP 93, FN 11, FP 7, TN 98; 93,0% / 89,4% / 6,7%; binary vô hại 72/102 = 70,6%; p95 2,17 s | `campaign-followup-TERMINAL.json`, `campaign-followup-RESULTS.json.gz` |
| Replay chính sách (k1of1_a3 tái lập kết quả live; k2of2_a5 97,4/95,8/2,6%, p95 2,88 s…) | `policy-replay-default.json`, `policy-replay-looser.json` |
| Theo kịch bản: attack / binary vô hại / control; tỉ lệ cửa sổ dương trong 15 s (trung vị 1,0 / 0,33 / 0) | `../receipts/attack-vs-benign-main.json`, `../receipts/attack-vs-benign-followup.json` |
| Cadence gap theo giờ (230/296 lúc 02h, 17/5/18 lúc 13h…) | `../receipts/cadence-gaps-pulse-live-recalibrated.json` |

Số đo console không còn tái lập được (ghi kèm cách đo trong báo cáo): 301/18/59 client `tetra getevents` mồ côi
(`pgrep -fc` trên từng worker, 19/10 02:05); CPU Tetragon 5,3 → 0,6 core (`kubectl top`); 17,2 đợt/replica-giờ trong
02:07–02:20 (mẫu 7,3 replica-giờ, quá nhỏ để kết luận — số chính thức sẽ là job `pulse-pulse-stable-candidate-selection` trên 19:00–02:04).

## Kiểm tra tương đương (`equivalence/`)

| Con số | File |
|---|---|
| Snapshot pulse-live-recalibrated `4ba303a` chấm như bản đóng băng: 27.840 dòng có điểm, 0 sai khác | `pulse-live-recalibrated-snapshot-4ba303a.json` |
| Đường nhanh: 13.505 dòng, 0 sai khác, CPU 42,4 s; đường sklearn 208,9 s | `fast-forest-pulse-live-recalibrated.json`, `sklearn-path-pulse-live-recalibrated.json` |

## RCA (`rca/`, `receipts/rca-*`)

| Con số | File |
|---|---|
| rca-flow: 36/315 attack có case; 88 gộp sau binary vô hại, 130 gộp sau case khác, 48 bị xóa do giới hạn lưu, 13 không có case; preview → case p50 8,4 s / p95 16,6 s | `../receipts/rca-coverage-rca-flow.json` |
| rca-flow: top-1 100% trên 36 case (lưu sẵn và xếp hạng lại) | `rca-flow-RANKING-stored.json`, `rca-flow-RANKING-reranked.json` |
| rca-followup (99 trial sau khởi động): 71 có case (57 là case tiếp nối), 14 + 5 gộp, 9 không có case; p50 7,0 s / p95 14,5 s; chỉ 2/71 có flow | `../receipts/rca-coverage-rca-followup-after-warmup.json` |
| rca-followup: top-1 lưu sẵn 56% (baseline chưa được chép — lỗi script) → xếp hạng lại với baseline đúng 98,6% (72/73) | `rca-followup-RANKING-stored.json`, `rca-followup-RANKING-reranked.json`, cấu hình `rca-followup-config.json` |
| Sau khi thu hẹp policy: 392/449 case có flow (87%) | `../receipts/rca-flow-coverage-after-policy-change.json` |

## Thí nghiệm syscall (`syscall/`, `receipts/arm-table-*`)

| Con số | File |
|---|---|
| Replay pulse-attack-dev cho 11 cấu hình (recall/control/p95 theo alpha) | `arm-replay-pulse-attack-dev-RESULTS.json` |
| So ở cùng ngân sách (holdout syscall-arms + pulse-attack-dev) | `arm-budget-syscall-arms-holdout-RESULTS.json`, bảng nội suy `../receipts/arm-table-syscall-arms-holdout-pulse-attack-dev.json` |
| Trên pulse-live-recalibrated có binary vô hại; khoảng cách recall − benign | `arm-replay-pulse-live-recalibrated-RESULTS.json`, `arm-budget-pulse-live-recalibrated-RESULTS.json`, `../receipts/arm-table-pulse-live-recalibrated.json` |

**Lưu ý trung thực:** các replay trên dùng khóa trial trần (`"12:attack"`), có thể trùng giữa các campaign
(phát hiện 19/10 17:52, ~5% trial của workload trùng). Job `syscall-arms-bootstrap` chạy lại với khóa đã sửa;
kết quả mới sẽ thay thế các file này trong báo cáo.
