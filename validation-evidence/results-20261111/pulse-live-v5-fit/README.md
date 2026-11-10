# Fit `lidds-ml-v5` cho cụm (amendment 2) và bước chọn trên trial của lượt 1109

Normal: `pulse-token-capture-1107` (12 h) cộng normal của `pulse-live-v4-1109` ngoài các trial (mỗi trial bỏ từ 5 s trước tới 25 s
sau lúc bắt đầu, `token_branch_fit.trial_spans`). Source 4addad0. Fit xong 10/11 22:23 (+07), 5 h 35 phút CPU, đỉnh 36,0 GB.
Mô hình và ngưỡng: `/mnt/sentinel-pulse-archive/pulse-live-v5-fit-1110/`. Khoá theo sha256:

- `token/MODELS.json` (`token-MODELS.json`): 8b71f797643228fdae6a77eb8c890141632fff2fe66f1fefaa0b6b40fb5702e7
- `token/FIT.json` (`token-FIT.json`): 279ac64871ee007e61f124038a9b7fd0af4c4b4e4ad827979951bc698a2a834f
- `count-thresholds.json` (nhánh đếm, `shadow: true`): 533640b07e32b7d03d764473fa3769ed1ed4b00a97aa1510bcf3faaedef60229
- `select/SELECT.json`: f3d39251a162060934cf43de3e778a555f1e8a6c357451b4d366ba3757aaa08e
- `select/MODELS.json` (`select-MODELS.json`, file lượt live dùng): 60ec8b153594cf768148550ccdf8acbeefe7b9c361f10c9ff5645c8f5d26ca88

## Ngưỡng so với fit v4

- Khối 60 s vượt ngưỡng trên điểm giữ ra của cross-fit: 350/134.905 (0,259%); fit v4: 145/48.531 (0,299%).
- Ngưỡng thấp hơn fit v4 ở 15/21 workload, trung vị chênh −0,49.

## Bước 2: chọn gate (`scripts/analysis/pulse_v5_select.py`, source 9a506d1, xong 10/11 22:59)

Ứng viên giữ được số v4 trên LID-DS development: `three-hold0-poolnone`, `token-hold0-poolnone`. Chỉ ứng viên một nhánh được xét.
Chọn: `token-hold0-poolnone` (không gate). Trên 525 trial của lượt 1109 (development cho bước này, fit không học cửa sổ nào
của chúng):

| | Bắt / tổng |
|---|---|
| Tấn công tốc độ chính (6, 12, 24/s) | 315/315 |
| Mọi tấn công | 525/525 |
| Binary vô hại | 522/525 |
| Control rảnh | 0/525 |

Chỉ ngưỡng mô hình gộp (không giữ sau `execve`): binary vô hại 520–522/525, gần như không giảm. Giữ 1–2 s sau `execve` hoặc
ngưỡng pha: binary vô hại 135–274/525 nhưng tấn công tốc độ chính chỉ 302–311/315. Mọi ứng viên có gate đều đã trượt LID-DS.
Bảng đầy đủ trong `SELECT.json`.
