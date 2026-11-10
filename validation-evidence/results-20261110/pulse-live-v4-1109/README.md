# Lượt live blind `pulse-live-v4-1109` (09–10/11/2026)

Protocol `pulse-live-v3-v1` + amendment 1, 2 (hệ thống `lidds-ml-v4` trên cụm). Lượt chạy từ snapshot 1167481; phân tích bằng
`scripts/analysis/pulse_live_v4.py` ở commit a01b843 (unit `pulse-live-v4-analysis` trên `.234`, 10/11 15:52–16:04). Kết quả: `arms.json`.

Capture 86.400 s mỗi worker, 48 segment, 0 issue; campaign 525/525 trial. Khoảng normal để tính gánh: từ hết pha chọn tới hết
capture, bỏ khoảng campaign (817,1 replica-giờ).

| Tốc độ chính 6/12/24 | Hệ thống v4 (token + cây + support) | Chỉ token | Chỉ cây + support |
|---|---|---|---|
| Recall | 315/315 (CI 98,8–100) | 315/315 | 133/315 |
| Precision (control nhàn rỗi) | 99,06% (CI 97,26–99,68) | 99,06% | 100% |
| Control nhàn rỗi bị báo | 3/315 (0,95%; CI 0,32–2,76) | 3/315 | 0/315 |
| Binary vô hại bị gắn cờ | 314/315 | 313/315 | 46/315 |
| p50 / p95 kernel → cuối cửa sổ báo | 0,34 s / 0,49 s | 0,34 s / 0,49 s | 0,43 s / 4,01 s |
| Gánh, đợt mỗi replica-giờ | 0,521 (CI 0,214–0,906; 426 đợt) | 0,406 (CI 0,150–0,733) | 0,163 |
| Bốn kỳ vọng của protocol | Đạt cả bốn | Đạt cả bốn | Không đạt |

Mọi tốc độ (1, 3, 6, 12, 24 mỗi giây): hệ thống và token 525/525 (105/105 ở từng tốc độ), control 5/525, binary vô hại 523/525.

Thời gian chấm sau cuối cửa sổ: token p50 0,147 s, p95 0,181 s, max 0,622 s; nhánh đếm p95 0,126 s. Cộng vào p95 ở bảng, từ kernel
tới decision được ghi là khoảng 0,64 s (đo trên file trial, `results-20261109/benign-burden-research/trial_arms.py`).

## Giới hạn

- Thời điểm báo lấy theo cuối cửa sổ và lúc ghi decision. Độ trễ tới Alertmanager và RCA của nhánh token không đo được ở lượt này:
  bridge bỏ mọi dòng của nhánh token (lỗi đã sửa cho lượt sau), nên cảnh báo token không đi qua đường cảnh báo.
- Binary vô hại bị gắn cờ 99,7%: mô hình phát hiện process mới, chưa tách được ý đồ. Đây là lý do có `lidds-ml-v5`.
- Trong pha chọn (trước 15:29), lúc 14:01 có tạo lại 5 pod bất thường sau sự cố vCenter; khoảng này không nằm trong phép đo.
- Gánh 0,521 so với 1,76 của `pulse-final-system-confirm` là hai lượt khác ngày và khác tải nền, không phải so sánh có đối chứng.
- Tấn công là 5 fixture tự viết, không phải exploit thật.
