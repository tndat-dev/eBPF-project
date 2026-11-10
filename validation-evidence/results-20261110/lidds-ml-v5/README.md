# lidds-ml-v5 trên LID-DS 2021 và CB-DS (10/11/2026)

Protocol `sentinel_pulse/protocol/lidds-ml-v5.json` + amendment 1, 2. Ma trận điểm của mô hình gộp: `lidds_ml_token_pool.py`
(unit `lidds-ml-v5-pool`, source a01b843, 10/11 15:52–20:27). Chấm: `lidds_ml_v5.py`, source 4addad0, 10/11 20:51–20:55.

## Bước 1: development + CB-DS (`lidds-ml-v5-development.json`)

Cổng: không gate, ba nhánh tái lập đúng 530/544 và 12 báo nhầm của lidds-ml-v4.

| Ứng viên | Development | Báo nhầm | CB-DS | Giữ v4 |
|---|---|---|---|---|
| ba nhánh, không gate (tham chiếu) | 530/544 | 12 | 891/891, 3 | có |
| chỉ token, không gate | 530/544 | 6 | 891/891, 3 | có |
| chỉ token + mô hình gộp (3 mức) | 487–509 | 6 | 891/891, 3 | không |
| chỉ token + bỏ 1 s sau `execve` (4 mức) | 316–365 | 4 | 576/891 | không |
| chỉ token + bỏ 2 s sau `execve` (4 mức) | 315–364 | 4 | 549–550/891 | không |
| chỉ token + ngưỡng theo pha 1 s hoặc 2 s (3 mức mỗi loại) | 488–509 | 6 | 891/891, 3 | không |

Không gate nào giữ được kết quả v4. Ứng viên duy nhất qua là chỉ token không gate.

## Bước 2

Chỉ một ứng viên qua bước 1, nên bước 2 chỉ còn kiểm recall tốc độ chính ≥ 95% trên trial của `pulse-live-v4-1109` với fit mới
(`scripts/analysis/pulse_v5_select.py`, xem `results-20261110/pulse-live-v5-fit/`).

## Bước 3: official (`lidds-ml-v5-official.json`), một ứng viên

`token-hold0-poolnone`: 1.238/1.271 (97,40%, CI 96,38–98,15), báo nhầm 26/7.938 (0,33%, CI 0,22–0,48), precision theo tỉ lệ dataset
97,94%, p95 1,47 s, trong 3 s 1.234. Ngưỡng đăng ký: ít nhất 1.238, tối đa 36 báo nhầm, p95 ≤ 1,5 s: đạt.

Số này trùng với nhánh token một mình đã báo cáo trong biên nhận lidds-ml-v4 (cùng mô hình, cùng ngưỡng); lần chấm này là theo
quy tắc của v5.

## Điều rút ra

- Hướng gate cho binary vô hại bị loại vì không giữ được kết quả LID-DS: bỏ qua pha sau `execve` làm mất bằng chứng của nhiều exploit,
  còn mô hình gộp các kịch bản làm mất 21–43 bản ghi development.
- Mô phỏng trên trial của cụm (binary vô hại 2/136) đọc trên dữ liệu có nhãn và không chuyển sang dataset.
- Hệ thống từ nay là nhánh token của v4, không có cây và support: cùng recall, ít hơn 10 báo nhầm trên official.
