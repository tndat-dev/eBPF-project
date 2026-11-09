# lidds-ml-v4: chấm official (lần thứ 3 trên LID-DS 2021 official)

Protocol: `sentinel_pulse/protocol/lidds-ml-v4.json`, đăng ký 09/11 01:55 (+07), trước mọi điểm official của nhánh token
cross-fit. Điểm token: unit `lidds-ml-v4-tokens` trên `.234`, source 5bfbea5, xong 09/11 05:38 (+07). Chấm official: 09/11
10:33 (+07), chạy đúng một lần bằng `lidds_ml_v4.py --official`.

Kết quả official của v2 và v3 đã biết khi thiết kế vòng này, dù mọi lựa chọn đều làm trên development và CB-DS. Đây không phải
bằng chứng độc lập; bằng chứng độc lập vẫn là lượt live blind và LID-DS 2019.

## Cổng trước khi đọc official

- `gate_tokens.py` (`gate-tokens.txt`): điểm mới trùng tuyệt đối điểm chỉ-development trên 10.572 khoá, 699.271 cửa sổ; 0 khác
  biệt, 0 thiếu. 9.209 khoá chỉ có ở bản mới là bản ghi official, không đọc ở bước này.
- Scorer tái lập số đã đăng ký: development 530/544, 12/3.403; CB-DS 891/891, 3/1.410.

## Kết quả (`lidds-ml-v4.json`)

| Official | v4 | v3 (07/11) |
|---|---|---|
| Recall | 97,40% (1.238/1.271) | 97,32% (1.237/1.271) |
| CI 95% recall | 96,38–98,15 | 96,29–98,08 |
| Báo nhầm | 0,454% (36/7.938) | 0,441% (35/7.938) |
| CI 95% báo nhầm | 0,33–0,63 | 0,32–0,61 |
| Precision theo base rate | 97,17% | 97,25% |
| Latency p50 | 0,39 s | 0,43 s |
| Latency p95 | 1,47 s | 2,09 s |
| Phát hiện trong 3 s | 1.234 | 1.223 |

Cả ba tiêu chí của protocol đều đạt (recall ≥ 95%, precision ≥ 95%, p95 ≤ 3 s).

Báo cáo thêm, không phải hệ thống được chọn: nhánh token một mình ở cùng mức α có 1.238/1.271, báo nhầm 26/7.938 (0,33%),
precision 97,94%, p95 1,47 s. Trên official, cây và support không thêm phát hiện nào mà thêm 10 báo nhầm.

## Kết luận theo quy tắc đã đăng ký

Protocol ghi: "v3 stays the reference if v4 is worse on false alarms or recall". v4 báo nhầm 36 so với 35, tức nhiều hơn một
bản ghi, nên **v3 vẫn là mốc tham chiếu**. Chênh lệch này nằm trong sai số thống kê, nhưng quy tắc viết trước khi chấm không có
ngoại lệ về sai số, nên áp dụng nguyên văn.

## Điều rút ra

- Development giảm báo nhầm từ 17 xuống 12 nhưng official không giảm (35 → 36): phần cải thiện báo nhầm chọn trên development
  không chuyển sang official. Protocol đã cảnh báo các số development là lạc quan vì đã so vài trăm cấu hình.
- Cải thiện có chuyển sang official là latency: p95 2,09 s → 1,47 s, trong 3 s 1.223 → 1.234 (CVE-2012-2122 p95 5,18 s → 0,47 s).
  Quy tắc đăng ký không xét latency, nên việc có đổi sang v4 vì latency hay không là quyết định của chủ đồ án.
- Recall vẫn dừng ở 97,4%; trần thông tin là 1.243/1.271 (28 bản ghi Juice-Shop `SQLInjectionUser` không để lại dấu vết).
