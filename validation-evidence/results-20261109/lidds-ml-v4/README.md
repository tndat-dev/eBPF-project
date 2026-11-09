# lidds-ml-v4: kết quả trên LID-DS 2021

Protocol: `sentinel_pulse/protocol/lidds-ml-v4.json`. Điểm token: unit `lidds-ml-v4-tokens` trên `.234`, source 5bfbea5, xong
09/11 05:38 (+07). Chấm: 09/11 10:33 (+07) bằng `lidds_ml_v4.py --official`.

Mô hình token học trên training + validation; không bản ghi test nào được dùng để học.

## Cổng trước khi chấm

- `gate_tokens.py` (`gate-tokens.txt`): điểm mới trùng tuyệt đối điểm chỉ-development trên 10.572 khoá, 699.271 cửa sổ; 0 khác
  biệt, 0 thiếu.
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
precision 97,94%, p95 1,47 s. Trên official, cây và support không thêm phát hiện nào mà thêm 10 báo nhầm; chủ đồ án giữ hai nhánh
này (05/11) vì chúng thấy mẫu mprotect và seccomp trên cụm. Các arm của lượt live sẽ đo lại câu hỏi này.

## Quyết định

Quy tắc so sánh trong protocol giữ v3 nếu v4 kém hơn về recall hoặc báo nhầm. v4 báo nhầm nhiều hơn một bản ghi (36 so với 35),
chênh lệch nằm trong sai số thống kê. **Chủ đồ án chốt `lidds-ml-v4` ngày 09/11** vì latency tốt hơn rõ: p95 2,09 s → 1,47 s, trong 3 s
1.223 → 1.234 (CVE-2012-2122 p95 5,18 s → 0,47 s). Cách đưa v4 lên cụm: `pulse-live-v3-v1-amendment-2.json`.

## Điều rút ra

- Development giảm báo nhầm từ 17 xuống 12 nhưng official không giảm (35 → 36). Cải thiện giữ được là latency.
- Recall dừng ở 97,4%; trần thông tin là 1.243/1.271 (28 bản ghi Juice-Shop `SQLInjectionUser` không để lại dấu vết), nên phần còn
  có thể lấy thêm nhiều nhất là 5 bản ghi.
