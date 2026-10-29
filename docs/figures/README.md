# Hình cho luận văn và paper

Sinh lại bằng `scripts/figures/thesis_figures.py`. Script chỉ đọc biên nhận đã commit trong `validation-evidence/`, không cần cụm:

```
python3 -m venv ~/.venvs/sentinel-figures && ~/.venvs/sentinel-figures/bin/pip install -r requirements-figures.txt
~/.venvs/sentinel-figures/bin/python scripts/figures/thesis_figures.py --lang vi   # hoặc --lang en
```

Mỗi hình có bản PNG (200 dpi) và PDF trong `vi/` (tiếng Việt) và `en/` (tiếng Anh).

| Hình | Nội dung | Nguồn | Lưu ý khi viết chú thích |
|---|---|---|---|
| `live-runs-metrics` | Precision, recall, control idle, binary vô hại của 6 lượt live (tới `pulse-final-system-confirm`, chỉ phần ML), CI 95% Wilson (`--no-ci`: chỉ điểm, dùng cho báo cáo docx và slide) | `results-20261019/pulse-live-recalibrated/campaign-main-RESULTS.json.gz`, `results-20261021/pulse-stable-{candidate,refreshed}/campaign-RESULTS.json`, `results-20261023/pulse-stable-confirm/campaign-{RESULTS,trials}.json` | Nhãn kỳ vọng, chưa review; lượt đầu dùng `policy-1win-a3`, hai lượt sau k2of2 α×10, lượt xác nhận CUSUM b3/h6 `cap`. Lượt xác nhận chỉ lấy tập chính (tốc độ 6, 12, 24/s), cùng thành phần với các lượt trước; lượt này **không đạt** luật (Pulse 5.25). Pulse 5.5, 5.8a, 5.13a, 5.25 |
| `live-latency-cdf` | Phân bố độ trễ kernel → preview của attack đã phát hiện, 4 lượt | như trên | Có điều kiện trên attack được phát hiện; preview, chưa phải cảnh báo tới người nhận (xem `alert-delivery-cdf`) |
| `policy-pareto` | 34 chính sách: gánh cảnh báo so với p95 trên pulse-stable-candidate, calibration làm mới; tô đậm tập thỏa luật v2 | `results-20261021/pulse-stable-candidate/final/policy-pareto-refreshed.json` | Development (replay); CI gánh cảnh báo nằm trong biên nhận; Pulse 5.8j |
| `feature-groups` | Thay đổi so với base29 khi bỏ một nhóm feature hoặc một nhánh p-value: Δ recall và Δ tách binary vô hại (điểm %, CI bootstrap 95% theo workload), Δ p95 (s, chỉ điểm) | `results-20261022/syscall/feature-groups-{primary,branches}/VERDICT.json` | Holdout chính, luật v1 k2of2, ngân sách 1; hai bộ attack (`pulse-attack-dev` không có binary vô hại nên không có Δ tách). Kết luận gộp với holdout thứ hai nằm ở syscall 5B.3, không đọc thẳng từ hình |
| `burden-levers` | Gánh cảnh báo trên normal (đợt/replica-giờ) của các cấu hình 5.22 trên hai lượt development và test blind trên lượt xác nhận, kèm ngân sách 0,1 | `results-20261022/pulse/burden-levers.json`, `results-20261021/pulse-stable-refreshed/final/cusum-carryover.json`, `results-20261023/pulse-stable-confirm/burden-blind-test.json` | Test blind chỉ có CI cho CUSUM `cap` (biên nhận 23/10); k2of2 α×10 không có trong test blind. Cấu hình ≤ 3 s đạt rule 5, đang xác nhận live (Pulse 5.26) |
| `live-runs-table.md` | Bảng số của `live-runs-metrics` và `live-latency-cdf`: đếm, CI Wilson, p50/p95 | như `live-runs-metrics` | Cùng hàm đếm với hình, nên luôn khớp nhau |
| `alert-delivery-cdf` | Lượt xác nhận: độ trễ kernel → người nhận theo từng đường cảnh báo (push vào Alertmanager, Prometheus pull nhanh và mặc định), trục y là phần trăm **mọi** trial attack của tập chính | `results-20261023/pulse-stable-confirm/delivery-latency-campaign.json` | Trial từ 03:53:22 (cả 3 đường đã chạy); 14 trial không có cảnh báo mới vì container đang báo sẵn. Phân vị theo hạng gần nhất như script. Chú giải ghi thêm push theo quy tắc cửa sổ của campaign (bỏ đợt mở từ cửa sổ vắt qua lúc tiêm). RCA 5.14 |
| `rule-comparison-table.md` | So sánh không có / có rule (R6): 5 nhánh trên cùng trial và cùng khoảng normal; hiệu gánh và p95 so với A, CI bootstrap | `results-20261025/rule-integration/rule-comparison.json` | Tập chính của lượt `pulse-peer-discount-confirm`; độ trễ của B3 tính tới lúc tạo case RCA; kết quả rule tách khỏi ML (RULE_INTEGRATION_STATUS R6) |
| `baselines-budget` | Recall và tỉ lệ binary vô hại bị gắn cờ theo gánh cảnh báo, Pulse so với 3 baseline | `results-20261021/baselines/RESULTS-budget.json` | Development: cùng capture đã dùng để chọn policy; k2of2; mỗi điểm là một hệ số α; Pulse 5.15a. Lần lặp lại trên dữ liệu mới: 5.15b |

Màu theo thứ tự đã kiểm cho người mù màu (xanh dương, cam, xanh ngọc, vàng). Mỗi chuỗi có thêm kiểu đường và marker riêng, nên in đen trắng vẫn phân biệt được.
