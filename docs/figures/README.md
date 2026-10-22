# Hình cho luận văn và paper

Sinh lại bằng `scripts/figures/thesis_figures.py`. Script chỉ đọc biên nhận đã commit trong `validation-evidence/`, không cần cụm:

```
python3 -m venv ~/.venvs/sentinel-figures && ~/.venvs/sentinel-figures/bin/pip install -r requirements-figures.txt
~/.venvs/sentinel-figures/bin/python scripts/figures/thesis_figures.py --lang vi   # hoặc --lang en
```

Mỗi hình có bản PNG (200 dpi) và PDF trong `vi/` (tiếng Việt) và `en/` (tiếng Anh).

| Hình | Nội dung | Nguồn | Lưu ý khi viết chú thích |
|---|---|---|---|
| `live-runs-metrics` | Precision, recall, control idle, binary vô hại của 3 lượt live, CI 95% Wilson (`--no-ci`: chỉ điểm, dùng cho báo cáo docx và slide) | `results-20261019/pulse-live-recalibrated/campaign-main-RESULTS.json.gz`, `results-20261021/pulse-stable-{candidate,refreshed}/campaign-RESULTS.json` | Nhãn kỳ vọng, chưa review; lượt đầu dùng `policy-1win-a3`, hai lượt sau dùng k2of2 α×10; Pulse 5.5, 5.8a, 5.13a |
| `live-latency-cdf` | Phân bố độ trễ kernel → preview của attack đã phát hiện | như trên | Có điều kiện trên attack được phát hiện; preview, chưa phải cảnh báo tới người nhận |
| `policy-pareto` | 34 chính sách: gánh cảnh báo so với p95 trên pulse-stable-candidate, calibration làm mới; tô đậm tập thỏa luật v2 | `results-20261021/pulse-stable-candidate/final/policy-pareto-refreshed.json` | Development (replay); CI gánh cảnh báo nằm trong biên nhận; Pulse 5.8j |
| `baselines-budget` | Recall và tỉ lệ binary vô hại bị gắn cờ theo gánh cảnh báo, Pulse so với 3 baseline | `results-20261021/baselines/RESULTS-budget.json` | Development: cùng capture đã dùng để chọn policy; k2of2; mỗi điểm là một hệ số α; Pulse 5.15a. Lần lặp lại trên dữ liệu mới: 5.15b |

Màu theo thứ tự đã kiểm cho người mù màu (xanh dương, cam, xanh ngọc, vàng). Mỗi chuỗi có thêm kiểu đường và marker riêng, nên in đen trắng vẫn phân biệt được.
