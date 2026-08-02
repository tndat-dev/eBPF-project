# Publication statistics

| Metric | Estimate | 95% interval |
|---|---:|---:|
| Precision | 1.000000 | [0.7961166989641515, 1.0] |
| Recall | 1.000000 | [0.7961166989641515, 1.0] |
| F1 | 1.000000 | descriptive |
| False alerts/window | 0.000000 | [0.0, 0.015562453888609386] |

| Path | n | p50 | p95 | p99 | max | bootstrap 95% CI of median |
|---|---:|---:|---:|---:|---:|---:|
| Confirmed ML | 15 | 17.302507s | 18.446091s | 18.563689s | 18.593088s | [8.65762186050415, 18.02890133857727] |
| Fast early warning | 6 | 0.285293s | 0.919387s | 0.948725s | 0.956060s | [0.17606890201568604, 0.8827135562896729] |

Các khoảng Wilson dùng đơn vị thử nghiệm ghi trong JSON. Cửa sổ normal có tương quan thời gian; kết quả paper cuối phải bổ sung block bootstrap theo run độc lập.
