# Publication statistics

| Metric | Estimate | 95% interval |
|---|---:|---:|
| Precision | 1.000000 | [0.9806807954262788, 1.0] |
| Recall | 0.975000 | [0.942821659593358, 0.9892752803482386] |
| F1 | 0.987342 | descriptive |
| False alerts/window | 0.000000 | [0.0, 3.5507962676948984e-05] |

| Path | n | p50 | p95 | p99 | max | bootstrap 95% CI of median |
|---|---:|---:|---:|---:|---:|---:|
| Confirmed ML | 195 | 18.549657s | 20.587361s | 20.980579s | 21.084921s | [17.666825771331787, 18.732598304748535] |
| Fast early warning | 75 | 0.452874s | 0.760794s | 0.890540s | 0.907293s | [0.4186134338378906, 0.5017054080963135] |

Các khoảng Wilson dùng đơn vị thử nghiệm ghi trong JSON. Cửa sổ normal có tương quan thời gian; kết quả paper cuối phải bổ sung block bootstrap theo run độc lập.
