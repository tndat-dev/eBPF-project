# Fit lidds-ml-v4 cho cụm (`pulse-live-v3-v1-amendment-2`)

Dữ liệu: `pulse-token-capture-1107` (chỉ normal, 12 h). Source 7594780. Fit xong 09/11 11:23 (+07), trước sự cố vCenter 13:10.
Mô hình và ngưỡng: `/mnt/sentinel-pulse-archive/pulse-live-v4-fit-1109/`. Khoá theo sha256:

- `token/MODELS.json`: 5799cc2ebe9c71eae40d8e00bf75e13bf5f05d2e46b173f64c93f0ff7a4d7b14 (21 workload, mỗi model có sha256 riêng trong file)
- `count-thresholds.json`: 94ac444502b9c05ba9d8087a206fd40a709acfdc48cf9ff0fe3c960b7a8fe2a6 (21 workload)

## Khối 60 s vượt ngưỡng nhánh token, trên normal của chính lượt thu

| | v3 (`token-FIT-v3-for-comparison.json`) | v4 (`token-FIT.json`) |
|---|---|---|
| Cách tính | Mô hình 8 h đầu, chấm 4 h validation | Điểm giữ ra của cross-fit trên cả 12 h |
| Khối vượt ngưỡng | 14/16.371 (0,086%) | 145/48.531 (0,299%) |
| Mức thiết kế mỗi khối | 0,0067% | 0,018% |
| Gấp mức thiết kế | 12,8 lần | 16,6 lần |
| Mỗi giờ, toàn cụm | khoảng 3,4 | khoảng 12 |

v4 có ngưỡng token thấp hơn v3 ở 19/21 workload, nên dự kiến báo nhầm nền của nhánh token trên cụm cao hơn khoảng 3,5 lần. Mô hình
cuối của v4 học cả 12 h nên điểm giữ ra là ước lượng hơi bi quan. Nhiều nhất: RabbitMQ 23, MinIO 18, waypoint 13. Ngưỡng không chỉnh
sau khi xem các số này; lượt live đo mức thật.
