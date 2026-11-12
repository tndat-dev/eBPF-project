# Lượt live blind `pulse-live-v5-1110` (11–12/11/2026)

Protocol `lidds-ml-v5` + amendment 1, 2, 3. Hệ thống: chỉ mô hình token, không gate; mô hình học từ 12 giờ capture cộng normal của
`pulse-live-v4-1109` (biên nhận fit: `results-20261111/pulse-live-v5-fit/`). Nhánh đếm (cây, support) chỉ ghi shadow.
Lượt chạy từ snapshot `runtime-9a506d1-20261110`: 86.400 s trên 3 worker, campaign 525 cặp, xong 11/11 15:16; capture xong 12/11 01:10.

Phân tích: `scripts/analysis/pulse_live_v4.py` (commit 0f2314b), `alert_delivery_latency.py`, `bridge_delivery.py`, `rca_coverage.py`,
`rca_follow_up.py` (commit 740d3aa), chạy trên `.234` ngày 12/11 08:17–08:30 sau khi lượt chạy kết thúc.

## Sự cố trong lượt: hypervisor nghẽn 3,5 phút

Ngày 11/11 từ 13:47:33 tới 13:51:04, cả ba worker ghi `cadence_gap` cùng lúc (50, 42, 20 issue; đây là toàn bộ issue của lượt). Kernel
của các VM ghi `hrtimer: interrupt took 81622731 ns` và `workqueue ... hogged CPU` từ đúng giây đó trên mọi worker: host ESXi nghẽn,
không phải Pulse. Amendment 3 (đăng ký trước khi chạy phân tích) giữ phân tích đã đăng ký trên mọi cặp và thêm bản độ nhạy không có
khoảng nghẽn ±30 s (bỏ cặp 465 và 466).

## Kết quả của mô hình token (`arms.json`, nhánh `T` = `system`)

| | Đã đăng ký (mọi cặp) | Không có khoảng nghẽn |
|---|---|---|
| Tấn công, tốc độ chính 6/12/24 | 314/314 (CI 98,8–100) | 313/313 |
| Tấn công, mọi tốc độ | 521/522 (1/s: 102/103) | 520/521 |
| Control idle bị báo, tốc độ chính / mọi tốc độ | 0/314 / 0/522 | 0/313 / 0/521 |
| Precision (control idle là mẫu âm) | 100% (CI 98,8–100) | 100% |
| Binary vô hại bị gắn cờ, tốc độ chính / mọi tốc độ | 314/314 / 520/522 | 313/313 / 519/521 |
| Lệnh admin bị gắn cờ, tốc độ chính / mọi tốc độ | 255/261 / 419/436 (96,1%) | 255/260 / 419/435 |
| p50 / p95 kernel → cuối cửa sổ báo | 0,35 s / 0,49 s | 0,35 s / 0,49 s |
| Gánh, đợt mỗi replica-giờ | 0,165 (CI 0,057–0,332; 104 đợt / 630,1 replica-giờ) | như bên trái |

- 3 cặp không có đoạn tấn công và 2 cặp không có đoạn binary vô hại (lỗi khởi chạy trial), nên có 522 tấn công.
- Lệnh admin: 436/525 lệnh chạy được (mã thoát 0); lệnh image không có bị bỏ theo protocol. Theo lệnh: `cat` 49/49, `df` 51/51,
  `env` 52/52, `id` 51/51, `ls` 44/44, `ps` 7/7, `sh` 46/48, `date` 45/50, `uname` 43/49, `python` 34/38.
- Thời gian chấm sau cuối cửa sổ: p50 0,149 s, p95 0,185 s, p99 0,277 s (10,9 triệu cửa sổ); lớn nhất 51,5 s nằm trong khoảng nghẽn.
- Nhánh đếm shadow: 134/314 tấn công tốc độ chính, p95 4,02 s; không vào đường cảnh báo.

**Mức chấp nhận của protocol:** recall, precision, control, p95 và gánh (≤ 1,76) đạt. Binary vô hại và lệnh admin (mỗi loại ≤ 20%)
**không đạt**: 100% và 96,1%.

So với `pulse-live-v4-1109` (cùng mô hình, chỉ học 12 giờ capture): gánh 0,41 → 0,165, control idle 3/315 → 0/314. Hai lượt khác
ngày, không phải so sánh có đối chứng.

## Đường tới Alertmanager (`delivery-latency.json`, `bridge-delivery.json`)

- Kernel → Alertmanager nhận, đường push: 521/522 tấn công có cảnh báo tới nơi, p50 0,51 s, p95 0,68 s, lớn nhất 6,55 s. Theo tốc độ,
  p95 0,65–0,69 s. Đường pull nhanh p50 5,29 s; pull mặc định p50 60,3 s và chỉ tới ở 143/522 trial.
- Ngoài khoảng nghẽn: 2.075/2.075 đợt cảnh báo tới Alertmanager; từ decision tới lúc nhận p50 0,034 s, p95 0,064 s, lớn nhất 0,16 s.
- Trong khoảng nghẽn: 113/190 đợt không tới (35 đợt không có lần push nào thành công); các đợt tới nơi chậm tới 112 s.

## RCA (`rca-coverage.json`, `rca-follow-up.json`)

- Tấn công có case riêng: 467/522 (89,5%); binary tấn công đứng hạng 1 ở 464/467 case (99,4%); 340 case có sự kiện flow.
- Cảnh báo → case: p50 2,33 s, p95 2,61 s.
- 55 tấn công không có case riêng, theo log kiểm toán của bước mở case tiếp nối:
  - 51: exec của binary tấn công **đã có** trong nhật ký exec mà vẫn bị từ chối (`binary_not_new` 42 dòng, `no_exec` 12 dòng);
  - 3: quyết định được lấy khi exec của binary tấn công chưa có; 1: không có quyết định nào.
  - 40 trong 55 là lần chạy lại cùng binary tấn công trên cùng container sau 85–345 s: gộp theo thiết kế. 14 còn lại bị từ chối vì
    cửa sổ báo đầu tiên kết thúc khoảng 0,2 s sau khi trial bắt đầu, trước lúc binary tấn công exec: mô hình báo trên burst dựng
    process của `runc`, và RCA chỉ xét exec tới cuối cửa sổ báo. Đã sửa ở commit 41d527f (`follow_up_recheck_seconds`), chưa đo live.
- Độ trễ sự kiện exec (lúc RCA nhận trừ lúc exec): binary tấn công p50 0,034 s, p95 0,10 s, lớn nhất 0,38 s (464 trial). Ngoài khoảng
  nghẽn có 41/1.284 dòng kiểm toán trễ trên 10 s (tới 45 s): tất cả là `/usr/local/bin/python` của các service trong pha chọn
  (01:47–02:40), không phải binary tấn công. Giả thuyết "exec của tấn công tới sau cảnh báo vì Tetragon giao muộn" bị bác.

## CPU của worker

`systemd` ghi cho unit `pulse-matched-worker-pulse-live-v5-1110` (loader + worker Python, gồm cả nhánh đếm shadow, 86.400 s):

| Worker | CPU | Trung bình |
|---|---|---|
| k8s-worker1 | 7 h 19 min 28 s | 0,305 core |
| k8s-worker4 | 7 h 05 min 38 s | 0,296 core |
| k8s-worker3 | 7 h 28 min 18 s (đỉnh bộ nhớ 3,0 GB, bằng trần của unit) | 0,311 core |

Đây là cận trên cho riêng mô hình token, vì nhánh đếm vẫn được tính để so sánh.

## Giới hạn

- Tấn công là 5 fixture tự viết; binary vô hại và tấn công cùng một fixture. Lệnh admin là lớp đối chứng chưa từng dùng để chọn gì.
- Trong mỗi cặp, tấn công luôn chạy sau binary vô hại và lệnh admin, nên hạng 1 của RCA được lợi từ luật phá hoà theo thời điểm.
- Một lần xem giữa lượt (11/11 10:07, số đếm từ bridge) có trước amendment 3; không quyết định nào dựa trên nó.
