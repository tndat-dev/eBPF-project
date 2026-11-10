# Hướng cải thiện sau lượt `pulse-live-v4-1109` (10/11/2026)

Số đo từ trial của lượt `pulse-live-v4-1109` (campaign xong 525/525; phần gánh cảnh báo chưa tính vì capture còn chạy lúc viết).
Script và đầu ra: `validation-evidence/results-20261109/benign-burden-research/`. Các phép mô phỏng đọc trên dữ liệu có nhãn của
chính lượt này, nên chỉ để chọn hướng, không phải kết quả.

## Kết quả trial của v4 (nhánh token, `trial_arms.py`)

| | Token | Cây + support |
|---|---|---|
| Recall, tốc độ chính 6/12/24 | 315/315 | 133/315 |
| Recall, mọi tốc độ | 525/525 | 187/525 |
| Control nhàn rỗi bị báo | 5/525 | 0/525 |
| Binary vô hại bị gắn cờ | 522/525 | 76/525 |
| p95 kernel → cuối cửa sổ / → decision | 0,49 s / 0,64 s | 4,01 s / 4,11 s |

Cây + support không bắt thêm trial nào ngoài token. Điểm yếu duy nhất của token là binary vô hại (99,4%).

## Hướng 1: gate `lidds-ml-v5` (đã đăng ký, chưa chấm)

Mô hình gộp toàn cụm + ngưỡng riêng cho pha sau `execve`. Mô phỏng: binary vô hại 2/136, tốc độ chính 69/69, mọi tốc độ 99/133.
Phải giữ kết quả v4 trên LID-DS 2021 trước khi chạy live.

## Hướng 2: gánh cảnh báo do capture chưa phủ, học thêm normal

- Mọi cửa sổ báo nhầm trên normal trong mẫu (146/146) đều chứa 4-gram chưa từng thấy lúc học: nguyên nhân là 12 giờ capture
  chưa phủ các sự kiện hiếm có chu kỳ, không phải ngưỡng sai.
- Các đợt lặp lại chữ ký: 118 đợt nhưng chỉ 28 đợt có chữ ký chưa từng xuất hiện trước đó; Kafka 89 đợt với 5 chữ ký.
- Mô phỏng "học gram đã báo sau 60 s" (`recurrence.py`): 118 → 45 đợt; đòi thấy ở 2 pod: 118 → 79. Tấn công không bị ảnh hưởng
  trong mô phỏng (133/133 trial vẫn còn gram ngoài tập đã học).
- Rủi ro: tự học từ chính cảnh báo là đường đầu độc (kẻ tấn công lặp lại hành vi để được coi là normal). Văn liệu về drift nêu
  cùng vấn đề: học tăng dần ngây thơ làm yếu phát hiện ([METANOIA](https://arxiv.org/abs/2501.00438)).
- Đề xuất an toàn hơn và rẻ: học thêm từ normal của lượt 1109 ngoài mọi khoảng trial (mô hình đếm nên cộng dồn được), tức khoảng
  36 giờ normal thay vì 12. Không có cơ chế tự học lúc chạy. Cần amendment trước khi fit.

## Hướng 3: bằng chứng mô hình hơn luật novelty khi chạy thật

Trên 132 khoảng control: luật "có 4-gram chưa thấy" báo 33 khoảng (25%), mô hình báo 3 (2,3%). Theo cửa sổ: 4,97% so với 0,078%.
Luật đếm có ngưỡng (từ 10 gram chưa thấy trở lên) thì ngang mô hình trên mẫu này (control 1/132, tấn công 133/133), nhưng ngưỡng 10
được chọn khi nhìn nhãn. Kết luận trung thực: mô hình hơn hẳn luật any-mismatch khi chạy thật; so với luật đếm có hiệu chỉnh thì
chưa chứng minh được, cần so trên toàn lượt với ngưỡng fit từ normal.

## Hướng 4: tấn công thật trên cụm

Fixture hiện tại là 5 vòng lặp syscall nhạy cảm. Hai nguồn exploit thật: (a) lệnh admin thật đã thêm cho lượt v5 (đối chứng vô
hại); (b) dựng vài kịch bản LID-DS 2021 thành workload trên cụm rồi chạy exploit gốc. Chưa xác minh mã kịch bản của LID-DS dùng
lại được trên Kubernetes; đây là việc lớn nhất và có giá trị nhất cho bài báo.

## Hướng 5 (dài hạn): chấm theo process

Tách luồng token của process vào qua `kubectl exec` khỏi luồng của workload (thêm một bit vào khoá gram), rồi chấm luồng đó bằng
mô hình riêng. Đây là lời giải gốc cho binary vô hại, nhưng phải đổi probe, proof và đo lại overhead.

## Thứ tự đề xuất

1. `lidds-ml-v5` trên LID-DS (cổng giữ kết quả v4), kèm học thêm normal của lượt 1109 (hướng 2, cần amendment).
2. Lượt live v5 có lệnh admin thật.
3. LID-DS 2019 một lần.
4. Exploit thật trên cụm; so mô hình với luật đếm có hiệu chỉnh trên toàn lượt.
5. Chấm theo process nếu gate chưa đủ.
