# Snapshot đánh giá attack đang chạy

Đọc SSH `.234` ngày 08/10/2026 lúc 02:23:50 ICT (UTC 07/10 19:23:50).
Không dừng/restart service, không thay model/policy hay raw capture.

`STATUS.json` là bản byte-for-byte từ campaign
`/home/dat/sentinel-pulse-observation-attacks/pulse-observation-attack-c2-20261007`.
SHA-256: `0c6c4055300f25bc7e933408cc6f034ae524ab032f3a1ef4cdb3fdf91fad4c29`.

`inspection.json` tính lại từ prefix **447 receipt đầu** của `TRIALS.jsonl`,
đối chiếu kernel provenance bằng `sentinel_pulse.evaluate_latency.kernel_events`.
SHA prefix: `d44c64b01621a190f483170b8d4284f088ff1a1da69019912f7ab057266fdf11`.
Raw receipt và Tetragon/decision tails vẫn ở VM; không đưa log lớn vào Git.
Registration START SHA-256:
`9e9c4664d16c62809b0c58b047d27670b6a9a59079f4ce6f9e671ff4064b21e9`.

Campaign tiếp tục append: snapshot này không phải terminal; số kernel record
ở thời điểm inspection có thể gồm trial mới hơn prefix 447. Không audit lại
worker raw seals, không adjudicate normal ground truth và không promote.
FP/TN, precision, FPR chưa có số đo; `null` không có nghĩa là 0.
