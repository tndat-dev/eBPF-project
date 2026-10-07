# Kiểm tra triển khai paired evaluation

Đọc qua SSH trên `.234`, ngày 08/10/2026 02:34:18 ICT. `inspection.json`
ghi source/dirty status, service PID, queue, hash model/policy và STATUS attack.
SHA-256 STATUS raw trên VM: `e1bba34f710156c7fd2ed119d30199cfe21b7435d9d4872a2b9d0df7f1de822b`.
JSON STATUS trong inspection đã được parse, không phải bản raw byte đồng nhất.

`trial-prefix-summary.json` tính từ đúng 454 dòng đầu của TRIALS, không trộn
các trial hoàn tất sau inspection. Prefix raw SHA-256:
`78971893adeba26ece941dc3dcd32aa2cf3b0adca87cc71ffd89cd4849554003`.
Đối chiếu TP=131, FN observed=247, unknown=76 với STATUS.

Đây là snapshot read-only, **không phải terminal hay full raw-seal audit**.
Normal-control enabled/đang queued, chưa có FP/TN/precision mới hoặc RESULTS.
Source worker frozen và model/policy không thay đổi. Source controller mới
là 5bc0b29, worker vẫn ee2528b; không ép mọi serving checkout về HEAD mới.
