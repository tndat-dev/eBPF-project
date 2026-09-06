# B7 canary normal — 06-09-2026

`AGGREGATE.json` là bản sao nguyên byte từ VM `dat@10.1.16.234`, được lấy và
đối chiếu SHA-256 qua SSH ngày 06-09-2026, sau 15:11 UTC.

Nguồn:
`/home/dat/sentinel-pulse-evidence/canary-b7/sentinel-pulse-b7-canary-r1-20260906T080908Z/AGGREGATE.json`.

SHA-256 aggregate:
`dcbb7da40f5bd79fbe3507b12a06f0d45092abb048151b0526972155ea428a6c`.

SHA-256 `FINAL_SHA256SUMS` trên VM:
`9115cc28668b6b7db5566d336a6bfc56f7df9622b72c1c6f8d87e9361f5db26f`.
73 entry đã được kiểm chứng trên VM; raw stream vẫn ở archive đó.
Bản sao aggregate này không thay thế raw archive để tái tính các percentile.

Kết quả: `valid=true`, 63.534 decision, 62.851 scored, 0 alert, 0 restart,
20/20 workload-container key. Thời gian đo tối thiểu 901,991 giây.
Window-start-to-decision p99 0,852 giây; inference p99 29,574 ms.
Canary chỉ quan sát traffic normal, không đo recall hoặc kernel-to-alert
attack và không chứng minh false-positive rate bằng 0.
