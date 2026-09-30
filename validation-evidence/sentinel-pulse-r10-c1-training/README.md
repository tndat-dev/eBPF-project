# R10-C1 training: bản sao metadata

Sao chép trực tiếp qua SSH ngày 30-09-2026 từ
`dat@10.1.16.234:/home/dat/sentinel-pulse-evidence/training-r10-c1`.
Bundle đầy đủ ở VM có `COMPLETE`, readonly; toàn bộ checksum kiểm tra đạt
trước khi khởi chạy bounded live canary.

Thư mục Git này chỉ lưu `inference-benchmark.json`, `training-contract.json`
và checksum index gốc. Không chứa model pickle hoặc dataset. Do đó không chạy
`sha256sum -c SHA256SUMS` cho toàn bộ index tại đây; các file không sao chép
sẽ được báo missing. Hai JSON đã được đối chiếu hash với index gốc.

Benchmark là in-sample và chỉ đo inference. Không dùng số liệu này làm recall,
false-positive rate hay latency kernel-to-alert ngoài thực tế.
