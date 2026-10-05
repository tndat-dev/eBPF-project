# Operational soak R10-C3: start receipt

**Amendment terminal ngày 02/10:** run đã infrastructure-reject **11:37:15
ICT**, archive hoàn tất 11:38:33 ICT. Checksum archive được kiểm tra lại thành
công lúc 17:18 ICT. Candidate dừng, control collector phục hồi; lịch finalize
03/10 phía dưới là lịch đăng ký lịch sử, không phải run đang active.
Xem [terminal receipt](TERMINAL_INTEGRITY_RECEIPT_20261002.json) và
[bounded timing diagnostic](BOUNDED_LIVE_TIMING_20261002.json).
Giữ nguyên checkpoint start bên dưới; không đổi lịch sử thành kết quả pass.

SSH xác minh ngày 02/10/2026, checkpoint 11:10 ICT. Run đã ACTIVE trên ba
worker; chưa có OPERATIONAL_PASS/NORMAL_PASS hoặc kết quả blind mới.

- VM source: `/home/dat/eBPF-project-operational-soak-20261002`.
- Commit: `464bb99c3dc69611d4bb05f8b16434e7a9c0b4ab`.
- Regression: `337 passed, 12 subtests passed in 33.29s` với
  `/home/dat/ml-venv/bin/python -m pytest -q tests/test_sentinel_pulse*.py`.
- Model verify pass; manifest SHA:
  `6ddf7cf9b03cb783b82c23272f7046bafa7ab1412b0545b60a2821d1f441cc21`.
- Policy SHA:
  `602165bd48d81f549d3bfb65e5bdb319a11252678cbf484d739afcf2e5bc8143`.
- Profile file SHA:
  `c08a15b023f7ed40207d6362b75d2d39b8b23b4e958844b28899902eca90359d`.
- Feature schema SHA:
  `879e33f8c33774c50d848524b78c0fa2398b9855971982e5a41a12f9259f5ae2`.

SOAK_START.json lưu actual start, exposure/telemetry/capacity contract và bound
21 workload/container, 16 dependency Longhorn volumes. workers.txt có ba node.
START_SHA256SUMS chứa đường dẫn tuyệt đối **trên VM**; verify ở source/evidence
gốc, không claim receipt host có đủ file raw để verify toàn campaign.

First monitor snapshots: worker1 2.891 decision; worker3 1.885; worker4 638;
đều 0 alert/0 restart và feature-tail valid. Đây là ba thời điểm kiểm tra khác
nhau, không phải snapshot đồng bộ hoặc số lượng scored window đã adjudicate.
Không suy ra FPR=0, recall hoặc latency kernel-to-alert từ chúng.

Lifecycle: `sentinel-pulse-operational-r10-c3-20261002.service`.
Supervisor: `sentinel-pulse-operational-r10-c3-20261002-supervisor.service`.
Finalization dự kiến 12:03 ICT 03/10 + export, không tự mở blind/promote.
