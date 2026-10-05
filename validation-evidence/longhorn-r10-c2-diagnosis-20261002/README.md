# R10-C2: đối chiếu Longhorn timeout với node stall

Kiểm tra trực tiếp qua SSH ngày 02/10/2026; timestamp log là UTC.
Giữ nguyên Longhorn, PV/PVC, model và policy. Đây là điều tra hạ tầng,
không phải một formal normal pass hoặc kết quả attack evaluation.

## Chuỗi bằng chứng

| Thời điểm UTC ngày 01/10 | Quan sát |
|---|---|
| 15:50:47.952 | Engine Kafka trên worker1: `R/W Timeout. No response received in 8s`, peer `10.0.4.244:13466` |
| 15:50:48.976 | Engine Tempo trên worker1: cùng lỗi, peer `10.0.4.244:13496` |
| 15:50:50.015 | Engine OpenSearch trên worker3: cùng lỗi, peer `10.0.4.244:13456` |
| 15:50:52.943 | Journald worker4 lại có log kubelet sau mốc 15:50:42.243; khoảng im lặng log không tự chứng minh toàn VM bị pause |
| 15:50:52.960–52.978 | Worker4 ghi containerd `context deadline exceeded`, gồm message có timestamp nội bộ 15:50:48.142 |
| 15:50:53.495 | Kubelet worker4: housekeeping expected `1s`, actual `10.092s` |
| 15:50:53 | Ba replica worker4 ghi `lastFailedAt` trong receipt terminal C2 |
| 15:51:28 | Monitor formal dừng vì `unhealthy_longhorn_volume` |

IP `10.0.4.244` là instance-manager trên worker4. Log nguồn engine Kafka/Tempo:
`/var/log/pods/longhorn-system_instance-manager-ce78a02ffed28be43271f6f6f3dc8f25_1f852673-6e73-43fc-af51-b8c759308ebc/instance-manager/0.log.20261001-163554`
trên `.237`; engine OpenSearch từ current `0.log` của instance-manager
`1b0e97eff7c0c24b052a44050b9bf8f5` trên `.239`.

Đọc cả rotated log là cần thiết: current log trên worker1 không còn đoạn lỗi.
Các trích đoạn trong `engine_errors.txt`, `worker3_errors.txt` và
`worker4_journal_gap.txt` lấy bằng grep/journalctl từ những nguồn trên.
Kubelet log `path does not exist` là noise lặp sẵn; không coi đó là nguyên nhân
timeout. Host báo virtualization `vmware`, NTP synchronized tại thời điểm kiểm tra.

## Điều đã xác định và điều chưa xác định

Đã xác định cơ chế replica bị loại: R/W timeout 8 giây tới cùng worker4.
Containerd/kubelet cùng chậm khiến lỗi không thể chỉ được quy cho classifier
hoặc riêng một replica. Đây là tương quan thời gian ở failure domain chung;
chưa chứng minh nguyên nhân sâu là hypervisor, scheduler, network hay storage.

`historical_capacity.txt` có sysstat 10 phút, mẫu 15:50:01: CPU idle 78,49%,
iowait 0,13%, sda await 0,29 ms, util 0,93%. Mẫu này **trước** timestamp timeout;
không đủ độ phân giải để loại trừ stall vài giây sau đó. Kernel journal khoảng
15:40–16:00 không có entry. Không kết luận cần tăng CPU/RAM từ những dữ liệu này.

`cluster.txt` là snapshot mới: 6 node Ready, 29 volume healthy. Snapshot hồi phục
không làm run C2 bị reject trở thành hợp lệ. `traffic-gate.json` lưu kiểm tra
20 request/target: 10 microservice và 3 ingress route đều pass; không phải load
benchmark hoặc kiểm tra toàn bộ business flow.

## Observer ngầm mới

- Unit trên `.237/.239/.238`: `sentinel-pulse-infra-r10c2-20261002.service`.
- Start: **02/10 03:24:00 UTC = 10:24 ICT**; duration 21.600 giây (6 giờ).
- Dự kiến hoàn tất **16:24 ICT 02/10**; thêm ít phút để xuất journal/checksum.
- Source riêng: `/home/dat/sentinel-pulse-infra-diag-20261002/`; không sửa worktree formal.
- Output mỗi node: `/var/lib/sentinel-pulse-diagnostics/r10-c2-stall-20261002/`.
- Sysstat mỗi giây: CPU, memory, queue, paging, swap, I/O, NIC và TCP counters.
- `clock.jsonl`: realtime/monotonic/boottime, PSI, read error, interval chậm;
  không tạo mẫu catch-up giả. `observer_late` chỉ là observer bị trễ, không tự
  chứng minh toàn node stall. Clock offset flag cũng không tự xác định nguyên nhân.
- Khi kết thúc: kernel/runtime journal và `SHA256SUMS`. MemoryMax 256 MiB;
  RuntimeMaxSec 22.200; chỉ ghi telemetry, không restart hay chỉnh workload.
- SHA-256 script: `bbfed3d57bed4c9386d33f75093983972ac44ec6b46dbb1174c676d5c3d22402`.
- SHA-256 probe: `b6cc1f986bc31c57a34dd8f7c06718eec15e7eae00975d155298b96125839df1`.

Launch và mẫu đầu lưu trong `observer_launch_*.txt`, `observer_sample_*.txt`.
Không suy ra sáu giờ pass từ các mẫu đầu. Formal detector/experiment chưa được
khởi động lại; control collectors và loadgen AIMS tiếp tục chạy.

Regression: 9 test observer pass trên host và VM; Pulse subset trên VM bằng
`/home/dat/ml-venv/bin/python -m pytest -q tests/test_sentinel_pulse*.py`
đạt **311 passed, 9 subtests passed trong 29,03 giây**. Lần thử bằng venv khác
thiếu pytest bị import error, không phải pass; sau đó chọn đúng venv hiện có,
không cài/sửa dependencies của candidate đã freeze.

Smoke observer 60 giây trên worker1 hoàn tất lúc 03:25:35 UTC, exit 0,
60 clock sample, 0 late sample/clock offset change, max interval 1,0021 giây.
Kernel/runtime journal export đều exit 0; checksum 21/21 mục đạt.
`smoke_receipt.txt` là output kiểm tra terminal. Smoke này xác nhận cơ chế
ghi/finalize, không xác nhận hạ tầng ổn định sáu giờ.

## Kiểm tra sau khi hoàn tất

Trên từng worker:

```bash
systemctl show sentinel-pulse-infra-r10c2-20261002.service \
  -p ActiveState -p Result -p ExecMainStatus
sudo cat /var/lib/sentinel-pulse-diagnostics/r10-c2-stall-20261002/FINAL.txt
sudo tail -n 1 /var/lib/sentinel-pulse-diagnostics/r10-c2-stall-20261002/clock.jsonl
sudo sh -c 'cd /var/lib/sentinel-pulse-diagnostics/r10-c2-stall-20261002 && sha256sum -c SHA256SUMS'
```

Đối chiếu late sample với sar/journal và Longhorn engine log cùng timestamp.
Nếu không tái hiện, kết luận đúng là chưa quan sát lại lỗi trong exposure này;
không tuyên bố đã sửa xong. Không tăng timeout hoặc nới telemetry gate để đạt pass.
