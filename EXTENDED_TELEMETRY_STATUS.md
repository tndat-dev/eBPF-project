# Sentinel Pulse — collector bổ sung seccomp và job quan sát

Trạng thái SSH ngày **08/10/2026, khoảng 10:15 ICT**. Đây là nhánh thu dữ liệu
để sửa điểm mù telemetry, **chưa phải model đạt precision/recall 95%**.
Không sửa kết quả baseline đã chốt.

## Collector đã triển khai và kiểm chứng

Collector riêng kết hợp `raw_tp/sys_enter` với `fexit/__seccomp_filter`:
syscall đi vào kernel được đếm qua tracepoint; lời gọi bị skip/emulation,
return −1 và không phải TRACE recheck, được đếm bổ sung qua fexit. Cả hai đi
vào cùng bộ counters/bins/transitions của collector mới. Chỉ áp dụng cho
allow-list của resolver, không thay seccomp policy của AIMS.

Đã build và chạy **collector tích hợp thực tế** trên ba worker, kernel
`6.8.0-138-generic`, native x86-64. Proof chỉ theo dõi cgroup của unit thử;
child tự cài ERRNO/EPERM filter, không tiêm vào production workload.

| Worker | `setns` bị chặn | `seccomp` bị chặn | Tổng skip collector | `mprotect` collector |
|---|---:|---:|---:|---:|
| 10.1.16.237 | 20 | 20 | 40 | 47 |
| 10.1.16.238 | 20 | 20 | 40 | 47 |
| 10.1.16.239 | 20 | 20 | 40 | 47 |

Fixture thực hiện 40 `mprotect` thành công; 7 lời gọi bổ sung thuộc phần
thực thi còn lại trong cùng cgroup, không tính là attack. Ba proof đều
`valid=true`, exit 0. [Receipt, snapshots và SHA-256](validation-evidence/pulse-improvement-20261008/extended-integrated-proof.json).
Không cộng những lời gọi này vào TP của attack matrix.

Proof đầu lỗi Git ownership: root đọc checkout của `dat` bị Git từ chối
**trước khi collector được launch**. Đã sửa bằng Git safe-directory scoped
đúng checkout, không thêm wildcard global exception. Log unit
`pulse-extended-proof-c1-20261008.service` và thư mục proof đầu được giữ;
proof thành công nằm riêng tại `proof-r2`.

Đã kiểm chứng ERRNO/EPERM fixture, không tuyên bố mọi seccomp action đều
được đếm đầy đủ: KILL không nhất thiết quay lại fexit; skip/emulation không
luôn là denial; TRACE recheck được loại để tránh đếm đôi. Đây chưa phải kết
quả cross-kernel/cross-ABI hoặc RCA provenance cho từng syscall.

## Job đang chạy ngầm

Trên cả ba worker:

- Unit: `sentinel-pulse-extended-collection.service`, **enabled** khi boot.
- Source pinned: `82289f07f867824699b4571b781975de4ceb926d`, checkout
  `/home/dat/eBPF-project-extended-observation-c1-20261008`.
- Build: `/home/dat/pulse-extended-telemetry-c1/build`; proof:
  `/home/dat/pulse-extended-telemetry-c1/proof-r2`.
- Output: `/var/lib/sentinel-pulse-extended-c1-20261008`.
- Snapshot **500 ms**, mục tiêu **7.200 giây quan sát boundary/node**.
  Bắt đầu khoảng 10:12 ICT; dự kiến khoảng **12:15 ICT** nếu không gián đoạn.
- CPU quota 150%, RAM cap 1 GiB, nice 15. Không phụ thuộc SSH/laptop.

| Worker | Giây boundary | Feature rows | Đủ điều kiện review normal | Lỗi parse/integrity | Segment | RAM unit lúc kiểm tra |
|---|---:|---:|---:|---:|---:|---:|
| .237 | 191,22 | 7.855 | 7.192 | 0 | 1 | ~66 MiB |
| .238 | 191,56 | 9.282 | 8.261 | 0 | 1 | ~71 MiB |
| .239 | 177,41 | 6.963 | 6.341 | 0 | 2 | ~38 MiB |

Tổng **24.100 feature rows**, **21.794** đủ điều kiện review về cadence,
history/integrity; union có **21 workload/container key**. Đây không phải
21 workload đã đủ 2 giờ exposure, và điều kiện review **không phải nhãn
normal đã adjudication**. [Snapshot thực](validation-evidence/pulse-improvement-20261008/extended-collection-restart-proof.json).

Đã thấy 3 seccomp skip ở Kafka trên mỗi worker trong
[snapshot đầu](validation-evidence/pulse-improvement-20261008/extended-collection-inspection.json).
Chưa điều tra nhãn từng lời gọi; **không gọi chúng là attack hoặc false
positive**. Skip cũng có thể xuất hiện trong vận hành bình thường.

Unit dùng `Type=oneshot` với thời hạn không giới hạn nên đang thu sẽ hiển thị
`ActiveState=activating`, `SubState=start`, MainPID khác 0. Khi hoàn thành
thành công chuyển `active/exited`. Kiểm tra STATUS và feature file tiến triển;
không suy từ chữ “activating” rằng startup bị treo.

## Contract riêng — không đưa vào model frozen

Raw: `cgroup_snapshot_extended`, contract
`pulse-entered-plus-seccomp-skip-v1`. Feature:
`sentinel-pulse-extended-feature-v1`, vẫn **249 chiều**, nhưng slot cũ
`seccomp_denied` đổi nghĩa/tên thành `seccomp_skipped_or_emulated`.
Tracked counters và hash bins cũng bao gồm skip được quan sát qua hook mới.
Đây không phải tổng số syscall thất bại: tracepoint không thu return của
mọi syscall, và skip/emulation không luôn là denial.

Luồng đã chạy: cgroup identity → hai hook kernel → snapshot 500 ms → số lần
gọi giữa hai lần đọc → 249 feature/metadata → JSONL. Rolling mean/std dùng
**10 window có hoạt động liền kề**; gap, counter reset, đổi revision hoặc idle
boundary reset history. Warm-up được ghi nhưng chưa đủ điều kiện review normal.

Schema/checksum mới ngăn sử dụng nhầm với model cũ. Collector nền 1 s và
manifest frozen trên ba worker giữ nguyên; manifest SHA-256:
`6ddf7cf9b03cb783b82c23272f7046bafa7ab1412b0545b60a2821d1f441cc21`.
**Job này không load model, không phát alert, không train hoặc tự promotion.**
Không có alert trong job quan sát không phải FPR=0 hay precision=100%.

## Recovery đã thử — không reset campaign

Đã SIGTERM **chỉ MainPID observer .239**. Service lưu checkpoint, đóng/seal
segment cũ và tự restart sau 15 s. Kiểm tra sau đó:

- `NRestarts=1`, PID mới, tiếp tục segment `s0002`.
- START SHA-256 giữ nguyên:
  `22712de7f8a84e959fc4ed7e9c7b38a069997ae51bbfd88b9fbbdbf321c50468`.
- Thời gian/row tích lũy không về 0; raw segment đầu vẫn tồn tại,
  SHA-256 rehash từ VM đúng terminal của segment.
- Collector nền và resolver cả ba worker giữ MainPID như snapshot trước.

Đây là kiểm chứng process restart; **chưa chủ động reboot VM**. Boot enable
và checkpoint replay đã triển khai, test local kiểm tra resume/binding.
Nếu reboot đổi kernel hoặc source/artifact/proof lệch thì block để tránh
dùng sai ABI; không coi đây là chất lượng model không đạt.

Loader lỗi/mất dữ liệu 30 s thì đóng segment, thử segment mới; resolver chưa
sẵn sàng, cadence gap và record lỗi được ghi observations/raw, không reset
campaign hoặc coi những khoảng đó là normal. Checkpoint mỗi ~5 s: mất điện
có thể mất phần kế toán checkpoint cuối, raw đã ghi vẫn giữ; resume không
cộng lại dữ liệu đó để tránh double-count. Downtime không cộng vào giờ đã thu.

Ngân sách output **4 GiB/node**; đầy budget thì giữ dữ liệu và kết thúc với
`completed_with_capacity_limit`, không xóa evidence. Root còn dưới **2 GiB**
sẽ chờ hồi phục, không ghi tiếp làm đầy node. Không giữ trống 64 GiB.
Khi kiểm tra, worker còn khoảng **161 / 113 / 95 GiB**. Không cam kết đủ 2 giờ
nếu budget/hạ tầng không cho phép.

## Hạ tầng và bước tiếp theo

[Snapshot cụm](validation-evidence/pulse-improvement-20261008/extended-cluster-health.json):
6/6 node Ready, không DiskPressure/MemoryPressure, Kubernetes `v1.34.10`;
**24 vCPU/node, khoảng 126 GiB RAM OS báo**. `production` có **66/66 pod Ready**
tại snapshot. Đây không phải bằng chứng ổn định nhiều ngày hoặc A/B overhead.

Sau collection: kiểm tra completeness/loss và traffic regimes; phân tích
skip trong normal; đăng ký baseline/calibration mới theo contract mới.
Đóng băng model + policy trước normal/attack độc lập mới. Không dùng 475
interval đã xem để chỉnh threshold rồi gọi là blind validation.

Model baseline vẫn **recall 35,26% có điều kiện**, p95 **1,538 s trên hit**
từ kernel exec-entry. Collector bổ sung là bước sửa nguyên nhân, chưa thay
thế phép đo precision/recall/kernel-to-alert của candidate mới.

Lệnh kiểm tra trên từng worker:

```bash
sudo systemctl show sentinel-pulse-extended-collection.service \
  -p ActiveState -p SubState -p MainPID -p NRestarts -p UnitFileState
sudo python3 -m json.tool /var/lib/sentinel-pulse-extended-c1-20261008/STATUS.json
sudo journalctl -u sentinel-pulse-extended-collection.service -n 30 --no-pager
```

Code: [BPF](sentinel_pulse/ebpf/pulse_counter.bpf.c),
[feature contract](sentinel_pulse/extended_capture.py),
[job checkpoint](sentinel_pulse/extended_collection.py),
[installer](sentinel_pulse/install_extended_collection.py),
[unit](sentinel_pulse/systemd/sentinel-pulse-extended-collection.service).
