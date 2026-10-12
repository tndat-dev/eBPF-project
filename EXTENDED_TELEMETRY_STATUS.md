# Sentinel Pulse — collector bổ sung seccomp và job quan sát

Trạng thái SSH ngày **12/10/2026, 10:22 ICT**. Đây là nhánh thu dữ liệu
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

## Capture extended v1 và audit đã hoàn tất

Trên cả ba worker:

- Unit: `sentinel-pulse-extended-collection.service`, **enabled** khi boot.
- Source pinned: `82289f07f867824699b4571b781975de4ceb926d`, checkout
  `/home/dat/eBPF-project-extended-observation-c1-20261008`.
- Build: `/home/dat/pulse-extended-telemetry-c1/build`; proof:
  `/home/dat/pulse-extended-telemetry-c1/proof-r2`.
- Output: `/var/lib/sentinel-pulse-extended-c1-20261008`.
- Snapshot **500 ms**, đã hoàn thành **7.200 giây quan sát boundary/node** ngày
  08/10. Kết quả bên dưới được xác minh lại trực tiếp qua SSH ngày 12/10.
- CPU quota 150%, RAM cap 1 GiB, nice 15. Không phụ thuộc SSH/laptop.

| Worker | Giây boundary | Feature rows | Đủ điều kiện review | Lỗi capture | Audit replay | Mismatch | Cadence gap |
|---|---:|---:|---:|---:|---|---:|---:|
| .237 | 7.200,28 | 295.726 | 277.941 | 0 | 295.726/295.726 | 0 | 0 |
| .238 | 7.200,34 | 349.486 | 319.979 | 0 | 349.486/349.486 | 0 | 0 |
| .239 | 7.200,31 | 292.051 | 281.866 | 0 | 292.051/292.051 | 0 | 0 |

Tổng **937.263 feature rows**, **879.786** đủ điều kiện review kỹ thuật; 21
workload/container key xuất hiện trên tập ba worker. Điều kiện review không
phải nhãn normal đã adjudication. Audit phát lại đúng vector đã lưu, không
có cadence gap hay mismatch. Riêng `.239` có 5 snapshot cuối chưa đóng frame;
giữ trong raw nhưng không nhận thành feature/exposure. [Evidence và các seal SHA-256](validation-evidence/pulse-improvement-20261012/extended-reference-status.json).

Capture ghi 720 seccomp-skip ở Kafka mỗi worker; `.238` còn ghi 515 ở topic
operator và 175 ở user operator. Đây là số telemetry của hook, chưa adjudicate
nguyên nhân từng lời gọi; **không coi chúng tự động là attack hoặc false
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

## Candidate tham chiếu và job idle-aware hiện hành

[SSH snapshot 12/10](validation-evidence/pulse-improvement-20261012/extended-reference-status.json):
6/6 node Ready, Kubernetes `v1.34.10`. Reference fit v1 hoàn thành trên 21 key:
**18 artifact fit**, 3 key không đủ conformal calibration tại alpha 0,001
(frontend web 400, MinIO 827, sidecar 390; cần tối thiểu 999). Holdout có
126.599 context chưa adjudicate, trong đó 196 raw reference flags và 128 tree
flags. Đây chỉ là tỷ lệ cờ trên quan sát chưa gán nhãn, **không phải FPR**;
precision, recall, confusion matrix và kernel-to-alert vẫn `null`. Model chưa
được chấp nhận bởi serving manifest và không tự promotion.

Đo riêng 2.304 lần `predict_contexts` đơn (128 × 18 workload): pooled p50/p95/p99
lần lượt **19,91/26,94/31,92 ms**; workload xấu nhất p95 **32,23 ms**, p99
**35,89 ms**. Đo này bỏ qua collector, feature extraction, queue, policy và
delivery; **không đại diện latency kernel-to-alert**. Candidate còn thiếu nhãn
độc lập và phép thử attack mới.

Hiện đang chạy capture v2 riêng có giữ verified idle windows, không sửa hoặc
ghi đè v1: 500 ms, mục tiêu 7.200 boundary-second/worker, contract
`pulse-entered-plus-seccomp-skip-idle-v2`. Tại 10:22 ICT, ba worker đã có xấp
xỉ 253 giây mỗi node, 97.539 feature rows, 95.589 review-eligible rows, 0 lỗi.
Unit collector enabled; audit worker đã đăng ký và đang chờ capture; master
reference service chờ đủ audit. Khi xong sẽ audit rồi fit candidate mới; không
đưa nhãn normal hay promotion tự động vào pipeline.

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
