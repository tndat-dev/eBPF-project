# Sentinel Pulse: ánh xạ chính xác 249 feature

Đối chiếu code ngày 02/10/2026. Đây là schema của **một cửa sổ**, không phải
249 event, 249 syscall khác nhau hoặc 249 rule. Không sửa schema/model đã freeze.

## 1. Định nghĩa nằm ở đâu?

- `sentinel_pulse/features.py`: `TRACKED_SYSCALLS`, `SENSITIVE_IDS`,
  `PulseFeatureBuilder.columns` và `ingest()` là nguồn định nghĩa chính.
- `sentinel_pulse/ebpf/pulse_counter.bpf.c`: 29 counter tường minh, 64 syscall
  bins và 64 transition bins; hash trong kernel phải khớp Python.
- `sentinel_pulse/capture.py`: tạo feature từ delta snapshot và chọn số cửa sổ
  rolling (`--rolling-windows`, mặc định 5).
- `sentinel_pulse/encoding.py`: `schema_record()` lưu danh sách tên cột và
  SHA-256 schema; `decode_vector()` giải mã vector compact trong log.
- `sentinel_pulse/model.py`: ghép 3 vector trước + vector hiện tại cho ExtraTrees.
- `tests/test_sentinel_pulse_features.py`: kiểm thử phép tính và layout 249 cột.

Trong JSONL compact, bản ghi `sentinel-pulse-feature-schema-v1` có `columns`,
`vector_dim` và `feature_schema_sha256`. Bản ghi feature có `vector_f32_zlib_b64`
thay vì in 249 số thập phân; giải mã thành 249 giá trị float32 theo thứ tự cột.
Metadata như pod/node/container, timestamp, `exact_counts`, `exact_total`
không được cộng thêm vào 249 chiều này.

## 2. Layout: index bắt đầu từ 0

Gọi `c_s` là delta counter syscall s trong cửa sổ, `T` là tổng syscall,
`D = max(T, 1)`, `dt = window_end - window_start`, `r_s = c_s / dt`.
`log1p(x) = ln(1 + x)`, không phải log cơ số 10.

| Index | Tên cột | Số chiều | Giá trị |
|---|---|---:|---|
| 0–28 | `log_count:<syscall>` | 29 | `log1p(c_s)` |
| 29–57 | `ratio:<syscall>` | 29 | `c_s / D` |
| 58 | `log_count:other` | 1 | `log1p(max(0, T - sum(c_tracked)))` |
| 59 | `ratio:other` | 1 | `other / D` |
| 60 | `log_total` | 1 | `log1p(T)` |
| 61 | `sensitive_ratio` | 1 | Tổng count nhóm sensitive / D |
| 62 | `seccomp_denied` | 1 | Delta counter denied, không log/ratio |
| 63–126 | `syscall_bin:0` … `syscall_bin:63` | 64 | Count bin / D |
| 127–190 | `transition_bin:0` … `transition_bin:63` | 64 | Count bin / tổng transition; không transition thì 0 |
| 191–219 | `rolling_mean:<syscall>` | 29 | `log1p(mean(r_s trước đó))` |
| 220–248 | `rolling_std:<syscall>` | 29 | `log1p(std(r_s trước đó, ddof=0))` |
| | **Tổng** | **249** | `29 + 29 + 5 + 64 + 64 + 29 + 29` |

## 3. Toàn bộ 29 syscall theo thứ tự cột

Với offset `i` bên dưới, bốn index tương ứng là
`log_count=i`, `ratio=29+i`, `rolling_mean=191+i`, `rolling_std=220+i`.
Syscall ID là Linux **x86_64**, không được dùng nguyên mapping này cho ARM64.

| i | Syscall ID | Tên |
|---:|---:|---|
| 0 | 0 | read |
| 1 | 1 | write |
| 2 | 2 | open |
| 3 | 3 | close |
| 4 | 9 | mmap |
| 5 | 10 | mprotect |
| 6 | 41 | socket |
| 7 | 42 | connect |
| 8 | 43 | accept |
| 9 | 44 | sendto |
| 10 | 45 | recvfrom |
| 11 | 56 | clone |
| 12 | 59 | execve |
| 13 | 90 | chmod |
| 14 | 101 | ptrace |
| 15 | 105 | setuid |
| 16 | 106 | setgid |
| 17 | 126 | capset |
| 18 | 155 | pivot_root |
| 19 | 165 | mount |
| 20 | 257 | openat |
| 21 | 272 | unshare |
| 22 | 288 | accept4 |
| 23 | 299 | recvmmsg |
| 24 | 307 | sendmmsg |
| 25 | 308 | setns |
| 26 | 317 | seccomp |
| 27 | 322 | execveat |
| 28 | 435 | clone3 |

Sensitive gồm `mprotect, execve, ptrace, setuid, setgid, capset, pivot_root,
mount, unshare, setns, seccomp, execveat`. `connect` có feature riêng nhưng
**không** nằm trong phép tính `sensitive_ratio` này; semantic policy có nhóm riêng.

## 4. Hai lớp lịch sử không giống nhau

Rolling statistics mặc định dùng **tối đa 5 cửa sổ trước**, chưa đưa cửa sổ hiện
tại vào history khi tính. Nếu chưa có history, builder dùng rate hiện tại làm
fallback mean và std=0. History ngắn dùng số cửa sổ thực có, không zero-padding.
Với cadence 500 ms, 5 cửa sổ liên tục tương ứng khoảng 2,5 giây; rate vẫn là
syscall/giây, không phải count/500 ms. Builder được phép cấu hình rolling khác;
kiểm tra capture command/env của run để biết giá trị thực, không suy ra từ
`history_windows` trong model manifest.

**Unit experiment 500 ms hiện tại truyền `--rolling-windows 10`**, không dùng
default 5. Như vậy rolling bao phủ tối đa khoảng **5 giây** trước đó, nhưng vẫn
chỉ có 29 mean + 29 std, không làm tăng số chiều. Định nghĩa nằm trong
`sentinel_pulse/systemd/sentinel-pulse-collector-500ms-experiment.service`.

ExtraTrees có `history=3`: flatten `[x(t-3), x(t-2), x(t-1), x(t)]`, mỗi x có
249 chiều. Do đó đầu vào estimator có **996 chiều**, còn mỗi dòng feature log
vẫn có **249 chiều**. Đây là context tabular theo thời gian, không phải LSTM.

## 5. Ví dụ minh họa

Cửa sổ 0,5 giây: `read=100`, `write=50`, `connect=2`, không có syscall khác:

```text
exact_total = 152
vector[0]  = log_count:read   = ln(101) ≈ 4.615121
vector[29] = ratio:read       = 100/152 ≈ 0.657895
vector[7]  = log_count:connect= ln(3)   ≈ 1.098612
vector[36] = ratio:connect    = 2/152   ≈ 0.013158
vector[60] = log_total        = ln(153) ≈ 5.030438
read_rate  = 100 / 0.5        = 200 syscall/giây
```

Nếu 5 read-rate trước đều bằng 200/s: `rolling_mean:read = ln(201)`,
`rolling_std:read = 0`. Nếu tải tăng, count/total và rolling có thể đổi dù ratio
không đổi; do đó có ratio **không bảo đảm** tránh false alert ở giờ cao điểm.
Normal data và evaluation vẫn cần bao phủ high-load, burst và recovery.


{
  "schema": "sentinel-pulse-feature-v1",
  "node_name": "k8s-worker1.local",
  "pod_name": "aims-rabbitmq-server-2",
  "container_name": "rabbitmq",
  "cgroup_id": 3112263,
  "workload_key": "production/aims-rabbitmq-server:rabbitmq",

  "window_start": 1790914445.2335382,
  "window_end": 1790914445.7384043,

  "exact_total": 71,
  "exact_counts": {
    "read": 0,
    "write": 0,
    "recvfrom": 10,
    "connect": 0,
    "execve": 0,
    "ptrace": 0,
    "other": 61
  },

  "vector_dim": 249
}
