# Ví dụ log pod thật và đầy đủ 249 feature Sentinel Pulse

## 1. Nguồn dữ liệu

Dữ liệu được lấy **trực tiếp qua SSH**, không phải số giả lập:

- Worker: `dat@10.1.16.237` — `k8s-worker1.local`.
- Pod: `aims-rabbitmq-server-2`, container `rabbitmq`.
- Run: `sentinel-pulse-operational-r10-c3-20261002T040300Z`.
- Lúc lấy dữ liệu: **2026-10-02 11:18:43.425 ICT**.
- Cửa sổ: **2026-10-02 11:18:42.269 ICT → 2026-10-02 11:18:42.776 ICT**.
- Độ dài thực: **506.687164 ms**.
- File trên worker:

```text
/var/lib/sentinel-pulse-500ms/runs/sentinel-pulse-operational-r10-c3-20261002T040300Z/features.jsonl
```

Đây là **syscall feature telemetry của Pulse**, không phải application log
`kubectl logs`, Tetragon event chi tiết hoặc alert của model. Mỗi dòng feature
ứng với một container/cgroup trong một cửa sổ; nhiều replica có các dòng riêng.

Mẫu này mới hơn mẫu lúc 11:14:05 trong hội thoại: hiện `read=2`, `write=1`,
`recvfrom=10`, `other=68`, tổng 81. Không gán lại giá trị của cửa sổ cũ vào
cửa sổ mới.

## 2. Bản ghi thật đầy đủ

Chỉ format lại JSON để đọc; không bỏ counter, metadata hoặc vector nén:

```json
{
  "schema": "sentinel-pulse-feature-v1",
  "cgroup_id": 3112263,
  "workload_key": "production/aims-rabbitmq-server:rabbitmq",
  "window_start": 1790914722.2696364,
  "window_end": 1790914722.7763236,
  "exact_counts": {
    "read": 2,
    "write": 1,
    "open": 0,
    "close": 0,
    "mmap": 0,
    "mprotect": 0,
    "socket": 0,
    "connect": 0,
    "accept": 0,
    "sendto": 0,
    "recvfrom": 10,
    "clone": 0,
    "execve": 0,
    "chmod": 0,
    "ptrace": 0,
    "setuid": 0,
    "setgid": 0,
    "capset": 0,
    "pivot_root": 0,
    "mount": 0,
    "openat": 0,
    "unshare": 0,
    "accept4": 0,
    "recvmmsg": 0,
    "sendmmsg": 0,
    "setns": 0,
    "seccomp": 0,
    "execveat": 0,
    "clone3": 0,
    "other": 68
  },
  "exact_total": 81,
  "feature_schema_sha256": "879e33f8c33774c50d848524b78c0fa2398b9855971982e5a41a12f9259f5ae2",
  "vector_dim": 249,
  "vector_f32_zlib_b64": "eAELmd9jL1FkaM9AAMiVSzoQUEK0dIfrKZsOVy8bQhpeXftjS0gNsfJna9sdHrwMs7/B3OsA0wNyB4xNbRrk9olGBXa4zCXkf0LyIHMnGn2Am09OWOGyg5hwUdsijhI3pNqPbPerazUoZqGHGb5wRFcL4oPMQ9Zzlp8bHE7o9szzbXC4cz3UAaTHwGYPPA80FurbH9goYu/4d6UdCFekuYPVgNThAztru+Fm4FKnf6fOwUQ/xAEkz7TkM1z90w/r7Z2tZtt/WeEOxrbMh+ByuMwCiUcbTiaoDgAXC1F+",
  "pod_name": "aims-rabbitmq-server-2",
  "pod_uid": "cf6db097-3801-4a50-939d-1ada52624ef9",
  "node_name": "k8s-worker1.local",
  "role": "rabbitmq",
  "container_name": "rabbitmq",
  "workload_revision": "aims-rabbitmq-server-6579bff56b",
  "emitted_at": 1790914722.8064566,
  "collector_stats": {
    "task_state_update_fail": 0,
    "snapshot_consistency_retry_exhausted": 0,
    "target_snapshot_gap": 0
  },
  "snapshot_read_seconds": 0.00454092,
  "collector_snapshot_interval_seconds": 0.5066871643066406,
  "collector_telemetry_availability": {
    "schema": "sentinel-pulse-telemetry-availability-v1",
    "observed_snapshots": 1257,
    "estimated_missing_snapshots": 0,
    "availability": 1,
    "maximum_snapshot_interval_seconds": 0.5204977989196777,
    "minimum_snapshot_interval_seconds": 0.5036835670471191,
    "short_interval_events": 0,
    "cadence_violation_events": 0
  }
}
```

`vector_f32_zlib_b64` chứa **249 số float32** sau giải mã
base64 → zlib → float32 little-endian. `exact_counts` là counter nguyên gốc
trong window, không phải 249 feature đã biến đổi. Trường `exact_total=81`
bằng 2 read + 1 write + 10 recvfrom + 68 other.

## 3. Giải thích các giá trị trong chính mẫu này

| Feature | Giá trị đã giải mã | Phép tính |
|---|---:|---|
| `log_count:read` | 1.0986123085021973 | ln(1 + 2) |
| `log_count:write` | 0.6931471824645996 | ln(1 + 1) |
| `log_count:recvfrom` | 2.397895336151123 | ln(1 + 10) |
| `ratio:read` | 0.02469135820865631 | 2 / 81 |
| `ratio:recvfrom` | 0.12345679104328156 | 10 / 81 |
| `log_count:other` | 4.234106540679932 | ln(1 + 68) |
| `ratio:other` | 0.8395061492919922 | 68 / 81 |
| `log_total` | 4.406719207763672 | ln(1 + 81) |
| `sensitive_ratio` | 0 | Count nhóm sensitive / 81 |
| `rolling_mean:read` | 4.009474754333496 | log1p(mean read-rate của history) |
| `rolling_std:read` | 3.9821889400482178 | log1p(std read-rate của history) |

Sai số rất nhỏ so với tính bằng số thực là do lưu vector **float32**.
Rolling mean/std đã được log1p, không phải trực tiếp số syscall/giây. Collector
experiment 500 ms dùng `--rolling-windows 10`: tối đa khoảng 5 giây trước đó.
Không đưa window hiện tại vào history khi tính; khi chưa có history, builder
dùng current rate làm fallback. Model history=3 là lớp context khác.

### Vì sao log trước có read=0?

Trong cửa sổ cũ khoảng 505 ms, collector không ghi nhận syscall `read()` của
container. Nhưng `recvfrom()` là syscall riêng và đã được ghi nhận 10 lần.
`read=0` không có nghĩa không có network I/O, pod không hoạt động, hoặc mọi
window đều có read=0. Mẫu mới này ghi nhận read=2.

`other` là tổng các syscall ngoài 29 syscall có cột tường minh, không phải số
event bị mất. Những syscall đó vẫn góp vào tổng và histogram syscall bins.
Không thể biết từng syscall cụ thể của `other` chỉ từ counter tổng này.

`seccomp_denied=0` là slot có trong schema nhưng kernel collector hiện tại
không cung cấp hook denial riêng; không coi 0 là bằng chứng không có denial.
`connect=0` chỉ nói không có syscall connect mới trong window, không chứng
minh container không có socket kết nối sẵn.

## 4. Toàn bộ 249 feature của chính bản ghi trên

**Không lược bỏ chiều bằng 0.** Index 0–248 đúng thứ tự vector/model schema.
Tên cột được kiểm tra SHA-256 trước khi gán với giá trị:

```text
879e33f8c33774c50d848524b78c0fa2398b9855971982e5a41a12f9259f5ae2
```

| Index | Tên feature | Giá trị float32 đã giải mã |
|---:|---|---:|
| 0 | `log_count:read` | 1.0986123085021973 |
| 1 | `log_count:write` | 0.6931471824645996 |
| 2 | `log_count:open` | 0 |
| 3 | `log_count:close` | 0 |
| 4 | `log_count:mmap` | 0 |
| 5 | `log_count:mprotect` | 0 |
| 6 | `log_count:socket` | 0 |
| 7 | `log_count:connect` | 0 |
| 8 | `log_count:accept` | 0 |
| 9 | `log_count:sendto` | 0 |
| 10 | `log_count:recvfrom` | 2.397895336151123 |
| 11 | `log_count:clone` | 0 |
| 12 | `log_count:execve` | 0 |
| 13 | `log_count:chmod` | 0 |
| 14 | `log_count:ptrace` | 0 |
| 15 | `log_count:setuid` | 0 |
| 16 | `log_count:setgid` | 0 |
| 17 | `log_count:capset` | 0 |
| 18 | `log_count:pivot_root` | 0 |
| 19 | `log_count:mount` | 0 |
| 20 | `log_count:openat` | 0 |
| 21 | `log_count:unshare` | 0 |
| 22 | `log_count:accept4` | 0 |
| 23 | `log_count:recvmmsg` | 0 |
| 24 | `log_count:sendmmsg` | 0 |
| 25 | `log_count:setns` | 0 |
| 26 | `log_count:seccomp` | 0 |
| 27 | `log_count:execveat` | 0 |
| 28 | `log_count:clone3` | 0 |
| 29 | `ratio:read` | 0.02469135820865631 |
| 30 | `ratio:write` | 0.012345679104328156 |
| 31 | `ratio:open` | 0 |
| 32 | `ratio:close` | 0 |
| 33 | `ratio:mmap` | 0 |
| 34 | `ratio:mprotect` | 0 |
| 35 | `ratio:socket` | 0 |
| 36 | `ratio:connect` | 0 |
| 37 | `ratio:accept` | 0 |
| 38 | `ratio:sendto` | 0 |
| 39 | `ratio:recvfrom` | 0.12345679104328156 |
| 40 | `ratio:clone` | 0 |
| 41 | `ratio:execve` | 0 |
| 42 | `ratio:chmod` | 0 |
| 43 | `ratio:ptrace` | 0 |
| 44 | `ratio:setuid` | 0 |
| 45 | `ratio:setgid` | 0 |
| 46 | `ratio:capset` | 0 |
| 47 | `ratio:pivot_root` | 0 |
| 48 | `ratio:mount` | 0 |
| 49 | `ratio:openat` | 0 |
| 50 | `ratio:unshare` | 0 |
| 51 | `ratio:accept4` | 0 |
| 52 | `ratio:recvmmsg` | 0 |
| 53 | `ratio:sendmmsg` | 0 |
| 54 | `ratio:setns` | 0 |
| 55 | `ratio:seccomp` | 0 |
| 56 | `ratio:execveat` | 0 |
| 57 | `ratio:clone3` | 0 |
| 58 | `log_count:other` | 4.234106540679932 |
| 59 | `ratio:other` | 0.8395061492919922 |
| 60 | `log_total` | 4.406719207763672 |
| 61 | `sensitive_ratio` | 0 |
| 62 | `seccomp_denied` | 0 |
| 63 | `syscall_bin:0` | 0.02469135820865631 |
| 64 | `syscall_bin:1` | 0 |
| 65 | `syscall_bin:2` | 0 |
| 66 | `syscall_bin:3` | 0 |
| 67 | `syscall_bin:4` | 0 |
| 68 | `syscall_bin:5` | 0 |
| 69 | `syscall_bin:6` | 0 |
| 70 | `syscall_bin:7` | 0 |
| 71 | `syscall_bin:8` | 0 |
| 72 | `syscall_bin:9` | 0 |
| 73 | `syscall_bin:10` | 0 |
| 74 | `syscall_bin:11` | 0 |
| 75 | `syscall_bin:12` | 0 |
| 76 | `syscall_bin:13` | 0 |
| 77 | `syscall_bin:14` | 0 |
| 78 | `syscall_bin:15` | 0 |
| 79 | `syscall_bin:16` | 0 |
| 80 | `syscall_bin:17` | 0 |
| 81 | `syscall_bin:18` | 0 |
| 82 | `syscall_bin:19` | 0 |
| 83 | `syscall_bin:20` | 0 |
| 84 | `syscall_bin:21` | 0 |
| 85 | `syscall_bin:22` | 0 |
| 86 | `syscall_bin:23` | 0.12345679104328156 |
| 87 | `syscall_bin:24` | 0.23456789553165436 |
| 88 | `syscall_bin:25` | 0 |
| 89 | `syscall_bin:26` | 0 |
| 90 | `syscall_bin:27` | 0 |
| 91 | `syscall_bin:28` | 0 |
| 92 | `syscall_bin:29` | 0 |
| 93 | `syscall_bin:30` | 0 |
| 94 | `syscall_bin:31` | 0.012345679104328156 |
| 95 | `syscall_bin:32` | 0 |
| 96 | `syscall_bin:33` | 0 |
| 97 | `syscall_bin:34` | 0 |
| 98 | `syscall_bin:35` | 0 |
| 99 | `syscall_bin:36` | 0 |
| 100 | `syscall_bin:37` | 0 |
| 101 | `syscall_bin:38` | 0 |
| 102 | `syscall_bin:39` | 0.012345679104328156 |
| 103 | `syscall_bin:40` | 0 |
| 104 | `syscall_bin:41` | 0 |
| 105 | `syscall_bin:42` | 0 |
| 106 | `syscall_bin:43` | 0 |
| 107 | `syscall_bin:44` | 0 |
| 108 | `syscall_bin:45` | 0 |
| 109 | `syscall_bin:46` | 0 |
| 110 | `syscall_bin:47` | 0 |
| 111 | `syscall_bin:48` | 0.4691357910633087 |
| 112 | `syscall_bin:49` | 0 |
| 113 | `syscall_bin:50` | 0 |
| 114 | `syscall_bin:51` | 0.12345679104328156 |
| 115 | `syscall_bin:52` | 0 |
| 116 | `syscall_bin:53` | 0 |
| 117 | `syscall_bin:54` | 0 |
| 118 | `syscall_bin:55` | 0 |
| 119 | `syscall_bin:56` | 0 |
| 120 | `syscall_bin:57` | 0 |
| 121 | `syscall_bin:58` | 0 |
| 122 | `syscall_bin:59` | 0 |
| 123 | `syscall_bin:60` | 0 |
| 124 | `syscall_bin:61` | 0 |
| 125 | `syscall_bin:62` | 0 |
| 126 | `syscall_bin:63` | 0 |
| 127 | `transition_bin:0` | 0.012345679104328156 |
| 128 | `transition_bin:1` | 0 |
| 129 | `transition_bin:2` | 0 |
| 130 | `transition_bin:3` | 0 |
| 131 | `transition_bin:4` | 0 |
| 132 | `transition_bin:5` | 0 |
| 133 | `transition_bin:6` | 0.02469135820865631 |
| 134 | `transition_bin:7` | 0 |
| 135 | `transition_bin:8` | 0 |
| 136 | `transition_bin:9` | 0 |
| 137 | `transition_bin:10` | 0 |
| 138 | `transition_bin:11` | 0 |
| 139 | `transition_bin:12` | 0 |
| 140 | `transition_bin:13` | 0 |
| 141 | `transition_bin:14` | 0 |
| 142 | `transition_bin:15` | 0.03703703731298447 |
| 143 | `transition_bin:16` | 0 |
| 144 | `transition_bin:17` | 0 |
| 145 | `transition_bin:18` | 0 |
| 146 | `transition_bin:19` | 0.12345679104328156 |
| 147 | `transition_bin:20` | 0 |
| 148 | `transition_bin:21` | 0 |
| 149 | `transition_bin:22` | 0 |
| 150 | `transition_bin:23` | 0 |
| 151 | `transition_bin:24` | 0 |
| 152 | `transition_bin:25` | 0 |
| 153 | `transition_bin:26` | 0 |
| 154 | `transition_bin:27` | 0 |
| 155 | `transition_bin:28` | 0 |
| 156 | `transition_bin:29` | 0 |
| 157 | `transition_bin:30` | 0 |
| 158 | `transition_bin:31` | 0.012345679104328156 |
| 159 | `transition_bin:32` | 0 |
| 160 | `transition_bin:33` | 0 |
| 161 | `transition_bin:34` | 0.06172839552164078 |
| 162 | `transition_bin:35` | 0 |
| 163 | `transition_bin:36` | 0 |
| 164 | `transition_bin:37` | 0 |
| 165 | `transition_bin:38` | 0 |
| 166 | `transition_bin:39` | 0 |
| 167 | `transition_bin:40` | 0 |
| 168 | `transition_bin:41` | 0 |
| 169 | `transition_bin:42` | 0.23456789553165436 |
| 170 | `transition_bin:43` | 0 |
| 171 | `transition_bin:44` | 0 |
| 172 | `transition_bin:45` | 0 |
| 173 | `transition_bin:46` | 0 |
| 174 | `transition_bin:47` | 0 |
| 175 | `transition_bin:48` | 0 |
| 176 | `transition_bin:49` | 0 |
| 177 | `transition_bin:50` | 0 |
| 178 | `transition_bin:51` | 0 |
| 179 | `transition_bin:52` | 0 |
| 180 | `transition_bin:53` | 0 |
| 181 | `transition_bin:54` | 0.06172839552164078 |
| 182 | `transition_bin:55` | 0.23456789553165436 |
| 183 | `transition_bin:56` | 0 |
| 184 | `transition_bin:57` | 0 |
| 185 | `transition_bin:58` | 0.1358024626970291 |
| 186 | `transition_bin:59` | 0 |
| 187 | `transition_bin:60` | 0.06172839552164078 |
| 188 | `transition_bin:61` | 0 |
| 189 | `transition_bin:62` | 0 |
| 190 | `transition_bin:63` | 0 |
| 191 | `rolling_mean:read` | 4.009474754333496 |
| 192 | `rolling_mean:write` | 3.3413000106811523 |
| 193 | `rolling_mean:open` | 0 |
| 194 | `rolling_mean:close` | 1.4705867767333984 |
| 195 | `rolling_mean:mmap` | 0 |
| 196 | `rolling_mean:mprotect` | 0 |
| 197 | `rolling_mean:socket` | 0.6853256821632385 |
| 198 | `rolling_mean:connect` | 0.5808372497558594 |
| 199 | `rolling_mean:accept` | 0.33201029896736145 |
| 200 | `rolling_mean:sendto` | 0.33201029896736145 |
| 201 | `rolling_mean:recvfrom` | 3.115629196166992 |
| 202 | `rolling_mean:clone` | 0 |
| 203 | `rolling_mean:execve` | 0 |
| 204 | `rolling_mean:chmod` | 0 |
| 205 | `rolling_mean:ptrace` | 0 |
| 206 | `rolling_mean:setuid` | 0 |
| 207 | `rolling_mean:setgid` | 0 |
| 208 | `rolling_mean:capset` | 0 |
| 209 | `rolling_mean:pivot_root` | 0 |
| 210 | `rolling_mean:mount` | 0 |
| 211 | `rolling_mean:openat` | 1.089774250984192 |
| 212 | `rolling_mean:unshare` | 0 |
| 213 | `rolling_mean:accept4` | 0 |
| 214 | `rolling_mean:recvmmsg` | 0 |
| 215 | `rolling_mean:sendmmsg` | 0 |
| 216 | `rolling_mean:setns` | 0 |
| 217 | `rolling_mean:seccomp` | 0 |
| 218 | `rolling_mean:execveat` | 0 |
| 219 | `rolling_mean:clone3` | 0 |
| 220 | `rolling_std:read` | 3.9821889400482178 |
| 221 | `rolling_std:write` | 3.3153810501098633 |
| 222 | `rolling_std:open` | 0 |
| 223 | `rolling_std:close` | 1.903442621231079 |
| 224 | `rolling_std:mmap` | 0 |
| 225 | `rolling_std:mprotect` | 0 |
| 226 | `rolling_std:socket` | 1.3745390176773071 |
| 227 | `rolling_std:connect` | 1.21271550655365 |
| 228 | `rolling_std:accept` | 0.7799217700958252 |
| 229 | `rolling_std:sendto` | 0.7799217700958252 |
| 230 | `rolling_std:recvfrom` | 1.5157238245010376 |
| 231 | `rolling_std:clone` | 0 |
| 232 | `rolling_std:execve` | 0 |
| 233 | `rolling_std:chmod` | 0 |
| 234 | `rolling_std:ptrace` | 0 |
| 235 | `rolling_std:setuid` | 0 |
| 236 | `rolling_std:setgid` | 0 |
| 237 | `rolling_std:capset` | 0 |
| 238 | `rolling_std:pivot_root` | 0 |
| 239 | `rolling_std:mount` | 0 |
| 240 | `rolling_std:openat` | 1.1499437093734741 |
| 241 | `rolling_std:unshare` | 0 |
| 242 | `rolling_std:accept4` | 0 |
| 243 | `rolling_std:recvmmsg` | 0 |
| 244 | `rolling_std:sendmmsg` | 0 |
| 245 | `rolling_std:setns` | 0 |
| 246 | `rolling_std:seccomp` | 0 |
| 247 | `rolling_std:execveat` | 0 |
| 248 | `rolling_std:clone3` | 0 |

249 là số chiều **mỗi window**. ExtraTrees history=3 ghép 3 vector trước với
vector hiện tại thành 996 chiều; bảng này không phải context 996 chiều ấy.
Hai histogram 64 bin chứa tỷ trọng có hash collision, không phải toàn bộ
chuỗi syscall/process/network payload.

## 5. Lệnh chạy trên terminal

Chạy **trên worker1 10.1.16.237**, nơi file capture nằm. Ví dụ đăng nhập từ host:

```bash
ssh dat@10.1.16.237
```

### 5.1 Xem exact counter của pod ở cửa sổ gần nhất

```bash
PULSE_CAPTURE=/var/lib/sentinel-pulse-500ms/runs/sentinel-pulse-operational-r10-c3-20261002T040300Z/features.jsonl

sudo tail -n 1000 "$PULSE_CAPTURE" \
  | jq -c 'select(
      .schema == "sentinel-pulse-feature-v1"
      and .pod_name == "aims-rabbitmq-server-2"
    )' \
  | tail -n 1 \
  | jq '{
      pod_name, container_name, workload_key,
      window_start, window_end,
      exact_total, exact_counts, vector_dim
    }'
```

Mỗi lần chạy lấy window mới, **không bảo đảm vẫn là 81 syscall**. Nếu pod bị
thay/redeploy, cập nhật pod name. Nếu không thấy dòng khớp trong tail, tăng
số dòng hoặc chọn pod thực tế; không tự tạo vector zero.

### 5.2 In đầy đủ 249 feature, có cả những chiều bằng 0

Dùng tiếp biến `PULSE_CAPTURE` ở trên:

```bash
sudo tail -n 1000 "$PULSE_CAPTURE" \
  | jq -c 'select(
      .schema == "sentinel-pulse-feature-v1"
      and .pod_name == "aims-rabbitmq-server-2"
    )' \
  | tail -n 1 \
  | PYTHONPATH=/opt/sentinel-pulse \
    /opt/sentinel-pulse/venv/bin/python -c '
import json
import sys
from sentinel_pulse.encoding import decode_vector, schema_digest
from sentinel_pulse.features import PulseFeatureBuilder

raw = sys.stdin.read().strip()
if not raw:
    raise SystemExit("Không thấy feature của pod trong tail.")

record = json.loads(raw)
vector = decode_vector(record)
columns = record.get("columns") or list(PulseFeatureBuilder().columns)

if record.get("feature_schema_sha256") != schema_digest(columns):
    raise SystemExit("Schema không khớp; không gán tên feature tùy ý.")
if len(vector) != len(columns) or len(vector) != 249:
    raise SystemExit("Số chiều không khớp schema 249.")

print("Pod:", record["pod_name"])
print("Window:", record["window_start"], "->", record["window_end"])
print("Exact counts:", json.dumps(record["exact_counts"]))
print("Feature count:", len(vector))
for index, (name, value) in enumerate(zip(columns, vector)):
    print(f"{index:03d}  {name:<30}  {float(value):.9g}")
'
```

Fallback tên cột lấy từ code chỉ được dùng khi SHA schema khớp. Không dùng
tên cột của code mới để đoán một vector có schema khác. Nếu thay schema,
phải đọc header `sentinel-pulse-feature-schema-v1` của capture tương ứng.

## 6. Code định nghĩa và giới hạn kết luận

- [features.py](sentinel_pulse/features.py): 29 syscall, thứ tự cột và phép biến đổi.
- [encoding.py](sentinel_pulse/encoding.py): encode/decode vector và schema hash.
- [capture.py](sentinel_pulse/capture.py): delta snapshot, metadata pod và log JSONL.
- [collector 500 ms](sentinel_pulse/systemd/sentinel-pulse-collector-500ms-experiment.service):
  cadence và rolling-windows=10.
- [Tài liệu 249 feature](SENTINEL_PULSE_FEATURES_249.md): mapping/công thức đầy đủ.

Một feature row không kết luận normal/anomaly. Phải đọc decision tương ứng
trong `decisions.jsonl` và policy gate; không suy ra precision, recall,
false-positive rate hoặc kernel-to-alert latency từ log ví dụ này.
