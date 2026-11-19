# Luồng code Sentinel Pulse và ví dụ thực tế

Tài liệu đi theo đúng đường dữ liệu: từ một syscall trong container tới cảnh báo trong Alertmanager, rồi tới phần
học mô hình (fit), campaign tấn công và phân tích. Mỗi bước ghi file code, file dữ liệu (đường dẫn đầy đủ, kèm máy chứa)
và một ví dụ lấy từ dữ liệu thật của lượt `pulse-live-final-1119` (chạy từ 19/11/2026 09:50 +07) hoặc của fit
`pulse-live-v7-fit-1118`. Mục 12 là quy trình chuẩn từ đầu tới cuối, kèm các lệnh cần chạy.

Quy ước máy trong lab:

| Máy | Vai trò | Ghi chú |
|---|---|---|
| `10.1.16.234` (k8s-master) | campaign, alert bridge, RCA, bộ ghi sự kiện K8s, phân tích | NFS gắn ở `/mnt/sentinel-pulse-archive` |
| `10.1.16.237` (k8s-worker1) | worker: probe + chấm điểm | |
| `10.1.16.238` (k8s-worker4) | worker | |
| `10.1.16.239` (k8s-worker3) | worker | |
| `10.1.16.233` | máy chủ NFS (`10.1.16.233:/sentinel-pulse`) | |

Đường dẫn bắt đầu bằng `sentinel_pulse/`, `scripts/`, `testbed/`, `tests/` là file trong repo
(`/home/tndat/Downloads/eBPF-project/` trên máy bạn; `/home/dat/eBPF-project/` trên `.234`). Lượt chạy không đọc repo
mà đọc bản đóng băng `/mnt/sentinel-pulse-archive/runtime-0c385d9-20261119/source/` (NFS).

---

## 0. Toàn cảnh

```
 container (pod production)
   │ syscall
   ▼
 [1] probe eBPF (kernel, mỗi worker)          sentinel_pulse/ebpf/pulse_counter.bpf.c + pulse_tokens.bpf.h
   │ map pulse_grams: (cgroup, cửa sổ 0,5 s, 4 token, dòng dõi) → số lần
   ▼
 [2] loader (user space, mỗi worker)          sentinel_pulse/ebpf/pulse_counter_loader.c
   │ mỗi 0,5 s: xả cửa sổ đã đóng → dòng JSON "token_grams" ra stdout
   ▼
 [3] worker Python (mỗi worker)               sentinel_pulse/pipeline/matched_worker.py
   │ gắn danh tính pod (cgroup_resolver) → TokenBranch.score → decision
   │ ghi tokens.jsonl, decisions.jsonl (NFS) + decisions.jsonl local
   ▼
 [4] alert bridge (.234)                      sentinel_pulse/ops/alert_bridge.py
   │ ssh tail decision local, gom đợt theo container → POST Alertmanager
   ▼
 Alertmanager  ──webhook──►  bridge ghi deliveries.jsonl, triggers.jsonl
                                   │
                                   ▼
                     [5] RCA (.234)   sentinel_pulse/rca/service.py → case (cây process + nghi phạm)

 Phía học (trước lượt):  capture normal → [6] fit (scripts/analysis/token_branch_fit.py) → MODELS.json → [3]
 Phía thử (trong lượt):  [7] campaign (sentinel_pulse/attack/preview_campaign.py) → INTERVALS.jsonl
 Phía chấm (sau lượt):   [8] phân tích (scripts/analysis/pulse_live_v4.py, ...) → validation-evidence/
```

---

## 1. Probe eBPF trong kernel

**File code**

- `sentinel_pulse/ebpf/pulse_counter.bpf.c`: hook `raw_tp/sys_enter`, hook `fexit/__seccomp_filter`, hàm chung
  `pulse_record_call`.
- `sentinel_pulse/ebpf/pulse_tokens.bpf.h`: hook `raw_tp/sys_exit` (`pulse_tok_sys_exit`), hook
  `raw_tp/sched_process_fork` (`pulse_tok_fork`), dựng token, đếm gram (`pulse_tok_emit`), map `pulse_grams`.
- `sentinel_pulse/ebpf/pulse_token_ids.h`: bố cục 32 bit của token, bảng 39 syscall có hook (`PULSE_HOOKED_ROWS`).
- `sentinel_pulse/ebpf/Makefile`: `make tokens` biên dịch ra `pulse_counter_tokens.bpf.o` và
  `pulse_counter_tokens_loader`.

**Bản build đang chạy**: trên đĩa từng worker, ví dụ worker1 (`ssh 10.1.16.237`):
`/home/dat/pulse-tokens-final-f8ccbb2/build/` (object + loader) và `/home/dat/pulse-tokens-final-f8ccbb2/proof/`
(kết quả kiểm verifier, worker từ chối chạy nếu proof không khớp kernel và SHA-256 của build).

### 1.1 Bốn hook

| Hook | Khi nào chạy | Làm gì |
|---|---|---|
| `raw_tp/sys_enter` | trước mọi syscall của node | lọc cgroup (map `pulse_cgroups`, chỉ container được theo dõi); syscall **không** có hook → phát token "chỉ tên" ngay; syscall có hook → đặt `tok_pending = 1` |
| `raw_tp/sys_exit` | sau mọi syscall | chỉ làm việc khi `tok_pending = 1`: dựng token với kết quả (errno, nhóm cỡ, thư mục đầu) rồi phát |
| `fexit/__seccomp_filter` | sau khi seccomp quyết định | syscall bị seccomp bỏ qua (kết quả −1) không bao giờ tới `sys_enter`, nên được ghi ở đây như một token "chỉ tên" |
| `raw_tp/sched_process_fork` | mỗi lần fork/clone | process con nhận dòng dõi (native/session) của cha, lịch sử token rỗng |

### 1.2 Token 32 bit (`pulse_token_ids.h`)

```
bit 31..23 : số syscall x86_64 (9 bit)
bit 22..21 : loại chi tiết  0 = chỉ tên | 1 = errno | 2 = nhóm cỡ | 3 = mở file
bit 20..0  : chi tiết       errno (bit 0..11) | ⌊log2(số byte)⌋ chặn 15 (bit 0..3)
                            | mở file: bit 20 = ghi, bit 0..19 = FNV-1a 20 bit của thư mục đầu
```

Ví dụ tính tay:

| Lời gọi | Cách tính | Token |
|---|---|---|
| `epoll_pwait` (nr 281), chỉ tên | 281 << 23 | 2357198848 |
| `epoll_ctl` (nr 233), chỉ tên | 233 << 23 | 1954545664 |
| `read` trả 300 byte | 0<<23 \| 2<<21 \| ⌊log2 300⌋=8 | 4194312 |
| `write` trả 120 byte | 1<<23 \| 2<<21 \| 6 | 12582918 |
| `read` lỗi EAGAIN (11) | 0<<23 \| 1<<21 \| 11 | 2097163 |
| `close` (nr 3) thành công | 3<<23 | 25165824 |

### 1.3 Từ token thành 4-gram (`pulse_tok_emit`)

Mỗi thread giữ 3 token gần nhất (`pulse_task_state.tok[0..2]`, map `pulse_last_syscall`). Mỗi token mới tạo **một**
4-gram = (3 token trước, token mới), cộng 1 vào map `pulse_grams` với khoá:

```
(cgroup_id, window = thời điểm_ns / 500 000 000, tok[0], tok[1], tok[2], token mới, dòng dõi)
```

rồi dịch lịch sử đi một ô. Thread mới (hoặc vừa đổi cgroup) bắt đầu với 3 ô `0xFFFFFFFF` (TOK_NONE), nên gram đầu là
`(NONE, NONE, NONE, token)`.

Map `pulse_grams` có 262.144 mục. Nếu chèn thất bại vì đầy, bộ đếm sức khoẻ `pulse_tok_stats[0]` (insert_fail) tăng;
từ vòng cải thiện D1 điều này thành một cảnh báo (mục 3.3).

**Ví dụ thật**: thread của `payment-service` trên worker1 chờ sự kiện, gọi lặp `epoll_pwait`. Các gram của nó
trong cửa sổ đầu của lượt (`window_end` 1795056468.618):

```
[1954545664, 2357198848, 2357198848, 2357198848, 1]   = (epoll_ctl, epoll_pwait, epoll_pwait) → epoll_pwait, 1 lần
[2357198848, 1954545664, 2357198848, ...]             = ...
```

Không có sự kiện đơn lẻ nào đi lên user space, chỉ có số đếm theo gram, nên chi phí thấp (đo D7 trên request thật:
p50 +10,5 ms, p95 +15,9 ms).

---

## 2. Loader: xả map mỗi 0,5 s

**File code**: `sentinel_pulse/ebpf/pulse_counter_loader.c` (hàm `drain_grams`, vòng lặp chính trong `main`).

Mỗi nhịp, loader ngủ tới ngay sau ranh giới 0,5 s của đồng hồ monotonic (+20 ms đệm), rồi:

1. làm mới allow-list cgroup từ `/run/sentinel-pulse/allowed-cgroups`;
2. in ảnh chụp bộ đếm của mô hình đếm cũ (`cgroup_snapshot_extended`, nhánh shadow);
3. `drain_grams`: đọc cả map theo lô 8.192 mục, chọn các cửa sổ **đã đóng**, sắp theo (cgroup, cửa sổ, gram), in mỗi
   (cgroup, cửa sổ) **một** dòng `token_grams`, rồi xoá các mục đó khỏi map;
4. in dòng `token_drain` (thời gian xả, `insert_fail_cumulative`);
5. in `snapshot_end` (hết một frame).

`window_end` = `(window + 1) × 0,5 s` + độ lệch giữa đồng hồ thực và monotonic (sửa D2: tính từ
`PULSE_TOK_WINDOW_NS` thay vì số cứng).

Dạng dòng loader in ra (stdout, đi thẳng vào worker, không lưu riêng):

```json
{"type":"token_grams","contract":"pulse-token-select1f-v1","cgroup_id":16090,"window":1130263,
 "window_end":1795056468.618,"events":7,
 "grams":[[1954545664,2357198848,2357198848,2357198848,1], ...],
 "session_events":0,"session":[]}
```

`grams` là cả cửa sổ (mọi dòng dõi cộng lại, cái mô hình chấm); `session` là phần đếm trên thread dòng dõi session
(`kubectl exec` và con cháu), nên native = grams − session.

---

## 3. Worker: gắn danh tính, chấm điểm, ghi decision

**File code**

- `sentinel_pulse/collector/cgroup_resolver.py`: unit riêng trên mỗi worker, mỗi 15 s dùng `crictl` và quét
  `/sys/fs/cgroup` để biết cgroup nào là container nào.
- `sentinel_pulse/pipeline/matched_worker.py`: hàm `run`, vòng frame.
- `sentinel_pulse/collector/token_capture.py`: `token_window` (kiểm và gắn danh tính), `MapOverflow` (D1).
- `sentinel_pulse/detector/token_model.py`: `TokenBranch.score`, `CountTokenLM.window_score`.

**File cấu hình và trạng thái trên mỗi worker** (ví dụ worker1, `ssh 10.1.16.237`)

- Unit: `pulse-matched-worker-pulse-live-final-1119.service`, chạy
  `python -m sentinel_pulse.pipeline.matched_worker --config /etc/sentinel-pulse/matched-worker-pulse-live-final-1119.json`
  với `PYTHONPATH=/mnt/sentinel-pulse-archive/runtime-0c385d9-20261119/source`.
- Do resolver ghi (root đọc được): `/run/sentinel-pulse/allowed-cgroups` (mỗi dòng một cgroup id, loader đọc) và
  `/run/sentinel-pulse/cgroups.json` (cgroup id → pod, container, namespace, phiên bản; worker đọc).

### 3.1 Trước khi chạy: kiểm toàn vẹn

`run()` dừng ngay nếu một trong các điều sau sai: kernel đúng bản có proof; SHA-256 của loader và object đúng; proof
hợp lệ; các file chấm của mô hình cũ trùng byte với snapshot đóng băng; SHA-256 của từng file mô hình token khớp
`MODELS.json` (trong `TokenBranch.__init__`). Nghĩa là lượt chạy không thể chạy với hệ thống khác cái đã đăng ký.

### 3.2 Mỗi frame (0,5 s)

1. Gom các dòng của loader tới `snapshot_end`.
2. Nhánh đếm cũ (shadow): ảnh chụp → vector đặc trưng → cây + support, ghi decision `candidate-raw-score-only`
   (không dùng để báo).
3. **Nhánh token (đường cảnh báo)**, với mỗi dòng `token_grams`:
   - `token_window(row, metadata)`: kiểm từng gram đúng 4 token + 1 số đếm > 0, ô trống chỉ ở đầu, tổng số đếm =
     `events`; gắn `workload_key` (`namespace/controller:container`), pod, container, phiên bản. Cgroup ngoài
     namespace `production` → bỏ.
   - `TokenBranch.score(window)`: chọn mô hình theo `workload_key`; điểm = `window_score` (mục 4.3);
     `token_alert = điểm > ngưỡng`. **Một cửa sổ vượt là đủ để báo.**
   - Ghi một decision `status: token-score` vào `decisions.jsonl` trên NFS và bản local; ghi cửa sổ vào
     `tokens.jsonl`.
4. Mỗi 30 phút đóng segment: ghi `TERMINAL.json` có SHA-256 của từng file ("niêm phong"), mở segment mới.
5. Theo dõi sức khoẻ: hai `snapshot_end` cách nhau ngoài 0,35–0,8 s → issue `cadence_gap`; loader im 30 s → issue,
   mở segment mới. Ghi vào `issues.jsonl`.

### 3.3 Map đầy thành cảnh báo (D1, `MapOverflow`)

Nếu `insert_fail_cumulative` trong `token_drain` tăng so với frame trước: mọi cửa sổ của frame được đánh dấu
`token_incomplete`, và cửa sổ có nhiều gram phân biệt nhất (của cgroup gây đầy map) được báo với
`token_alert_reason: gram_map_overflow`. Thử trên worker1 (`scripts/map_overflow_test.py`, biên nhận
`validation-evidence/results-20261119/improvement-round/map-overflow-d1.json`): cảnh báo đúng cgroup gây đầy, trễ 0 s.

### 3.4 File ra và ví dụ thật

Trên NFS (đọc qua `.234`):
`/mnt/sentinel-pulse-archive/pulse-live-final-1119/workers/<worker>/segments/sNNNNN/`
gồm `tokens.jsonl`, `decisions.jsonl`, `features.jsonl`, `issues.jsonl`, `loader.log`, `TERMINAL.json`.

Bản local mà bridge, RCA và campaign đọc:
`/var/lib/sentinel-pulse-live/pulse-live-final-1119/segments/sNNNNN/decisions.jsonl` trên từng worker.

Dòng đầu của
`/mnt/sentinel-pulse-archive/pulse-live-final-1119/workers/k8s-worker1.local/segments/s00001/tokens.jsonl`:

```json
{"type":"token_window","schema":"sentinel-pulse-token-window-v1","telemetry_contract":"pulse-token-select1f-v1",
 "workload_key":"production/payment-service:app","cgroup_id":"16090","pod_name":"payment-service-86bf86b6-wq4lf",
 "pod_uid":"20bd1770-7299-47f1-8bc5-1b9e2211191a","container_name":"app","workload_revision":"86bf86b6",
 "node_name":"k8s-worker1.local","window":1130263,"window_end":1795056468.618,"events":7,
 "grams":[[1954545664,2357198848,2357198848,2357198848,1],[2357198848,1954545664, ...], ...]}
```

Một decision **không báo** (istio-proxy của `aims-waypoint`, segment `s00004`, worker1):

```json
{"status":"token-score","branch":"token","candidate_alert_preview":false,"window_end":1795062903.118,
 "workload_key":"production/aims-waypoint:istio-proxy","token_score":4.647,"token_threshold":24.753,
 "events":377,"session_events":0}
```

Một decision **có báo**, trong trial tấn công 5 (`child_ptrace_handshake`, 12 lần/s, `catalog-service`, worker1):

```json
{"status":"token-score","branch":"token","candidate_alert_preview":true,"window_start":1795062758.618,
 "window_end":1795062759.118,"workload_key":"production/catalog-service:app","token_score":40.498,
 "token_threshold":19.301,"events":519,"session_events":503,"capture_segment":"s00004"}
```

Điểm 40,50 > ngưỡng 19,30 → báo. 503/519 sự kiện chạy trên thread session (fixture được khởi chạy qua `kubectl exec`),
nên bridge gắn nhãn `stream=session` (mục 5).

---

## 4. Mô hình token (`sentinel_pulse/detector/token_model.py`)

### 4.1 Học: `CountTokenLM.learn` / `learn_window`

Với gram `(t0, t1, t2, w)` thấy `c` lần, cộng `c` vào ba ngữ cảnh đứng trước `w`:

```
count[1][(t2,)][w]          += c
count[2][(t1, t2)][w]       += c
count[3][(t0, t1, t2)][w]   += c
names[w >> 23] += c;  given[w >> 23][w] += c;  total += c
```

`learn_window` đọc đúng định dạng loader: `for *gram, c in grams: learn(strip(gram), int(c))`. `strip` bỏ các ô
TOK_NONE ở đầu, nên gram đầu thread thành gram ngắn.

Ví dụ: gram `[1946157056, 4194312, 12582918, 25165824, 5]` = (`epoll_wait`, `read` 300 byte, `write` 120 byte) →
`close`, 5 lần, cộng 5 vào `count[1][(write,)][close]`, `count[2][(read, write)][close]`,
`count[3][(epoll_wait, read, write)][close]`.

### 4.2 Xác suất: Witten–Bell (`prob`)

```
p ← P0(w) = P(tên) × P(biến thể | tên)            (cộng ½, tên chưa thấy dùng xác suất biến thể chưa thấy trung bình)
với k = 1, 2, 3:  p ← (c(h_k, w) + T(h_k)·p) / (c(h_k) + T(h_k))      (bỏ qua nếu ngữ cảnh h_k chưa thấy)
```

`T(h)` = số token khác nhau từng theo sau `h`. Ngữ cảnh "đoán được" tin số đếm của nó; ngữ cảnh nhiều khả năng nhường
xác suất cho mức ngắn hơn.

### 4.3 Điểm cửa sổ: `window_score`

Mỗi gram cho độ bất ngờ `−ln p`, lặp đúng số lần `c` của nó; sắp giảm dần; lấy trung bình `top` giá trị lớn nhất.
Cấu hình hiện tại `lidds-ml-v5-t3`: `top = 3` (đọc từ `MODELS.json`).

Ví dụ minh hoạ: một cửa sổ có gram A (−ln p = 45, 2 lần), gram B (31, 1 lần), gram C (6, 400 lần) → điểm =
(45 + 45 + 31)/3 = 40,3. Với `top = 10` (v5) điểm sẽ là (45·2 + 31 + 6·7)/10 = 16,3: hành vi lạ ngắn bị pha loãng
bởi hành vi quen. Đây là cơ chế khiến t3 tăng phát hiện trên LID-DS 2019 (chủ yếu ở Heartbleed, 17 → 73/77 trên
holdout) mà vẫn giữ mức của LID-DS 2021.

---

## 5. Fit: học mô hình và đặt ngưỡng (`scripts/analysis/token_branch_fit.py`)

**Đầu vào** (NFS):

- capture normal `/mnt/sentinel-pulse-archive/pulse-token-capture-v6-1116/`
  (đọc `workers/*/segments/*/tokens.jsonl*`);
- thêm normal của lượt trước ngoài các trial: `--extra-run /mnt/sentinel-pulse-archive/pulse-live-v5-1110`.

**Các bước**

1. `split()`: tách dòng `tokens.jsonl` theo `workload_key`, bỏ cửa sổ trong [bắt đầu − 5 s, bắt đầu + 25 s] của mọi
   interval campaign (`trial_spans`).
2. `crossfit_one()`: cắt thời gian thành đoạn 30 phút liền nhau, chia lần lượt vào 5 fold; mỗi fold được chấm bằng mô
   hình học 4 fold kia; lấy điểm lớn nhất của mỗi (container, khối 60 s).
3. `fit_crossfit()`: bỏ 0,5% cực đại lớn nhất (`--trim 0.005`), khớp Gumbel theo moment, ngưỡng tại α′ = 0,0003;
   mô hình cuối học **toàn bộ** dữ liệu.
4. Ghi `MODELS.json` và `FIT.json`.

**File ra** (NFS):

- `/mnt/sentinel-pulse-archive/pulse-live-v7-fit-1118/token/MODELS.json`: mỗi workload
  `{lm, lm_sha256, threshold, top}`;
- `/mnt/sentinel-pulse-archive/pulse-live-v7-fit-1118/token/<hash>.lm.json.gz`: bảng đếm của 21 workload;
- `/mnt/sentinel-pulse-archive/pulse-live-v7-fit-1118/token/FIT.json`: tham số và thống kê từng workload;
- `/mnt/sentinel-pulse-archive/pulse-live-v7-fit-1118/count-thresholds.json`: ngưỡng của nhánh đếm (shadow).

**Ví dụ thật**, `production/catalog-service:app` trong `FIT.json`:

| Trường | Giá trị |
|---|---|
| `training_windows` | 982.837 cửa sổ |
| `validation_blocks` (khối 60 s giữ ra) | 8.276 |
| `gumbel` (μ, β) | (7,6657; 1,4344) |
| ngưỡng = μ − β·ln(−ln(1 − α′)) | 7,6657 + 1,4344 × 8,1116 = **19,30** |
| `validation_blocks_above` | 60 khối (0,72%) |
| `validation_block_max` | 64,08 |

Đây chính là `token_threshold` 19,30 trong decision có báo ở mục 3.4. Mục của workload này trong `MODELS.json` có
dạng `{"lm": ".../<hash>.lm.json.gz", "lm_sha256": "...", "threshold": 19.3006, "top": 3}`; ví dụ
`production/aims-frontend:web` có `threshold` 15,44.

Fit phải làm lại khi cụm đổi (image, phiên bản, workload) hoặc khi đổi cấu hình mô hình (quy tắc D9). Lần đổi sang t3
ngày 18/11 dùng lại capture v6, chỉ fit lại (16:59–19:10 UTC, đỉnh 14,4 GB, unit `pulse-v7-token-fit` trên `.234`).

---

## 6. Alert bridge (`sentinel_pulse/ops/alert_bridge.py`)

Unit `pulse-alert-bridge-pulse-live-final-1119` trên `.234`. Cấu hình:
`/var/lib/sentinel-pulse-alert-bridge/pulse-live-final-1119/config.json` (danh sách worker, URL Alertmanager).

1. Với mỗi worker, mở `ssh tail` trên decision **local**
   (`/var/lib/sentinel-pulse-live/pulse-live-final-1119/segments/*/decisions.jsonl`), chỉ lấy dòng
   `"candidate_alert_preview":true`. Đọc qua ssh vì qua NFS dòng mới hiện chậm khoảng 5 s.
2. `Bridge.ingest`: gom thành **đợt** theo container; dòng dương cách nhau không quá `resolve_after_seconds` thuộc cùng
   đợt. Mỗi đợt là một alert `SentinelPulseAnomaly`, nhãn `stream` = `session` nếu ≥ 50% sự kiện của cửa sổ chạy trên
   thread session, ngược lại `native` (chỉ để phân loại, không hạ cảnh báo).
3. `push_worker`: POST `/api/v2/alerts` ngay khi đợt bắt đầu (đường **push**). Song song xuất gauge
   `sentinel_pulse_preview_active` cho Prometheus (đường **pull**, để so sánh). Alert chưa giao được ghi vào hàng đợi
   bền `push-queue.jsonl` và thử lại (D3).
4. Alertmanager gọi webhook ngược về bridge → ghi lần giao đầu và độ trễ vào `deliveries.jsonl`; dòng decision đầu của
   đợt vào `triggers.jsonl` (RCA đọc file này).

File ra (đĩa local `.234`): `/var/lib/sentinel-pulse-alert-bridge/pulse-live-final-1119/` gồm `episodes.jsonl`,
`pushes.jsonl`, `deliveries.jsonl`, `triggers.jsonl`, `notifications.jsonl`, `rca.jsonl`, `STATUS.json`.

**Ví dụ thật**, cảnh báo trial tấn công 5 ở mục 3.4 trong `deliveries.jsonl`:

| Mốc | Thời điểm (unix) | Sau cuối cửa sổ |
|---|---|---|
| cuối cửa sổ (`window_end`) | 1795062759.118 | 0 |
| bridge nhận dòng | 1795062759.253 | 0,135 s |
| push tới Alertmanager | 1795062759.257 | 0,139 s |
| Alertmanager giao (webhook) | 1795062759.258 | **0,140 s** |

Campaign gọi `kubectl exec` lúc 1795062758.500, nên cảnh báo tới Alertmanager khoảng 0,76 s sau đó.
(`preview_emitted_at` lấy theo đồng hồ worker, lệch vài ms so với `.234`, nên `latency_from_preview` có thể hơi âm.)

Cảnh báo đầu tiên của lượt (trước tấn công, đợt `88fae51de5d4dc70573c9102`, catalog-service trên worker3): đường push
tới Alertmanager sau cuối cửa sổ 0,27 s, đường pull-fast 5,60 s.

---

## 7. RCA (`sentinel_pulse/rca/service.py`)

Unit `rca-pulse-live-final-1119` trên `.234`, cấu hình `/etc/sentinel-pulse-rca/rca-pulse-live-final-1119.json`.

- Nguồn sự kiện kernel: stream Tetragon trên từng node (`kubectl exec` vào pod Tetragon, `tetra getevents`, policy
  `sentinel-rca-runtime-v1`, `sentinel-rca-fork-v1`, `sentinel-rca-flow-v1`) → chuẩn hoá → vòng đệm SQLite cục bộ.
- Trigger: dòng trong `/var/lib/sentinel-pulse-alert-bridge/pulse-live-final-1119/triggers.jsonl`.
- Mỗi trigger: lấy sự kiện của đúng container trong [cửa sổ − 30 s, cửa sổ] → dựng cây process → xếp nghi phạm → ghi
  case. Bridge đẩy lại cùng alert kèm chú thích RCA khi case xuất hiện (khoảng 2,7 s sau alert).
- Container đã có case trong 300 s: không mở case mới trừ khi có exec mới (follow-up, xét lại sau 2 s).

---

## 8. Campaign: tạo trial có nhãn

**File code**

- `sentinel_pulse/pipeline/plan_matched_run.py`: lập lịch 945 trial (workload, kịch bản, tốc độ, PAD, bật-tắt, seed)
  vào `/mnt/sentinel-pulse-archive/pulse-live-final-1119/CONFIG.json`.
- `sentinel_pulse/pipeline/matched_traffic.py` + `testbed/traffic/set_aims_traffic_regime.sh`: áp 11 pha tải đã đăng ký
  (steady, toolmix, peak, burst, recovery, ...); pha cuối `steady` giữ tới hết lượt.
- `sentinel_pulse/attack/preview_campaign.py`: `one_pair` chạy từng trial.
- `sentinel_pulse/attack/preview_target.py`: chép (stage) binary vào container trên worker, chỉ tới các đường dẫn cho phép.
- `testbed/attack/runtime_attack_with_benign_control.c`: fixture tự viết, 5 kịch bản (`anonymous_mprotect_churn`,
  `child_ptrace_handshake`, `invalid_setns_burst`, `seccomp_api_probe`, `execveat_resolution_probe`) + chế độ
  `benign_exec_control`; mọi thao tác chỉ ảnh hưởng process của chính nó hoặc chắc chắn thất bại.

**Một trial** (`one_pair`), mỗi bước là một khoảng có nhãn ghi vào `INTERVALS.jsonl`:

| Bước | Nhãn | Nội dung |
|---|---|---|
| control | `expected_normal` | 17 s không làm gì |
| admin | `expected_normal` | một lệnh quản trị thật của image qua `kubectl exec` (`whoami`, `stat /`, `find /etc ...`) |
| benign | `expected_normal` | binary vô hại, cùng đường khởi chạy như tấn công, chỉ `getpid` + `clock_nanosleep` |
| attack | `attack` | fixture chạy kịch bản 15 s ở tốc độ đăng ký (0,1–24 lần/s), có thể kèm PAD 300 hoặc bật-tắt 10 s |
| lotl | `attack_lotl` | chỉ dùng `sh`/`cat`/`ls` của image: đọc token service account, `/proc`, socket, tài khoản; ghi rồi xoá file `/tmp` |
| eventgen | `attack_eventgen` | một trong 14 hành động của Falco event-generator v0.13.0 (bản tĩnh tự build) |

Sau control, thứ tự các bước được xáo có seed. Khoảng tấn công còn bật thu sự kiện exec của Tetragon để biết thời điểm
kernel thật sự chạy binary (dùng tính độ trễ).

**File ra** (NFS): `/mnt/sentinel-pulse-archive/pulse-live-final-1119/pulse-development-matrix/` gồm
`INTERVALS.jsonl`, `DISPATCH.jsonl`, `EVENTGEN.jsonl`, `ATTEMPTS.jsonl`, `trials/NNNN/`, `STATUS.json`.
`STATUS.json` chỉ đếm theo nhánh đếm cũ, không dùng để báo cáo.

**Ví dụ thật**, khoảng tấn công của trial 5 trong `INTERVALS.jsonl`:

```json
{"label":"attack","trial_id":"5:attack","scenario":"child_ptrace_handshake","rate_per_second":12,"seed":61501,
 "duration_seconds":15,"start_at":1795062758.5002136,"node_name":"k8s-worker1.local",
 "pod_name":"catalog-service-6dc97b678f-wgv7z","pod_uid":"24b7eeee-b536-4c0d-aaf2-8dd75437fe00",
 "container_name":"app","cgroup_id":16899,"workload_key":"production/catalog-service:app",
 "binary_path":"/tmp/sentinel-runtime-attack-blind","injection_id":"pulse-live-final-1119:0005"}
```

**Xem sơ 6 cặp đầu của lượt** (đối chiếu thô lúc 19/11 11:34: có cảnh báo token trên đúng pod trong 15 s đầu; số chính
thức chỉ lấy từ phân tích ở mục 9):

| Loại | Có cảnh báo | Cảnh báo đầu sau khi bắt đầu |
|---|---|---|
| attack | 6/6 | 0,57–0,77 s |
| lotl | 6/6 | 0,39–0,91 s |
| eventgen | 6/6 | 0,39–0,95 s |
| control | 0/7 | — |
| benign | 6/6 | khoảng 30 cửa sổ báo mỗi trial |
| admin | 6/6 | 1 cửa sổ báo mỗi trial |

---

## 9. Khởi chạy và phân tích

### 9.1 Khởi chạy: `scripts/launch_run.sh`

Chạy trên `.234` từ thư mục snapshot. `bash scripts/launch_run.sh all` lần lượt:

1. `plan` → `CONFIG.json`;
2. `workers` → cài unit worker trên 3 node qua ssh + sudo, tạo thư mục decision local;
3. `rca` → unit RCA;
4. `bridge` → unit alert bridge;
5. `master` → unit traffic + campaign, và (`K8S_EVENTS=1`) unit `pulse-k8s-events-<run>` chạy
   `scripts/k8s_events_record.py`, ghi `/mnt/sentinel-pulse-archive/pulse-live-final-1119/k8s-events.jsonl`.

Mọi unit là system unit, nên đóng phiên ssh không ảnh hưởng (bộ ghi sự kiện K8s từng là user unit và dừng theo phiên
ssh lúc 09:49 ngày 19/11; đã đổi sang system unit).

Lượt cuối: 90 phút đầu chỉ normal (chọn mẫu), khoảng 36 giờ campaign, khoảng 6 giờ normal cuối để đo gánh cảnh báo;
tổng 162.000 s. Protocol đăng ký trước: `sentinel_pulse/protocol/pulse-live-final-v1.json`.

### 9.2 Phân tích sau lượt

- `scripts/analysis/pulse_live_v4.py`: H0 (recall, precision 1:1, control dương, độ trễ, gánh cảnh báo theo
  replica-giờ). Trial được tính báo nếu có cửa sổ báo của cùng container trong [bắt đầu, bắt đầu + 15 s]; độ trễ = cuối
  cửa sổ báo − sự kiện kernel đầu tiên của tấn công.
- `scripts/analysis/live_attribution.py`, `scripts/analysis/native_stream.py`, `scripts/analysis/rca_coverage.py` và
  các script khác trong `scripts/analysis/`: quy kết, dòng native, độ phủ RCA, gánh theo ngữ cảnh.
- Biên nhận ghi vào `validation-evidence/results-<ngày>/<run>/`; ví dụ lượt v6:
  `validation-evidence/results-20261118/pulse-live-v6-1117/`.
- Sau phân tích: nén segment bằng `scripts/compress_raw_frames.py` (ra `*.jsonl.gz` + `COMPRESSION.json` trong từng
  segment; các script đọc qua `sentinel_pulse/common.py` `open_sealed` nhận cả hai dạng).

---

## 10. Nhánh offline: LID-DS và CB-DS

Cùng số học với cụm (test `tests/test_token_model.py` kiểm sai lệch < 1e-12 giữa `CountTokenLM` và bản offline
`scripts/analysis/lidds_ml_tokens.py` `TokenLM`).

- `scripts/analysis/lidds_token_cache.py`: dựng cache 4-gram từ bản ghi syscall của dataset theo cùng định nghĩa token.
- `scripts/analysis/lidds_token_study.py`, `scripts/analysis/lidds_ml_v4.py`: học, cross-fit, ngưỡng Gumbel, chấm.
- `scripts/analysis/lidds2019_dev.py`: split 30/70 của LID-DS 2019 (development / holdout) và các bước chấm t3.

Kết quả của cấu hình t3 (biên nhận `validation-evidence/results-20261118/lidds2019-development/`):

| Tập | Phát hiện | Báo nhầm | p95 độ trễ | File |
|---|---|---|---|---|
| LID-DS 2021 official | 1.236/1.271 (97,25%) | 15/7.938 (0,19%) | 1,54 s | `official2021.json` |
| LID-DS 2019 holdout (70%, dung sai nhãn 1 s) | 817/841 (97,15%) | 25/5.395 (0,46%) | 10,95 s | `holdout.json` |

Holdout 2019 đã được mô hình v5 chấm trước đó và quy tắc dung sai đặt sau lượt chấm (amendment 1). Độ trễ 2019 không
xuống được 3 s: cận dưới của mọi bộ phát hiện dựa trên độ lạ là p95 9,39 s (`latency.json`).

Mỗi lần đổi mô hình (top, trim, α′, token) phải chạy lại nhánh này trước khi lên cụm.

---

## 11. Bảng tra nhanh

| Cần tìm | Ở đâu |
|---|---|
| Code probe | `sentinel_pulse/ebpf/pulse_counter.bpf.c`, `sentinel_pulse/ebpf/pulse_tokens.bpf.h`, `sentinel_pulse/ebpf/pulse_token_ids.h` |
| Code loader | `sentinel_pulse/ebpf/pulse_counter_loader.c` |
| Bản build probe đang chạy | `/home/dat/pulse-tokens-final-f8ccbb2/` trên mỗi worker (.237, .238, .239) |
| Code worker | `sentinel_pulse/pipeline/matched_worker.py`, `sentinel_pulse/collector/token_capture.py` |
| Cấu hình worker | `/etc/sentinel-pulse/matched-worker-pulse-live-final-1119.json` trên mỗi worker |
| Code mô hình | `sentinel_pulse/detector/token_model.py` |
| Code fit | `scripts/analysis/token_branch_fit.py` |
| Mô hình đang dùng | `/mnt/sentinel-pulse-archive/pulse-live-v7-fit-1118/token/MODELS.json` (+ `*.lm.json.gz`, `FIT.json`) |
| Capture normal | `/mnt/sentinel-pulse-archive/pulse-token-capture-v6-1116/` |
| Snapshot code của lượt | `/mnt/sentinel-pulse-archive/runtime-0c385d9-20261119/source/` |
| Dữ liệu lượt (NFS) | `/mnt/sentinel-pulse-archive/pulse-live-final-1119/workers/<worker>/segments/sNNNNN/` |
| Decision local | `/var/lib/sentinel-pulse-live/pulse-live-final-1119/segments/sNNNNN/decisions.jsonl` trên mỗi worker |
| Lịch và cấu hình lượt | `/mnt/sentinel-pulse-archive/pulse-live-final-1119/CONFIG.json` |
| Nhãn trial | `/mnt/sentinel-pulse-archive/pulse-live-final-1119/pulse-development-matrix/INTERVALS.jsonl` |
| Sự kiện Kubernetes | `/mnt/sentinel-pulse-archive/pulse-live-final-1119/k8s-events.jsonl` |
| Đầu ra bridge | `/var/lib/sentinel-pulse-alert-bridge/pulse-live-final-1119/` trên `.234` |
| Code bridge, RCA | `sentinel_pulse/ops/alert_bridge.py`, `sentinel_pulse/rca/service.py` |
| Code campaign, fixture | `sentinel_pulse/attack/preview_campaign.py`, `testbed/attack/runtime_attack_with_benign_control.c` |
| Khởi chạy | `scripts/launch_run.sh` |
| Phân tích | `scripts/analysis/pulse_live_v4.py` và `scripts/analysis/` |
| Protocol lượt cuối | `sentinel_pulse/protocol/pulse-live-final-v1.json` |
| Nén sau lượt | `scripts/compress_raw_frames.py` |

---

## 12. Quy trình chuẩn và các lệnh cần chạy

Thứ tự đã dùng cho lượt cuối `pulse-live-final-1119`; lệnh là lệnh đã thực sự chạy. Mọi lệnh chạy trên lab
(`ssh 10.1.16.234` hoặc worker); `R=/mnt/sentinel-pulse-archive` (NFS). Job nặng trên `.234` luôn chạy trong
`systemd-run` có `MemoryMax` và `OOMPolicy=continue`.

### Bước 0. Đổi mô hình thì chấm lại dataset trước (offline, `.234`)

Chỉ khi đổi cấu hình mô hình (top, trim, α′, token). Chạy lại LID-DS 2021, LID-DS 2019 và CB-DS:

- `scripts/lidds2019_dev_run.sh`: split, gate, study trên phần development;
- `scripts/lidds2019_amendment1_run.sh`: LID-DS 2021 official rồi holdout 2019.

Biên nhận: `validation-evidence/results-<ngày>/...`, ví dụ `validation-evidence/results-20261118/lidds2019-development/`.

### Bước 1. Đăng ký protocol (máy bạn, trong repo)

Ghi giả thuyết, tiêu chí và cách tính vào `sentinel_pulse/protocol/<tên>.json` **trước** khi tính, commit và push.
Ví dụ: `sentinel_pulse/protocol/pulse-live-final-v1.json`.

### Bước 2. Build probe và proof (cả 3 worker)

```bash
for h in 237 238 239; do ssh 10.1.16.$h 'cd /home/dat/eBPF-project; git pull -q --ff-only;
  SHA=$(git log -1 --format=%h); B=/home/dat/pulse-tokens-final-$SHA
  cd sentinel_pulse/ebpf && make -s tokens TOKENS_BUILD_DIR=$B/build; cd ../..
  echo 1 | sudo -S -p "" env PYTHONPATH=$PWD /opt/sentinel-pulse/runtime-venv/bin/python \
    scripts/token_probe_proof.py --build $B/build --proof $B/proof --source-commit $SHA
  python3 -c "import json;d=json.load(open(\"$B/proof/RESULTS.json\"));print(d[\"valid\"])"'; done
```

- Code: `sentinel_pulse/ebpf/Makefile`, `scripts/token_probe_proof.py`.
- Kết quả trên từng worker: `/home/dat/pulse-tokens-final-<SHA>/build/` và `/home/dat/pulse-tokens-final-<SHA>/proof/RESULTS.json`.
- Phải đạt `valid: true` trên cả 3 worker (mỗi syscall đúng một token, không chèn thất bại). Bản final
  `pulse-tokens-final-f8ccbb2`: 361.900 / 442.796 / 393.644 lời gọi = số token.

### Bước 3. Đóng băng code (`.234`)

```bash
SNAP=$R/runtime-<sha>-<YYYYMMDD>
git clone -q ~/eBPF-project $SNAP/source && cd $SNAP/source && git checkout -q <sha>
```

Lượt chạy chạy từ `$SNAP/source`; sửa repo sau đó không ảnh hưởng.

### Bước 4. Thu normal (chỉ khi cụm đổi; `.234`, khoảng 12 giờ)

Không truyền `TOKEN_MODELS`, nên worker chỉ ghi `tokens.jsonl`, không chấm.

```bash
cd /home/dat/eBPF-project && export LAB_SSH_PASSWORD=$(cat /home/dat/.pulse-recovery-credential-20261005) \
  RUN=pulse-token-capture-<ver>-<MMDD> SNAP=$SNAP/source \
  CANDIDATE=$R/pulse-next-run-model/model-bundle MODEL_HASH=4bad16dcd88b004f55d81c1a9721b9224a55b7a2cc2f35023cf57c8bb11d7fbc \
  POLICY=sentinel_pulse/protocol/policy-2of2-a10-refreshed.json POLICY_HASH=9c41ebc06243461a8abce9ceec3becdb17869db42f51a85b3137b87d030d1540 \
  SECONDS_TOTAL=43200 TOKEN_BUILD=/home/dat/pulse-tokens-<...> LOCAL_DECISIONS=1
bash $SNAP/scripts/launch_run.sh plan
bash $SNAP/scripts/launch_run.sh workers
bash $SNAP/scripts/launch_run.sh traffic
```

Kết quả: `$R/pulse-token-capture-<ver>-<MMDD>/workers/*/segments/*/tokens.jsonl`; lần gần nhất
`/mnt/sentinel-pulse-archive/pulse-token-capture-v6-1116/`.

### Bước 5. Fit (`.234`, chạy ngầm có trần bộ nhớ)

```bash
F=$R/pulse-live-<ver>-fit-<MMDD>; mkdir -p $F /var/tmp/pulse-<ver>
cp $R/pulse-live-v6-fit-1117/count-thresholds.json $F/        # nhánh đếm (shadow) giữ ngưỡng cũ
echo 1 | sudo -S -p "" systemd-run --unit=pulse-<ver>-token-fit --uid=dat --gid=dat \
  -p MemoryMax=22G -p OOMPolicy=continue -E PYTHONPATH=$SNAP/source -E PYTHONDONTWRITEBYTECODE=1 \
  -E HOME=/home/dat --working-directory=/tmp \
  /home/dat/ml-venv/bin/python -u $SNAP/source/scripts/analysis/token_branch_fit.py \
  --run-root $R/pulse-token-capture-v6-1116 \
  --train 1794813247.7573142 1794842047.7573142 --validation 1794842047.7573142 1794856447.7573142 \
  --extra-run $R/pulse-live-v5-1110 --extra-span 1794339632.1040783 1794420632.1040783 \
  --folds 5 --alpha 0.0003 --share 1.0 --top 3 --trim 0.005 --jobs 2 \
  --work /var/tmp/pulse-<ver>/fit-split --dump-maxima $F/maxima --output $F/token
```

- Code: `scripts/analysis/token_branch_fit.py`.
- Kết quả: `$F/token/MODELS.json`, `$F/token/*.lm.json.gz`, `$F/token/FIT.json`.
- Khoảng 2–3 giờ, đỉnh 14,4 GB (fit v7). Kiểm `FIT.json` có đủ workload và `validation_blocks_above` không bất thường.

### Bước 6. Diễn tập (`.234`, khoảng 20–30 phút)

Lệnh như bước 7, thêm `REHEARSAL=1` và `RUN=pulse-final-rehearsal-<MMDD>`: 6 trial, mỗi loại một, trên các workload
khó nhất; kiểm mọi bước chạy và kiểm script phân tích. Biên nhận lần gần nhất:
`validation-evidence/results-20261119/final-rehearsal/`. Đạt thì xoá thư mục diễn tập rồi chạy lượt chính.

### Bước 7. Chạy live (`.234`, từ `$SNAP`)

```bash
env LAB_SSH_PASSWORD=$(cat /home/dat/.pulse-recovery-credential-20261005) RUN=pulse-live-final-<MMDD> SNAP=$SNAP \
  CANDIDATE=$R/pulse-next-run-model/model-bundle MODEL_HASH=4bad16dcd88b004f55d81c1a9721b9224a55b7a2cc2f35023cf57c8bb11d7fbc \
  POLICY=sentinel_pulse/protocol/policy-2of2-a10-refreshed.json POLICY_HASH=9c41ebc06243461a8abce9ceec3becdb17869db42f51a85b3137b87d030d1540 \
  SECONDS_TOTAL=162000 TOKEN_BUILD=/home/dat/pulse-tokens-final-f8ccbb2 \
  TOKEN_MODELS=$R/pulse-live-v7-fit-1118/token/MODELS.json V3_COUNTS=$R/pulse-live-v7-fit-1118/count-thresholds.json \
  ADMIN_CONTROL=1 ADMIN_COMMANDS=v6 RANDOM_ORDER=1 LOTL_ATTACK=1 DILUTION_PADS=300 ON_OFF=10 \
  EVENTGEN=$R/tools/event-generator-0.13.0-static K8S_EVENTS=1 LOCAL_DECISIONS=1 \
  ATTACK_RATES=0.1,0.5,1,3,6,12,24 bash scripts/launch_run.sh all
```

`all` = `plan → workers → rca → bridge → master` (`scripts/launch_run.sh`). Kiểm ngay sau khi khởi chạy:

```bash
systemctl list-units --no-legend "pulse*" "rca*"                    # trên .234: campaign, bridge, rca, k8s-events
ssh 10.1.16.237 'systemctl is-active pulse-matched-worker-<RUN>'     # lặp cho .238, .239
cat $R/<RUN>/pulse-development-matrix/STATUS.json                    # trạng thái campaign
```

Trong lúc chạy: không job nặng trên node nào, không pull code lên worker, để lượt chạy hết chu kỳ. Chỉ đọc file bằng
`head`, không `cat`/`grep`/`tail` cả file lớn trên NFS.

### Bước 8. Phân tích (`.234`, sau khi lượt xong)

Mỗi lệnh chạy trong `systemd-run ... -p MemoryMax=... -p OOMPolicy=continue` với `PYTHONPATH=$SNAP/source`;
`RUN=$R/<run>`, `M=$R/pulse-live-v7-fit-1118/token/MODELS.json`.

```bash
python3 scripts/analysis/pulse_live_v4.py    --run-root $RUN --output h0.json          # H0: recall, precision, control, độ trễ, gánh
python3 scripts/analysis/live_attribution.py --run-root $RUN --models $M --output attribution.json
python3 scripts/analysis/native_stream.py    --run-root $RUN --models $M --output native.json
python3 scripts/analysis/rule_e_benefit.py   --run-root $RUN --models $M --output rule.json
python3 scripts/analysis/burden_context.py   --run-root $RUN --output burden-context.json
python3 scripts/analysis/rca_coverage.py     --cases <thư mục case RCA> --campaign $RUN/pulse-development-matrix --output rca.json
```

Biên nhận chép về repo `validation-evidence/results-<ngày>/<run>/` kèm `README.md`; cập nhật `notes/WORKLOG.md`,
`notes/STATE.md`, đồ án `thesis/`, paper `paper/`, báo cáo và slide trong `docs/`.

### Bước 9. Nén và dọn (sau phân tích)

```bash
python3 scripts/compress_raw_frames.py --run-root $RUN --files tokens.jsonl features.jsonl decisions.jsonl issues.jsonl
```

Ra `*.jsonl.gz` + `COMPRESSION.json` trong từng segment; file gốc chỉ bị xoá khi SHA-256 khớp `TERMINAL.json`. Sau đó
xoá thư mục tạm `/var/tmp/...` của fit và phân tích.

### Khi nào làm lại bước nào

| Thay đổi | Làm lại từ |
|---|---|
| Cụm đổi (image, phiên bản, workload) | Bước 4 → 5 → 6 → 7 |
| Đổi cấu hình mô hình (top, trim, α′) | Bước 0 → 1 → 5 (fit trên capture cũ) → 6 → 7 |
| Đổi code probe | Bước 0 nếu token đổi → 2 → 3 → 6 → 7 |
| Chỉ đổi campaign hoặc bridge | Bước 1 → 3 → 6 → 7 |
