# Kiến trúc Sentinel Pulse: từng thành phần trong hình và code tương ứng

Tài liệu đi theo đúng 5 trang của hình kiến trúc
`docs/architecture/sentinel-pulse-architecture.drawio` (ảnh xuất trong `docs/architecture/export/`:
`1-tong-quan.png`, `2-probe-ebpf.png`, `3-worker-mo-hinh-token.png`, `4-canh-bao-rca.png`, `5-hoc-va-danh-gia.png`).
Mỗi hộp trong hình có một mục: nó làm gì, code nằm ở file và hàm nào, chạy ở đâu, đọc và ghi file nào.

Trạng thái: hệ thống của lượt live cuối `pulse-live-final-1119` (19/11/2026): mô hình `lidds-ml-v5-t3` (top 3, trim 0,5%,
α′ 0,0003), probe `pulse-tokens-final-f8ccbb2`, snapshot code `/mnt/sentinel-pulse-archive/runtime-0c385d9-20261119/source/`.

Mọi tài liệu chỉ dùng hình draw.io này (chủ đồ án, 19/11):

- đồ án (`thesis/main.pdf`): Hình 4.1 = trang 1, Hình 4.2 = trang 3, Hình 4.3 = trang 4, Hình 5.1 = trang 2, Hình 6.1 =
  trang 5, chèn từ `docs/architecture/export/sentinel-pulse-architecture.pdf`;
- báo cáo và slide tiến độ 20/11: `docs/architecture/export/1-tong-quan.png`, `2-probe-ebpf.png`;
- paper: Figure 1 = `docs/architecture/sentinel-pulse-overview-en.drawio` (bản tiếng Anh, xuất
  `docs/architecture/export/overview-en.pdf`);
- luồng dữ liệu kèm ví dụ thật và lệnh chạy: `docs/LUONG_CODE.md`.

Đường dẫn bắt đầu bằng `sentinel_pulse/`, `scripts/`, `testbed/` là file trong repo (`/home/tndat/Downloads/eBPF-project/`
trên máy bạn, `/home/dat/eBPF-project/` trên `.234`). Máy: `.234` k8s-master; `.237` k8s-worker1, `.238` k8s-worker4,
`.239` k8s-worker3; `.233` NFS.

Sinh lại hình: sửa `docs/architecture/make_architecture_drawio.py`, chạy nó, rồi xuất bằng `drawio -x` (lệnh trong
`docs/architecture/README.md`; `-p` đánh số trang từ 1).

---

## Trang 1. Tổng quan hệ thống

### Cụm Kubernetes của lab

6 VM trên ESXi, Ubuntu 24.04, kernel 6.8.0, Kubernetes v1.34, Cilium, Istio ambient. 3 master (`.234`, `.235`, `.236`),
3 worker. Pulse chỉ cài thêm unit systemd trên node; không sửa ứng dụng hay pod.

### namespace production: ứng dụng AIMS

21 workload, khoảng 80 pod (frontend, API gateway, các service Python, PostgreSQL CNPG, Kafka, RabbitMQ, Redis, MinIO...).
Mỗi container là một cgroup v2; Pulse nhận diện container bằng cgroup id.

- Manifest tải normal: `testbed/k8s/production-loadgens.yaml`, `testbed/k8s/aims-sentinel-loadgen.yaml`.

### Probe eBPF của Pulse (kernel)

Bốn chương trình BPF dựng token cho mỗi syscall và đếm 4-gram theo thread.

| Hook | Code |
|---|---|
| `raw_tp/sys_enter` | `sentinel_pulse/ebpf/pulse_counter.bpf.c`: `pulse_sys_enter` → `pulse_record_call` |
| `raw_tp/sys_exit` | `sentinel_pulse/ebpf/pulse_tokens.bpf.h`: `pulse_tok_sys_exit` → `pulse_tok_return` |
| `fexit/__seccomp_filter` | `sentinel_pulse/ebpf/pulse_counter.bpf.c`: `pulse_seccomp_skip` |
| `raw_tp/sched_process_fork` | `sentinel_pulse/ebpf/pulse_tokens.bpf.h`: `pulse_tok_fork` |

- Bản build đang chạy: `/home/dat/pulse-tokens-final-f8ccbb2/build/` trên mỗi worker; build bằng
  `make tokens` (`sentinel_pulse/ebpf/Makefile`), kiểm bằng `scripts/token_probe_proof.py` (kết quả ở
  `/home/dat/pulse-tokens-final-f8ccbb2/proof/RESULTS.json`).
- Chi tiết: trang 2.

### Allow-list cgroup

Map `pulse_cgroups` (khai báo trong `sentinel_pulse/ebpf/pulse_counter.bpf.c`): chỉ cgroup có trong map mới được xử lý;
mọi task khác thoát sau một lần tra map (bước 1 của `pulse_record_call`).

- Loader nạp map từ file `/run/sentinel-pulse/allowed-cgroups` (trên worker) mỗi nhịp:
  `sentinel_pulse/ebpf/pulse_counter_loader.c` `refresh_targets_bounded` / `refresh_targets`. Allow-list rỗng thì loader
  dừng (fail closed).

### Tetragon (kprobe) và Agent Tetragon

Thành phần có sẵn của cụm (DaemonSet), dùng cho RCA, không dùng để phát hiện.

- Policy: `sentinel_pulse/k8s/tetragon-rca-runtime-policy.yaml`, `sentinel_pulse/k8s/tetragon-rca-flow-policy.yaml`,
  `testbed/k8s/tetragon-sentinel-pulse-exec-provenance.yaml` (exec của campaign, để biết thời điểm kernel chạy binary
  tấn công).
- RCA đọc sự kiện bằng `kubectl exec ... tetra getevents` (`sentinel_pulse/rca/service.py` `Service.start_stream`).

### Loader C (`pulse_counter_tokens_loader`)

User space, chạy làm process con của worker. Mỗi 0,5 s (ngay sau ranh giới cửa sổ của đồng hồ monotonic + 20 ms) đọc
map 4-gram theo lô, in mỗi (cgroup, cửa sổ đã đóng) một dòng `token_grams`, rồi xoá các mục đã in.

- Code: `sentinel_pulse/ebpf/pulse_counter_loader.c`: `main` (vòng lặp chính), `drain_grams` (xả map),
  `print_snapshots` (bộ đếm của nhánh cũ), `tok_stat_sum` (bộ đếm sức khoẻ).
- Khoá: worker kiểm SHA-256 của loader và object cùng proof theo kernel trước khi chạy
  (`sentinel_pulse/pipeline/matched_worker.py` `run`).

### sentinel-pulse-resolver

Unit systemd root trên mỗi worker, mỗi 15 s trả lời "cgroup nào là container nào" mà không cần quyền Kubernetes API:
dùng `crictl` và quét `/sys/fs/cgroup`.

- Code: `sentinel_pulse/collector/cgroup_resolver.py`: `cri_pods`, `cri_containers`, `resolve_cgroups`, `refresh`.
- Unit: `sentinel_pulse/systemd/sentinel-pulse-resolver.service`.
- Ghi: `/run/sentinel-pulse/allowed-cgroups` (loader đọc) và `/run/sentinel-pulse/cgroups.json` (worker đọc; cgroup id →
  pod, container, namespace, phiên bản workload).

### Worker chấm điểm

Unit `pulse-matched-worker-<run>` trên mỗi worker (giới hạn 3 core, 3 GB). Đọc stdout của loader, gắn danh tính, chấm mô
hình token của workload, ghi decision. Chi tiết: trang 3.

- Code: `sentinel_pulse/pipeline/matched_worker.py` `run`; cấu hình
  `/etc/sentinel-pulse/matched-worker-pulse-live-final-1119.json` trên worker (sinh từ `CONFIG.json` bởi
  `sentinel_pulse/pipeline/matched_services.py` `install`).
- "Map gram đầy → báo cửa sổ nặng nhất" (D1): `sentinel_pulse/collector/token_capture.py` `MapOverflow.frame`.
- "Ghi NFS bằng thread nền": `sentinel_pulse/pipeline/async_sink.py` `AsyncSink`, `AsyncState`.

### Luồng decision local

`/var/lib/sentinel-pulse-live/<run>/segments/sNNNNN/decisions.jsonl` trên đĩa từng worker: bản sao decision mà bridge,
RCA và campaign đọc (đọc qua NFS chậm khoảng 5 s). Worker ghi cùng lúc với bản NFS (biến `local` trong
`matched_worker.py` `run`).

### Alert bridge (trên .234)

Unit `pulse-alert-bridge-<run>`. Bám decision local của 3 worker qua SSH, gom đợt theo container, push vào
Alertmanager, hàng đợi bền, nhãn `stream`, phục vụ trang case. Chi tiết: trang 4.

- Code: `sentinel_pulse/ops/alert_bridge.py` (`Streams`, `Bridge.ingest`, `Bridge.tick`, `push_worker`, `PushQueue`,
  `stream_of`, `serve`, `main`); dựng unit bằng `scripts/alert_bridge.sh`.
- Cấu hình và đầu ra: `/var/lib/sentinel-pulse-alert-bridge/<run>/` trên `.234`.

### Alertmanager

Của kube-prometheus-stack trong cụm, nhận `POST /api/v2/alerts`; route theo nhãn `notify`.

- Cấu hình route và rule: `testbed/k8s/monitoring/sentinel-pulse-alerting.yaml`.

### RCA (trên .234)

Unit `rca-<run>`. Một case cho mỗi cảnh báo Alertmanager đã nhận, từ sự kiện Tetragon. Chi tiết: trang 4.

- Code: `sentinel_pulse/rca/service.py` `Service` (cấu hình `/etc/sentinel-pulse-rca/rca-<run>.json`).

### RCA viewer, Prometheus / Grafana

- Trang `/cases`, `/cases/<id>`, `/cases.json`: bridge phục vụ (`sentinel_pulse/ops/alert_bridge.py` `serve`, dựng nội
  dung bằng `sentinel_pulse/ops/rca_view.py` `CaseIndex`, `render_html`, `render_index`, `case_svg`).
- Dashboard: `testbed/k8s/monitoring/sentinel-pulse-dashboard.json`; nguồn dữ liệu bảng case:
  `testbed/k8s/monitoring/sentinel-pulse-infinity-datasource.yaml`.

### Planner + launcher (đánh giá)

Dựng `CONFIG.json` bất biến của một lượt (hash mô hình, probe, fixture, lịch tải, lịch trial) và cài mọi unit.

- Code: `sentinel_pulse/pipeline/plan_matched_run.py` `plan` (và `rehearsal_schedule` cho diễn tập);
  `scripts/launch_run.sh` (bước `plan`, `workers`, `rca`, `bridge`, `master`, `traffic`, `all`).
- Bộ ghi sự kiện Kubernetes: `scripts/k8s_events_record.py` (system unit `pulse-k8s-events-<run>`, ghi
  `/mnt/sentinel-pulse-archive/<run>/k8s-events.jsonl`).

### Job phân tích (.234)

Mọi job nặng chạy trong `systemd-run` có `MemoryMax` và `OOMPolicy=continue`; không chạy cùng lượt live.

- Fit: `scripts/analysis/token_branch_fit.py`; dataset: `scripts/analysis/lidds_*.py`, `scripts/analysis/lidds2019_dev.py`;
  phân tích lượt live: `scripts/analysis/pulse_live_v4.py` và các script khác trong `scripts/analysis/`.

### Tải normal (đánh giá)

4 generator gửi HTTP tới AIMS theo lịch đăng ký (steady, toolmix, peak, burst, recovery).

- Code: `sentinel_pulse/pipeline/matched_traffic.py` (áp từng pha), `testbed/traffic/set_aims_traffic_regime.sh`;
  unit `pulse-matched-traffic-<run>`.

### Chiến dịch tấn công (đánh giá)

Lượt cuối 945 trial; mỗi trial: control 15 s, rồi theo thứ tự có seed: lệnh quản trị, binary vô hại, tấn công, lotl,
event-generator.

- Code: `sentinel_pulse/attack/preview_campaign.py` (`one_pair`, `step_order`, `LOTL_SCRIPT`, `EVENTGEN_ACTIONS`,
  `ADMIN_SETS`); `sentinel_pulse/attack/preview_target.py` (chép binary vào container, chỉ tới đường dẫn cho phép);
  fixture `testbed/attack/runtime_attack_with_benign_control.c`; unit `pulse-matched-campaign-<run>`.
- Ghi: `/mnt/sentinel-pulse-archive/<run>/pulse-development-matrix/` (`INTERVALS.jsonl`, `trials/`, ...).

### NFS .233

`/mnt/sentinel-pulse-archive` (`10.1.16.233:/sentinel-pulse`): segment 30 phút của mỗi worker
(`/mnt/sentinel-pulse-archive/<run>/workers/<worker>/segments/sNNNNN/`: `decisions.jsonl`, `tokens.jsonl`,
`features.jsonl`, `issues.jsonl`, `TERMINAL.json` có SHA-256), `CONFIG.json`, mô hình
(`/mnt/sentinel-pulse-archive/pulse-live-v7-fit-1118/token/`), snapshot code.

### Người vận hành

Nhận cảnh báo route `notify=immediate` hoặc xem dashboard; mở case RCA.

### Repo git và dữ liệu công khai

- Repo: GitHub `main`, checkout trên `.234`, `.237`, `.238`, `.239` đồng bộ bằng `git pull --ff-only`
  (`scripts/sync_cluster_checkouts.sh`).
- LID-DS 2021, CB-DS, LID-DS 2019: chấm offline trên `.234` (trang 5).

---

## Trang 2. Probe eBPF trong kernel

### Hàng trên: một syscall đi qua kernel

`syscall(nr, args)` → `seccomp của container` (có thể trả lỗi, syscall không chạy) → `thân syscall` → `trở về user
space`. Đây là đường của kernel, không phải code của Pulse; Pulse gắn hook ở bốn điểm dưới.

### `raw_tp/sys_enter` → `pulse_record_call`

`sentinel_pulse/ebpf/pulse_counter.bpf.c`:

1. `bpf_get_current_cgroup_id()` → tra `pulse_cgroups`; không có thì thoát;
2. `full_counts[nr]++` và bin cặp syscall (nhánh đếm cũ, không dùng để báo);
3. tra hoặc tạo trạng thái thread trong `pulse_last_syscall` (khoá `pid_tgid`); thread mới: `pulse_tok_reset` và
   `pulse_tok_lineage` (thẻ dòng dõi);
4. syscall không có hook (`pulse_tok_hooked` trả 0) → phát token tên ngay: `pulse_tok_emit(..., pulse_tok_plain(nr))`;
   có hook → `tok_pending = 1`.

### `fexit/__seccomp_filter`

`sentinel_pulse/ebpf/pulse_counter.bpf.c` `pulse_seccomp_skip`: khi seccomp bỏ qua syscall (`result == -1`, không phải
lần kiểm lại lồng nhau), syscall không tới `sys_enter`; gọi `pulse_record_call(nr, 1)` để vẫn có token tên và đếm
`seccomp_skipped_or_emulated`.

### `raw_tp/sys_exit` → `pulse_tok_sys_exit`

`sentinel_pulse/ebpf/pulse_tokens.bpf.h`: chỉ chạy khi `tok_pending`; `pulse_tok_return` dựng token theo kết quả:

- lỗi `[-4095, -1]` và syscall có cờ ERR: tên + errno;
- đọc/ghi thành công: tên + `pulse_tok_log2(ret)` (chặn 15);
- mở file thành công: tên + bit ghi + `pulse_tok_dir_of_fd(ret)`;
- còn lại: tên.

Bảng 39 syscall có hook và cờ của chúng: `sentinel_pulse/ebpf/pulse_token_ids.h` `PULSE_HOOKED_ROWS`
(`PULSE_HOOK_SMALL` là bản đo chi phí D6, không dùng).

**Thư mục đầu**: `pulse_tok_dir_of_fd` (fd → `struct file` → dentry, mount), `pulse_tok_walk_step` (một bước đi ngược
`d_parent`, vượt mount, gọi qua `bpf_loop` tối đa 64 lần), `pulse_tok_dir_hash` (FNV-1a của thành phần đầu, 20 bit).

### `.rodata.tokcfg`

`sentinel_pulse/ebpf/pulse_tokens.bpf.h` `pulse_tok_config` (`futex_at_exit`, `count_grams`): loader đặt trước khi nạp
(`--tokens exit-nofutex|exit|grams` trong `pulse_counter_loader.c` `main`); verifier cắt nhánh tắt. Lượt live dùng
`grams` (chế độ D).

### `raw_tp/sched_process_fork`

`sentinel_pulse/ebpf/pulse_tokens.bpf.h` `pulse_tok_fork`: chạy trong process cha; tạo sẵn trạng thái cho con với thẻ
dòng dõi của cha và lịch sử token rỗng. Thread gặp lần đầu không qua fork lấy thẻ bằng `pulse_tok_lineage` (leader →
cha cùng cgroup → pid 1 của namespace là native, còn lại session).

### `pulse_tok_emit`

`sentinel_pulse/ebpf/pulse_tokens.bpf.h`: khoá `struct pulse_gram_key` = (cgroup, cửa sổ = `now_ns / PULSE_TOK_WINDOW_NS`,
3 token trước + token mới, dòng dõi); có thì `__sync_fetch_and_add`, chưa có thì `bpf_map_update_elem(..., BPF_NOEXIST)`,
thua tranh chấp thì tra lại, vẫn không có thì `pulse_tok_stat(0)` (insert_fail); rồi dịch lịch sử 3 token.

### Bốn map

| Map | Khai báo | Nội dung |
|---|---|---|
| `pulse_cgroups` | `pulse_counter.bpf.c` | allow-list + bộ đếm theo cgroup (nhánh cũ) |
| `pulse_last_syscall` | `pulse_counter.bpf.c` | trạng thái thread: cgroup, thời điểm, syscall, `tok[3]`, `tok_pending`, `lineage` |
| `pulse_grams` | `pulse_tokens.bpf.h` | 262.144 mục: (cgroup, cửa sổ, 4 token, dòng dõi) → số lần |
| `pulse_stats`, `pulse_tok_stats` | `pulse_counter.bpf.c`, `pulse_tokens.bpf.h` | lỗi chèn trạng thái / gram, đi cây quá sâu, tổng gram |

### Bố cục token 32 bit

`sentinel_pulse/ebpf/pulse_token_ids.h`: `PULSE_TOK_NR_SHIFT` 23, `PULSE_TOK_KIND_SHIFT` 21, `PULSE_TOK_KIND_ERR`,
`PULSE_TOK_KIND_SIZE`, `PULSE_TOK_KIND_OPEN`, `PULSE_TOK_OPEN_WRITE` (bit 20), `PULSE_TOK_DIR_MASK`,
`PULSE_TOK_DIR_ROOT`, `PULSE_TOK_DIR_REL`, `PULSE_TOK_DIR_UNKNOWN`, `PULSE_TOK_NONE` (`0xFFFFFFFF`).
Bên Python: `sentinel_pulse/detector/token_model.py` `call_of`, `strip`, `TOK_NONE`.

### Loader và đầu ra

- **Khởi động**: `pulse_counter_loader.c` `main`: kiểm layout map, đặt `.rodata.tokcfg`, nạp object, gắn 4 hook, nạp
  allow-list; lỗi thì dừng.
- **Mỗi 0,5 s**: `print_snapshots` → `cgroup_snapshot_extended`; `drain_grams` → `token_grams` (có `session_events`,
  `session`); `window_end` = (W + 1) × 0,5 s + lệch giữa đồng hồ thực và monotonic (D2); dòng `token_drain` có
  `insert_fail_cumulative`; `stat`; `snapshot_end`.
- **Proof**: `scripts/token_probe_proof.py`: trong cgroup cô lập, tổng sự kiện token = tổng `full_counts` (bản final:
  361.900 / 442.796 / 393.644 trên 3 worker), token mẫu đúng, đường seccomp đúng.

---

## Trang 3. Worker và mô hình token

### Dòng `token_grams` từ loader

Worker đọc stdout của loader theo khối, tách dòng, gom tới `snapshot_end`
(`sentinel_pulse/pipeline/matched_worker.py` `run`, biến `token_pending`).

### `token_window`

`sentinel_pulse/collector/token_capture.py`: `token_window` (kiểm contract, gắn danh tính), `check_grams` (mỗi gram 4
token + số đếm > 0, ô trống chỉ ở đầu, tổng = `events`), `check_session` (phần session là tập con). Cgroup ngoài
`production` → `None`. Dòng sai → `issues.jsonl`.

### Metadata resolver

`/run/sentinel-pulse/cgroups.json`; worker nạp lại khi file đổi mtime (`matched_worker.py` `run`, biến `metadata`).
`workload_key` = `namespace/controller:container`: `sentinel_pulse/collector/capture.py` `workload_key`.

### CountTokenLM của workload

`sentinel_pulse/detector/token_model.py` `CountTokenLM`:

- `learn`, `learn_window`: cộng số đếm vào `count[k][h][w]`, `names`, `given`, `total`;
- `finalize`: tính sẵn `stats` (c(h), T(h)), `unseen_given`, `given_total`;
- `base`: P0(w) = P(tên) × P(biến thể | tên), cộng ½;
- `prob`: Witten–Bell nội suy k = 1, 2, 3 (có `memo`);
- `save`, `load`, `to_json`, `from_json`: file `<hash>.lm.json.gz`.

Cùng số học với bản offline `scripts/analysis/lidds_ml_tokens.py` `TokenLM` (test `tests/test_token_model.py`).

### Điểm cửa sổ

`CountTokenLM.window_score(grams, top)`: −ln p của từng gram lặp theo số lần, trung bình `top` giá trị lớn nhất;
`top` = `default_top` (đọc từ `MODELS.json`, t3: 3). Ví dụ lượt cuối: tấn công `child_ptrace_handshake` trong
catalog-service, s(W) = 40,50 > τ = 19,30.

### TokenBranch

`sentinel_pulse/detector/token_model.py` `TokenBranch`: `__init__` nạp `MODELS.json` (kiểm SHA-256 từng file mô hình,
đọc `top`, `threshold`); `score(window)` → `token_score`, `token_threshold`, `token_alert`. Nhánh `gate` (pool, exec hold)
là của protocol v5 đã loại, không bật.

### Decision

Dòng `status: token-score` do `matched_worker.py` `run` ghi (trường `candidate_alert_preview` = `token_alert`, cùng
`token_score`, `token_threshold`, `events`, `session_events`, và khi map đầy `token_alert_reason`, `token_incomplete`).

### NFS: segment 30 phút; đĩa local; ghi ngoài vòng chấm; khoá trước khi chấm

- Segment và niêm phong `TERMINAL.json`: `matched_worker.py` `run` (khối `finally`).
- Bản local: `stream_root` trong cấu hình worker.
- Ghi bất đồng bộ: `sentinel_pulse/pipeline/async_sink.py` `AsyncSink`, `AsyncState`.
- Khoá: `matched_worker.py` `run` (kernel, SHA-256 artifact, proof, `FROZEN_SCORER_FILES`), `TokenBranch.__init__`
  (SHA-256 mô hình).

### Học mô hình

`scripts/analysis/token_branch_fit.py`: `split`, `trial_spans`, `crossfit_one`, `fold_of`, `fit_crossfit`,
`trimmed_gumbel`; ngưỡng `threshold` và `gumbel` trong `scripts/analysis/lidds_ml_v2.py`. Kết quả lượt cuối:
`/mnt/sentinel-pulse-archive/pulse-live-v7-fit-1118/token/` (`MODELS.json`, `FIT.json`, `*.lm.json.gz`).

---

## Trang 4. Cảnh báo và RCA

### Worker ×3

Chỉ dòng `"candidate_alert_preview":true` rời worker: bridge chạy một chương trình Python nhỏ (`FOLLOWER` trong
`sentinel_pulse/ops/alert_bridge.py`) qua `sshpass ssh` trên từng worker, bám file decision local mới nhất.

### Alert bridge

`sentinel_pulse/ops/alert_bridge.py`:

| Việc trong hình | Code |
|---|---|
| bám log decision qua SSH | `Streams` (xoay kết nối mỗi `rotate_seconds`), `FOLLOWER`, `newest` |
| gom đợt theo (pod_uid, container) | `Bridge.ingest` (khoá `identity` và mã `case_id` từ `sentinel_pulse/rca/tree.py`) |
| hết đợt khi im lặng, làm mới alert | `Bridge.tick` |
| push `POST /api/v2/alerts` | `push_worker`, `Bridge.alert`, `Bridge.labels` |
| hàng đợi bền (D3) | `PushQueue` (`push-queue.jsonl`), `backoff`; `PUSH_BACKOFF_MAX` 30 s, `PUSH_MAX_AGE` 1 giờ |
| nhãn `stream` | `stream_of` |
| đường pull để so độ trễ | `Bridge.metrics` (gauge `sentinel_pulse_preview_active`) |
| webhook, `deliveries.jsonl`, `triggers.jsonl` | `Bridge.webhook`, `serve` |
| gắn chú thích RCA, alert triage | `Bridge.attach_cases`, `Bridge.triage_alert` |

### Alertmanager, route theo `notify`, người vận hành, Grafana

`testbed/k8s/monitoring/sentinel-pulse-alerting.yaml` (route `immediate` → webhook `/alertmanager/notify` của bridge,
`Bridge.notification`; `dashboard` → chỉ dashboard), `testbed/k8s/monitoring/sentinel-pulse-dashboard.json`.

### 3 policy Tetragon

`sentinel_pulse/k8s/tetragon-rca-runtime-policy.yaml` (runtime + fork), `sentinel_pulse/k8s/tetragon-rca-flow-policy.yaml`
(flow), `testbed/k8s/tetragon-sentinel-pulse-exec-provenance.yaml`.

### Subscriber

`sentinel_pulse/rca/service.py` `Service.start_stream`, `drain_streams`, `ingest_event`, `stop_stream`; chuẩn hoá sự
kiện: `sentinel_pulse/rca/runtime_events.py` `normalize_runtime_event`, `sentinel_pulse/rca/connect.py`; ring SQLite:
`database`.

### Dựng case

`sentinel_pulse/rca/service.py` `Service.tail_alert_triggers` (đọc `triggers.jsonl`), `observe_trigger`,
`follow_up_allowed`, `recheck_follow_ups`, `emit_cases`, `maintenance`; cây: `sentinel_pulse/rca/runtime_tree.py`
`build_runtime_tree`, `sentinel_pulse/rca/tree.py` `build_tree`.

### Xếp hạng nghi phạm

`sentinel_pulse/rca/ranking.py` `rank_suspects` (điểm +4, +3, +2, +2, +1, +1 như hình), `is_privilege_drop_at_start`,
`is_container_runtime`, `started` (phá hoà theo thời điểm khởi chạy); mốc baseline: `sentinel_pulse/rca/baseline_seed.py`.

### Triage

`sentinel_pulse/rca/triage.py` `triage`, `probe_entries`; phân loại hiển thị: `sentinel_pulse/ops/rca_view.py`
`classify`, `summarize`, `alert_annotations`.

### Đầu ra của case

`<case_id>.json`, `.md` (`sentinel_pulse/rca/runtime_tree.py` `render_runtime_markdown`), `.svg`
(`sentinel_pulse/ops/rca_view.py` `case_svg`); trang `/cases` (`render_index`, `render_html`).

---

## Trang 5. Học và đánh giá

### Hàng trên: sáu bước

| Bước | Code | Protocol / biên nhận |
|---|---|---|
| LID-DS 2021 development + CB-DS | `scripts/analysis/lidds_ml_token_alphabets.py`, `lidds_ml_token_crossfit.py`, `lidds_ml_v5.py` | `sentinel_pulse/protocol/lidds-ml-v5*.json` |
| LID-DS 2021 official | như trên (chấm một ứng viên); t3: `scripts/lidds2019_amendment1_run.sh` | `validation-evidence/results-20261118/lidds2019-development/official2021.json` |
| LID-DS 2019 | `scripts/analysis/lidds2019_dev.py` (`split`, `gate`, `study`, `grid`, `official`, `holdout`) | `sentinel_pulse/protocol/lidds2019-development-v1*.json`; `validation-evidence/results-20261118/lidds2019-development/` |
| Thu normal + fit trên cụm | `scripts/launch_run.sh traffic`, `scripts/analysis/token_branch_fit.py` | `/mnt/sentinel-pulse-archive/pulse-token-capture-v6-1116/`, `/mnt/sentinel-pulse-archive/pulse-live-v7-fit-1118/` |
| Lượt live v4–v6 | `scripts/launch_run.sh all`, `scripts/analysis/pulse_live_v4.py` | `validation-evidence/results-20261118/pulse-live-v6-1117/` |
| Lượt live cuối | như trên, `REHEARSAL=1` trước | `sentinel_pulse/protocol/pulse-live-final-v1.json`; `validation-evidence/results-20261119/final-rehearsal/` |

### Offline

- Chuyển đổi và chấm: `sentinel_pulse/lidds/` (`convert.py`), các script `scripts/analysis/lidds_*.py`.
- Ngưỡng: `scripts/analysis/lidds_ml_v4.py` `trimmed_gumbel`, `scripts/analysis/lidds_ml_v2.py` `gumbel`, `threshold`.
- Kiểm thêm (development) và overhead probe: biên nhận trong `validation-evidence/` theo ngày; đo overhead:
  `scripts/overhead_ab.sh`, `scripts/app_overhead_ab.py` (D7).

### Trên cụm

- Planner: `sentinel_pulse/pipeline/plan_matched_run.py` (cờ `--token-build`, `--token-models`, `--admin-control`,
  `--on-off`, `--eventgen`, `--rehearsal`); launcher `scripts/launch_run.sh`.
- Fit trước lượt live: `scripts/analysis/token_branch_fit.py` (`--extra-run`, `--top`, `--trim`).
- Chấm lượt live: `scripts/analysis/pulse_live_v4.py` (`load_trials`, `read_decisions`, `trial_table`, `trial_metrics`,
  `burden`), `scripts/analysis/native_stream.py`, `scripts/analysis/live_attribution.py`,
  `scripts/analysis/burden_context.py`, `scripts/analysis/rca_coverage.py`.
- Gate cho binary vô hại (đã loại): `TokenBranch` nhánh `gate`, `token_branch_fit.py` `merge_models`,
  `fit_pool_threshold`.

### Bằng chứng và tài liệu

- Protocol: `sentinel_pulse/protocol/*.json`.
- Biên nhận: `validation-evidence/results-YYYYMMDD/`.
- Audit số liệu: `scripts/audit/headline_numbers.py`.
- Đồ án: `thesis/` (tectonic); paper: `paper/latex/` (pdflatex); báo cáo, slide: `docs/`.
- Ghi chép: `notes/STATE.md`, `notes/WORKLOG.md`; luồng code và lệnh: `docs/LUONG_CODE.md`.
