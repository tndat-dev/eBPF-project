# Hướng dẫn đọc code — hiểu đồ án từ gốc (15/11/2026)

File này là **đường đọc code**: nếu muốn hiểu tường tận hệ thống bằng cách đọc mã nguồn thì đọc theo thứ tự nào, mỗi
file làm gì, và chúng nối với nhau ra sao. Khác với [DOCS_INDEX.md](../DOCS_INDEX.md) (điều hướng *tài liệu*) và
[README.md](../README.md) (từ con số trong báo cáo → biên nhận). Mọi đường dẫn tính từ gốc repo.

---

## 0. Đồ án là gì (một đoạn)

Một hệ **phát hiện xâm nhập runtime** cho Kubernetes: một **probe eBPF** đếm *token syscall* của mỗi tiến trình theo
cửa sổ 0,5 s; một **mô hình ngôn ngữ token** (n-gram học từ hành vi *bình thường*) chấm mỗi cửa sổ; cửa sổ nào "lạ" quá
ngưỡng thì báo động. Mục tiêu: bắt **tấn công blind** (chưa từng thấy) chỉ bằng việc học normal, với recall ≥ 95%,
precision ≥ 95%, p95 kernel→alert ≤ 3 s, và càng ít gắn cờ nhầm hành vi hợp lệ càng tốt. Hệ được **chọn và đo offline
trên LID-DS 2021 + CB-DS**, rồi **validate live trên cụm** (fixture tổng hợp). Luật (rule) chỉ thêm
*sau khi* ML chốt, để so sánh có/không có luật.

Hai câu hỏi lớn xuyên suốt code: **(1) mô hình học-từ-normal có bắt được tấn công không?** và **(2) nó có gắn cờ nhầm
hành vi hợp lệ không?** Gần như mọi file phục vụ một trong hai câu đó.

---

## 1. Đọc theo thứ tự này (xương sống)

Bảy chặng, mỗi chặng một câu hỏi. Đọc đúng thứ tự thì mỗi file sau đều dựa trên file trước.

| # | Câu hỏi | Đọc |
|---|---|---|
| 1 | Hiện trạng & vì sao | [notes/STATE.md](STATE.md), [notes/PAPER_PLAN.md](PAPER_PLAN.md) (các điểm yếu W1–W8), [README.md](../README.md) |
| 2 | **Đơn vị dữ liệu**: "token window" là gì? | `sentinel_pulse/ebpf/pulse_counter.bpf.c`, `sentinel_pulse/ebpf/pulse_token_ids.h` → `sentinel_pulse/collector/token_capture.py` |
| 3 | **Mô hình** chấm điểm thế nào? | `sentinel_pulse/detector/token_model.py` (CountTokenLM) |
| 4 | **Chọn & đặt ngưỡng** mô hình (offline) | `scripts/analysis/lidds_token_study.py` → `scripts/analysis/lidds_ml_v5.py` → biên nhận `validation-evidence/results-20261110/lidds-ml-v5/` |
| 5 | **Chạy online** trên cụm (kernel→alert) | `sentinel_pulse/collector/cgroup_resolver.py` → `sentinel_pulse/pipeline/matched_worker.py` → `sentinel_pulse/ops/alert_bridge.py` |
| 6 | **Validate live** | `scripts/analysis/pulse_live_v4.py` + `live_attribution.py` (campaign tổng hợp operator bơm trial). |
| 7 | **Luật & RCA** (thêm sau ML) | `scripts/analysis/rule_e_benefit.py`, `sentinel_pulse/rca/` |

Muốn hiểu nhanh "hệ làm gì" mà chưa cần chi tiết: đọc chặng 1–3 là đủ khung. Muốn tái lập số liệu paper: 4 và 6.

---

## 2. Bản đồ thư mục

| Thư mục | Vai trò |
|---|---|
| `sentinel_pulse/ebpf/` | **Probe eBPF** (C): đếm token syscall theo cửa sổ. `pulse_counter.bpf.c` + `pulse_tokens.bpf.h` + `pulse_token_ids.h`; loader `pulse_counter_loader.c`; `Makefile` (`make tokens`). |
| `sentinel_pulse/collector/` | Từ dòng loader → **cửa sổ token có danh tính**: `token_capture.py` (parse), `cgroup_resolver.py` (cgroup→pod, không cần RBAC), `capture.py`/`extended_capture.py`/`features.py` (feature stream cũ), `telemetry_recovery.py`. |
| `sentinel_pulse/detector/` | **Mô hình**: `token_model.py` (nhánh token — *đường cảnh báo hiện tại*), `support_model.py`+`fast_forest.py` (cây+support — *shadow*), `candidate_policy.py`/`v3_policy.py` (quyết định), `novelty.py`, `recalibration.py`. |
| `sentinel_pulse/pipeline/` | **Chạy online**: `matched_worker.py` (capture 500 ms + chấm candidate), `async_sink.py`, `live_recalibration.py`, `retention.py`, `matched_{services,traffic}.py`. |
| `sentinel_pulse/ops/` | `alert_bridge.py` (kernel→Alertmanager, đo độ trễ giao alert), `rca_view.py`. |
| `sentinel_pulse/rca/` | **Root-cause** (W7): `ranking.py`, `runtime_tree.py`, `runtime_events.py`, `triage.py`, `service.py`. |
| `sentinel_pulse/rules/` | `tripwire.py` — khung luật cũ, nay giữ *shadow* (ML là chính). |
| `sentinel_pulse/lidds/` | Nạp dataset: `convert.py` (LID-DS→recordings), `cbds.py` (CB-DS), `lidds2019.py`, `signals.py`. |
| `sentinel_pulse/attack/` | Campaign tấn công tổng hợp trên cụm: `cluster.py`, `preview_*.py`, `confirmation_study.py`, `rolling_recalibration.py`. |
| `sentinel_pulse/protocol/` | **Protocol đăng-ký-trước** (JSON): định nghĩa thí nghiệm *trước khi* chạy. Xem §7. |
| `scripts/analysis/` | **Toàn bộ nghiên cứu offline + live** (Python, mỗi file một thí nghiệm). Xem §4, §6. |
| `scripts/audit/` | Kiểm toán số: `headline_numbers.py` (tính lại số chủ chốt từ biên nhận, chạy trong test). |
| `validation-evidence/results-YYYYMMDD/<study>/` | **Biên nhận**: README + JSON cho mỗi lần chạy. Mọi con số trong đồ án truy về đây. |
| `notes/` | `STATE.md` (hiện trạng), `WORKLOG.md` (nhật ký), `PAPER_PLAN.md` (W1–W8), `RESEARCH_NOTES.md`, `CODE_AUDIT.md`. |
| `thesis/` | Luận văn LaTeX (`main.tex` + `chapters/`); số liệu lấy từ biên nhận. |
| `tests/` | ~548 test; chốt tính đúng (ví dụ `test_token_model.py` kiểm CountTokenLM = TokenLM offline). |

---

## 3. Luồng dữ liệu kernel → alert (chặng 2–5 chi tiết)

```
syscall  ──►  eBPF probe        ──►  loader in "token_grams"  ──►  token_capture.py  ──►  CountTokenLM.score
(kernel)      pulse_counter.bpf.c     mỗi (cgroup, cửa sổ 0,5s)     cửa sổ token + danh     điểm = trung bình top-10
              đếm 4-gram token         distinct 4-gram + count       tính (pod/container)    (−ln p) mỗi cửa sổ
                                                     │                                              │
                                        cgroup_resolver.py (cgroup→pod)              ngưỡng Gumbel (token_branch_fit)
                                                     │                                              │
                                        pipeline/matched_worker.py  ──────────────►  vượt ngưỡng → alert_bridge.py → Alertmanager
```

- **Token là gì:** một số nguyên 32-bit. Số syscall = `tok >> 23`; các bit còn lại mã hoá errno / bucket log2 cỡ
  đọc-ghi / chế độ mở + thư mục đầu (bảng chữ **select1f**). Định nghĩa: `sentinel_pulse/ebpf/pulse_token_ids.h`,
  `pulse_tokens.bpf.h`. Probe gom theo **4-gram mỗi thread** trong **cửa sổ 0,5 s**, gửi *một count cho mỗi (cgroup,
  cửa sổ, gram) phân biệt* — nên "gram thấy c lần" cộng c (khớp c lần `learn`, xem `tests/test_token_model.py`).
- **token_capture.py:** đọc dòng `token_grams`, gắn danh tính (workload_key, pod, container, revision), bỏ cgroup
  ngoài namespace production. CONTRACT `pulse-token-select1f-v1`, `TOK_NONE=0xFFFFFFFF` (slot thread-start).
- **token_model.py (CountTokenLM):** mô hình ngôn ngữ — 4-gram theo thread, backoff **Witten-Bell** xuống
  P(name)×P(token|name), add-half; call lạ chấm bằng xác suất token-lạ trung bình. **Điểm một cửa sổ = trung bình
  của TOP (10) −log p lớn nhất** (event tính theo bội). Đây là trái tim phát hiện — đọc kỹ file này nhất.
- **cgroup_resolver.py:** chạy root mỗi node, map cgroup→pod bằng CRI + quét cgroup v2, *không* cần RBAC cho detector.
- **matched_worker.py:** vòng chạy online 500 ms, chấm candidate đã đóng băng.
- **alert_bridge.py:** đẩy alert tới Alertmanager, đo độ trễ kernel→giao-alert.

---

## 4. Nhánh nghiên cứu offline — chọn & chốt mô hình (chặng 4)

Đây là nơi quyết định mô hình nào được dùng, trên **LID-DS 2021 (development → official) + CB-DS**. Đọc theo:

1. **`scripts/analysis/lidds_token_study.py` — file lõi.** Chứa `base_spec()` (bảng chữ select1f, n=4, số fold),
   `token_map`, `score_scenario` (điểm top10 mỗi cửa sổ), `TokenScenario`, và **harness `m`** (`m.load`, `m.score`,
   ngưỡng, Gumbel theo moment, bootstrap theo workload). Hầu hết file khác *import* `lidds_token_study as st`.
2. **`lidds_token_cache.py`** — dựng **gram cache** (`<rec>/w|g|c` + `vocab`) từ dataset đã convert; đây là input mà
   `lidds_token_study`/`lidds_token_rate` đọc (ở `.234:/var/tmp/lid-ds-2021/token-study/cache`).
3. **`lidds_ml_v5.py`** (và `lidds_ml_v4.py`) — lần chọn-và-chấm chính thức tạo ra con số official **97,40% / FA
   0,33%**. Biên nhận `validation-evidence/results-20261110/lidds-ml-v5/` (official + development JSON).
4. Phụ trợ chọn bảng chữ / cross-fit / pool: `lidds_ml_token_alphabets.py`, `lidds_ml_token_crossfit.py`,
   `lidds_ml_token_variants.py`, `lidds_ml_token_pool.py`, `lidds_ml_token_inventory.py`, `lidds_ml_tokens.py`.
5. Nhánh cây + support (shadow): `lidds_ml_scores.py`; bản cũ `lidds_ml_v2.py`.
6. **Kiểm kê cảnh báo per-recording:** `lidds_evaluate_v2.py` → `*-alarms.json.gz` (mỗi recording: split/subset/
   exploit/arms). Đây là "alarms inventory" nhiều phân tích khác dùng lại.
7. **Fit ngưỡng cho cụm:** `token_branch_fit.py` (5-fold cross-fit theo chunk 30’, cực đại block 60 s, Gumbel moment
   bỏ 1% cao nhất, α'=0,00018) — fit này dùng chung cho các lượt live.
8. **W3(b) nhánh tần suất:** `lidds_token_rate.py` (import `st`) — so ML-only vs ML+nhánh rate; biên nhận
   `results-20261115/w3b-rate-signal/` (kết quả âm: nhánh rate thêm 0 phát hiện).

> Lịch sử phiên bản mô hình (đọc để hiểu vì sao v5): v1 65% (âm) → v2 95,99% → v3 97,32% → v4 97,40% (3 nhánh) →
> **v5 97,40% token-đơn** (bỏ cây+support khỏi đường cảnh báo nên FA 36→26). Chi tiết trong [STATE.md](STATE.md) mục
> "Hệ thống hiện tại".

---

## 5. Nhánh validate live (chặng 6)

Campaign tổng hợp trên cụm — operator bơm trial có kiểm soát (control / benign / admin / attack) vào pod đang chạy (xem
[STATE.md](STATE.md)):
- `scripts/analysis/pulse_live_v4.py` — định nghĩa trial (`load_trials`), `CAMPAIGN`, `HORIZON`, `PRIMARY` (nhịp
  tấn công primary), các arm chấm. *File này được import như `live` bởi các file dưới.*
- `live_attribution.py` — **W-part A**: tách recall live là do burst khởi chạy hay hành vi tấn công; dùng
  `CountTokenLM` + `flagged()`.
- `rule_e_benefit.py` — **part E (luật sau ML)**: R1 (hạ cảnh báo khi chỉ exec tool-của-image), R2 (drift). Phát khối
  `comparison` tách **ML-only vs ML+rule**; biên nhận `results-20261115/rule-e-benefit/`.
- `session_model.py` — mô hình phiên / thẻ dòng dõi (native/session, amendment 2).

---

## 6. Khái niệm then chốt (từ điển để đọc code không lạc)

- **Bảng chữ select1f:** token = syscall + (errno của 27 syscall gồm futex / bucket log2 cỡ đọc-ghi không chia đôi /
  chế độ mở + thư mục đầu). Mã trong `pulse_token_ids.h`; chọn trong `lidds_ml_token_alphabets.py`.
- **4-gram theo thread, Witten-Bell:** mô hình ngôn ngữ trên chuỗi token mỗi thread; backoff nội suy.
- **Điểm cửa sổ = trung bình top-10 (−ln p):** cửa sổ càng chứa chuỗi hiếm càng điểm cao. Trong `token_model.py` và
  `lidds_token_study.score_scenario`.
- **Ngưỡng Gumbel (moment, bỏ 1% cao nhất):** đặt trên cực đại điểm của bản ghi/khối giữ-ra cross-fit; một cửa sổ vượt
  ngưỡng là báo. α=0,0002 chia token 0,9 / cây 0,05 / support 0,05 → token **α'=0,00018**.
- **Đường cảnh báo = chỉ nhánh token** (từ v5): cây + support giữ *shadow* (phân tích, không báo). Xem memory
  "ml-is-the-focus-keep-tree-support".
- **Thẻ dòng dõi native/session** (amendment 2): probe gắn thread là luồng gốc của app (native) hay phiên admin
  (session); cảnh báo đúng phải nổ trên native.
- **W1–W8** ([PAPER_PLAN.md](PAPER_PLAN.md)): các điểm yếu cần đóng — W1 gắn cờ hành vi hợp lệ/lineage, W3 né tránh
  (W3a pha loãng / W3b nhánh tần suất), W4 baseline, W6 chi phí, W7 thứ tự RCA, W8 ngưỡng. Mỗi lượt chạy ghi rõ nó
  đóng W nào.

---

## 7. Protocol, biên nhận, test — vì sao tin được số

- **Protocol đăng-ký-trước** `sentinel_pulse/protocol/*.json`: định nghĩa thí nghiệm (mô hình, bảng chữ, ngưỡng, tiêu
  chí đạt) *trước khi* chạy, có `registered_at` / `registered_before`. Ví dụ `lidds-ml-v5.json`, `ml-final-study-v1.json`
  (+ amendment 1/2/3). Sửa thiết kế = thêm amendment, không sửa bản gốc.
- **Biên nhận** `validation-evidence/results-YYYYMMDD/<study>/`: mỗi lần chạy một thư mục, README giải thích + JSON số
  thô + lệnh tái lập. Đồ án/paper chỉ trích số từ đây.
- **Kiểm toán** `scripts/audit/headline_numbers.py` chạy trong test: tính lại số chủ chốt từ biên nhận để không lệch
  giữa báo cáo và dữ liệu. `notes/CODE_AUDIT.md` ghi lần rà soát codebase (tag `archive/pre-audit-20261110`).
- **Test** `tests/`: ví dụ `test_token_model.py` chốt CountTokenLM online = TokenLM offline (cùng số học).

---

## 8. Tái lập một con số (ví dụ)

- **Official LID-DS 2021 của v5** (97,40%): xem `validation-evidence/results-20261110/lidds-ml-v5/README.md` → lệnh
  chạy `lidds_ml_v5.py` trên cache `.234:/var/tmp/lid-ds-2021/...`.
- **ML-only vs ML+rule** (báo nhầm admin 0,977→0): `results-20261115/rule-e-benefit/README.md` → `rule_e_benefit.py`.
- **W3(b) nhánh tần suất** (âm): `results-20261115/w3b-rate-signal/README.md` → `lidds_token_rate.py`.

---

### Đọc tối thiểu nếu chỉ có 30 phút
`notes/STATE.md` (hiện trạng) → `sentinel_pulse/detector/token_model.py` (mô hình) → `scripts/analysis/lidds_token_study.py`
(chọn & ngưỡng) → một biên nhận trong `validation-evidence/results-20261110/lidds-ml-v5/`. Bốn file đó cho khung đầy đủ:
dữ liệu gì, mô hình gì, chọn thế nào, kết quả ra sao.
