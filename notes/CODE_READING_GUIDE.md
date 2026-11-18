# Hướng dẫn đọc code — hiểu đồ án từ gốc (cập nhật 18/11/2026)

File này là **đường đọc code**: muốn hiểu tường tận hệ thống bằng cách đọc mã nguồn thì đọc theo thứ tự nào, mỗi file
làm gì, chúng nối với nhau ra sao. Khác với [DOCS_INDEX.md](../DOCS_INDEX.md) (điều hướng *tài liệu*) và
[README.md](../README.md) (từ con số trong báo cáo → biên nhận). Mọi đường dẫn tính từ gốc repo.

**Chú thích tiếng Việt trong code:** các đoạn chú thích tiếng Việt (C: `/* ... */`, Python và shell: `# ...`) được
thêm để đọc code; chúng không đổi logic (mỗi đợt được kiểm bằng so sánh AST / so code đã bỏ chú thích). Chú thích tiếng
Anh gốc giữ nguyên. Mức chú thích từng phần ở §10.

---

## 0. Đồ án là gì (một đoạn)

Một hệ **phát hiện xâm nhập runtime** cho Kubernetes: một **probe eBPF** biến mỗi syscall của container thành một
*token* 32 bit (tên + mã lỗi / cỡ đọc-ghi / thư mục đầu) và đếm **4-gram token theo thread** trong cửa sổ 0,5 s; một
**mô hình ngôn ngữ đếm** (học chỉ từ hành vi *bình thường*) chấm mỗi cửa sổ; cửa sổ vượt ngưỡng thì báo, cảnh báo được
đẩy thẳng tới Alertmanager và RCA dựng cây bằng chứng. Mục tiêu: recall ≥ 95%, precision ≥ 95%, p95 kernel→alert ≤ 3 s,
và càng ít gắn cờ nhầm hành vi hợp lệ càng tốt. Hệ được **chọn và đo offline trên LID-DS 2021 + CB-DS**, rồi **chạy live
blind trên cụm** (fixture tự viết, không exploit CVE). Luật (rule) chỉ thêm *sau khi* ML chốt, để so có/không có luật.

Hai câu hỏi lớn xuyên suốt code: **(1) mô hình học-từ-normal có bắt được tấn công không?** và **(2) nó có gắn cờ nhầm
hành vi hợp lệ không?** Gần như mọi file phục vụ một trong hai câu đó.

---

## 1. Đọc theo thứ tự này (xương sống)

| # | Câu hỏi | Đọc |
|---|---|---|
| 1 | Hiện trạng & vì sao | [notes/STATE.md](STATE.md), [notes/PAPER_PLAN.md](PAPER_PLAN.md) (W1–W8), [README.md](../README.md) |
| 2 | **Token sinh ra thế nào?** (kernel) | `sentinel_pulse/ebpf/pulse_token_ids.h` (bảng chữ, bố cục 32 bit) → `pulse_counter.bpf.c` (hook sys_enter, lọc cgroup) → `pulse_tokens.bpf.h` (token lúc trả về, 4-gram, thư mục đầu, dòng dõi, hook fork) |
| 3 | **Token lên user space thế nào?** | `sentinel_pulse/ebpf/pulse_counter_loader.c` (`drain_grams`: dòng `token_grams` mỗi (cgroup, cửa sổ), có phần `session`) → `sentinel_pulse/collector/token_capture.py` (kiểm tra dòng, gắn danh tính pod/container) |
| 4 | **Mô hình chấm điểm thế nào?** | `sentinel_pulse/detector/token_model.py` (`CountTokenLM`: Witten–Bell, top-10; `TokenBranch`: nạp mô hình + ngưỡng, chấm một cửa sổ) — **file quan trọng nhất** |
| 5 | **Học mô hình & đặt ngưỡng** | Dataset: `scripts/analysis/lidds_ml_token_crossfit.py` → `lidds_ml_v5.py`. Cụm: `scripts/analysis/token_branch_fit.py` |
| 6 | **Chạy một lượt live** | `scripts/launch_run.sh` → `sentinel_pulse/pipeline/plan_matched_run.py` (CONFIG.json) → `pipeline/matched_worker.py` (mỗi node) → `ops/alert_bridge.py` → `rca/service.py`; campaign: `attack/preview_campaign.py` + fixture `testbed/attack/runtime_attack_with_benign_control.c` |
| 7 | **Phân tích lượt live** | `scripts/analysis/pulse_live_v4.py` → `live_attribution.py`, `native_stream.py`, `rule_e_benefit.py`, `rca_coverage.py` |
| 8 | **Luật & RCA** (sau ML) | `scripts/analysis/rule_e_benefit.py` (R1/R2), `sentinel_pulse/rca/` |

Hiểu nhanh "hệ làm gì": chặng 1–4. Tái lập số liệu: chặng 5 và 7 cùng §8.

---

## 2. Bản đồ thư mục

| Thư mục | Vai trò |
|---|---|
| `sentinel_pulse/ebpf/` | **Probe eBPF** (C). Kernel: `pulse_counter.bpf.c` (hook sys_enter, fexit seccomp, map allow-list + bộ đếm cũ), `pulse_tokens.bpf.h` (probe token: sys_exit, 4-gram, dòng dõi, fork), `pulse_token_ids.h` (bảng chữ select1f, 39 syscall có hook, bố cục token, khoá gram), `pulse_counter_ids.h` + `pulse_counter_projection.h` (bộ đếm syscall của mô hình đếm cũ, nay shadow). User space: `pulse_counter_loader.c`. `Makefile` (`make tokens`). `visibility_probe*.c`, `seccomp_fixture.c`: fixture kiểm tra probe. |
| `sentinel_pulse/collector/` | Từ dòng loader → bản ghi có danh tính: `token_capture.py` (cửa sổ token), `cgroup_resolver.py` (cgroup→pod, chạy root mỗi node, không cần RBAC), `capture.py` (danh tính workload, namespace được theo dõi), `features.py`/`extended_capture.py` (vector đếm của mô hình cũ), `telemetry_recovery.py`. |
| `sentinel_pulse/detector/` | **Mô hình**: `token_model.py` (nhánh token — *đường cảnh báo hiện tại*). Shadow/cũ: `v3_policy.py` (ngưỡng nhánh đếm), `model.py`, `support_model.py`, `fast_forest.py`, `candidate_policy.py`, `candidate_shadow.py`, `idle_*.py`, `novelty.py`, `recalibration.py`, `confirmation.py`. |
| `sentinel_pulse/pipeline/` | **Chạy online**: `plan_matched_run.py` (dựng CONFIG.json của một lượt), `matched_worker.py` (vòng 0,5 s mỗi node: chạy loader, ghi tokens/decisions, chấm), `matched_services.py` (tạo unit systemd), `matched_traffic.py` (đổi chế độ tải), `async_sink.py` (ghi NFS ngoài vòng chấm), `retention.py`, `live_recalibration.py`. |
| `sentinel_pulse/attack/` | **Campaign trên cụm**: `preview_campaign.py` (mỗi trial: control → lệnh quản trị / binary vô hại / tấn công / lotl theo thứ tự có seed; pha loãng PAD), `preview_target.py` (đưa binary vào container), `preview_evaluation.py`, `tetragon_evidence.py` (sự kiện exec để đo độ trễ). Cũ: `cluster.py`, `confirmation_study.py`, `rolling_recalibration.py`, `window_table.py`. |
| `sentinel_pulse/ops/` | `alert_bridge.py` (đọc decision trên đĩa local của worker → đẩy Alertmanager, đo độ trễ), `rca_view.py`. |
| `sentinel_pulse/rca/` | **RCA**: `service.py` (mở case cho mỗi alert đã giao, recheck sau 2 s), `runtime_events.py`/`runtime_tree.py`/`tree.py` (cây process từ Tetragon), `ranking.py` (xếp nghi phạm), `connect.py`, `triage.py`, `audit_cases.py`, `baseline_seed.py`, `evaluate_ranking.py`. |
| `sentinel_pulse/lidds/` | Dataset: `convert.py` (LID-DS → bản ghi), `cbds.py` (CB-DS), `lidds2019.py` (2019 → bố cục 2021), `signals.py`. |
| `sentinel_pulse/rules/` | `tripwire.py` — luật cũ, giữ shadow. |
| `sentinel_pulse/syscall_study/` | Nghiên cứu đặc trưng của mô hình đếm cũ (lịch sử, không ở đường cảnh báo). |
| `sentinel_pulse/protocol/` | **Protocol đăng-ký-trước** (JSON). Xem §7. |
| `testbed/` | `attack/runtime_attack_with_benign_control.c` (5 fixture tấn công + chế độ vô hại + PAD pha loãng), `bench/syscall_bench.c` (đo chi phí), `bench/gram_stress.c` (đo sức chứa map), `traffic/set_aims_traffic_regime.sh` (chế độ tải). |
| `scripts/` | Vận hành và đo: `launch_run.sh` (khởi chạy lượt live), `token_probe_proof.py`, `lineage_probe_proof.py` (proof của build), `overhead_ab.sh` (chi phí A/B), `map_capacity_test.py`. |
| `scripts/analysis/` | **Nghiên cứu offline + phân tích live** (mỗi file một thí nghiệm). Xem §4, §5. |
| `scripts/audit/` | `headline_numbers.py` (tính lại mọi số chủ chốt của đồ án từ biên nhận; chạy trong test). |
| `validation-evidence/results-YYYYMMDD/<study>/` | **Biên nhận**: README + JSON mỗi lần chạy. Mọi con số truy về đây. |
| `thesis/` | Đồ án LaTeX (`main.tex` + `chapters/`), build bằng tectonic. |
| `paper/` | Paper USENIX Security '27 (quy trình PaperOrchestra): `raw_materials/`, `outline.json`, `literature/`, `latex/`, `tools/`. Xem `paper/README.md`. |
| `notes/` | `STATE.md`, `WORKLOG.md`, `PAPER_PLAN.md`, `RESEARCH_NOTES.md`, `CODE_AUDIT.md`, file này. |
| `tests/` | 586 test (18/11); ví dụ `test_token_model.py` chốt CountTokenLM trên cụm = TokenLM offline. |

---

## 3. Luồng dữ liệu kernel → alert

```
syscall ─► pulse_counter.bpf.c ─► pulse_tokens.bpf.h ─► map pulse_grams ─► loader drain_grams ─► matched_worker
(kernel)   sys_enter: lọc cgroup   token (lúc vào hoặc     (cgroup, cửa sổ,    mỗi 0,5 s: dòng       token_capture.token_window
           đếm syscall (shadow)    sys_exit), 4-gram       4 token, dòng dõi)  "token_grams" JSON    → TokenBranch.score (token_model)
                                   theo thread                                  + "session"          → vượt ngưỡng: decision
                                                                                                          │
                                       cgroup_resolver.py ghi allow-list (cgroup cần theo dõi) ◄──────────┤
                                                                                                          ▼
                                       Alertmanager ◄── ops/alert_bridge.py (đọc decision trên đĩa local) ──► rca/service.py
```

- **Token:** số 32 bit. Số syscall = `tok >> 23`; bit 21–22 là loại (0 tên, 1 errno, 2 nhóm cỡ, 3 mở file); bit thấp là
  chi tiết. `0xFFFFFFFF` (TOK_NONE) = ô lịch sử trống ở đầu thread. Định nghĩa: `pulse_token_ids.h`.
- **Mỗi sự kiện đúng một 4-gram:** ở mỗi syscall, gram = 3 token trước của *chính thread đó* + token mới; kernel đếm
  (cgroup, cửa sổ, gram) nên gram lặp lại chỉ tăng số đếm. Dòng `token_grams` cho mỗi gram phân biệt một số đếm c, và
  "gram thấy c lần" = c lần `learn` (`tests/test_token_model.py`).
- **Thẻ dòng dõi:** khoá gram có trường `pad` = native(0)/session(1). Loader in `grams` (cả cửa sổ, hai dòng cộng lại —
  thứ được chấm) và `session` (phần session); native = grams − session (`scripts/analysis/native_stream.py`).
- **token_capture.py:** kiểm dòng (4 token + count, ô trống chỉ ở đầu), gắn danh tính, bỏ cgroup ngoài namespace
  được theo dõi. CONTRACT `pulse-token-select1f-v1`.
- **token_model.py:** `CountTokenLM` (P₀ add-½ theo tên × biến thể, Witten–Bell nội suy k=1..3, điểm = trung bình 10
  giá trị −ln P₃ lớn nhất, có bội) và `TokenBranch` (nạp MODELS.json đã khoá SHA-256, chấm một cửa sổ, so ngưỡng).
- **matched_worker.py:** mỗi node, chạy loader, tách dòng token/snapshot, ghi `tokens.jsonl`/`decisions.jsonl` theo
  segment (NFS qua `async_sink`, và bản local cho bridge/RCA), chấm cửa sổ token ngay khi đóng.
- **alert_bridge.py:** đẩy cảnh báo tới Alertmanager (không chờ Prometheus scrape); **rca/service.py** mở case.

---

## 4. Nhánh offline — chọn & chốt mô hình trên dataset

1. **Chuyển dataset:** `sentinel_pulse/lidds/convert.py` (LID-DS 2021), `cbds.py`, `lidds2019.py`.
2. **Ma trận điểm cross-fit (đường của con số official):** `scripts/analysis/lidds_ml_token_crossfit.py` — mỗi kịch
   bản: học training+validation, chia 5 fold theo sha256(tên), mỗi bản ghi giữ ra được chấm bằng mô hình 4 fold kia
   (`val/<tên>`), bản ghi test chấm bằng mô hình học hết. Token và điểm dùng `lidds_ml_token_alphabets.py` /
   `lidds_ml_tokens.py`.
3. **Chọn & chấm:** `lidds_ml_v4.py` (Gumbel moment bỏ 1% cao nhất, α×0,9) → **`lidds_ml_v5.py`** (chỉ token, thử gate
   rồi loại) → biên nhận `validation-evidence/results-20261110/lidds-ml-v5/` (official **97,40%**, 26/7.938 báo nhầm).
   Đánh giá dùng "alarms inventory" `validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz`
   (mỗi bản ghi: split, subset dev/official, thời điểm exploit) do `lidds_evaluate_v2.py` tạo.
4. **Nghiên cứu thiết kế (RQ2):** `lidds_token_cache.py` (cache "fact" mỗi syscall) → `lidds_token_study.py` (bộ khung:
   bảng chữ, bỏ-từng-syscall, tham số, quy tắc ngưỡng, mô hình vs luật) → biên nhận `results-20261112/token-design-study/`.
5. **Nhánh tần suất (âm):** `lidds_token_rate.py` → `results-20261115/w3b-rate-signal/`.
6. **LID-DS 2019 (chạy một lần):** `scripts/analysis/lidds2019_token.py` (gate tái lập official 2021 rồi chấm 2019) theo
   protocol `lidds2019-confirmation-v2`.
7. Lịch sử mô hình: v1 65% (âm) → v2 95,99% → v3 97,32% → v4 97,40% (3 nhánh) → **v5 97,40% chỉ token** (bỏ cây+support
   khỏi đường cảnh báo, báo nhầm 36→26).

---

## 5. Nhánh cụm — học, chạy, phân tích một lượt live

1. **Học trên cụm:** lượt thu normal 12 giờ (`launch_run.sh traffic` + `workers`) → `scripts/analysis/token_branch_fit.py`
   (cross-fit theo đoạn 30 phút, cực đại khối 60 s, Gumbel bỏ 1%, α′=0,00018; `--extra-run` học thêm normal của lượt
   trước ngoài trial) → `MODELS.json`. Nhánh đếm shadow: `count_branch_fit.py --shadow`.
2. **Kiểm build trước lượt:** `scripts/token_probe_proof.py` (mỗi syscall đúng một token), `lineage_probe_proof.py`.
3. **Khởi chạy:** `scripts/launch_run.sh plan|workers|rca|bridge|master` (biến môi trường ghi ở đầu file; lệnh đầy đủ
   của lượt v6 trong `notes/STATE.md`). `plan` gọi `plan_matched_run.py` dựng `CONFIG.json` (lịch trial, lịch tải).
4. **Campaign:** `attack/preview_campaign.py` — mỗi trial: control 15 s; rồi theo thứ tự có seed: lệnh quản trị
   (`ADMIN_SETS`), binary vô hại, tấn công (fixture, có thể PAD), bước living-off-the-land (`LOTL_SCRIPT`); ghi
   `INTERVALS.jsonl`, `ORDER.json`, bằng chứng exec của Tetragon.
5. **Phân tích (lượt v6):** `pulse_live_v4.py` (recall/precision/control/độ trễ/gánh; tập chính, PAD, lotl) →
   `live_attribution.py` (recall gắn với hành vi tấn công) → `native_stream.py` (H1) → `rule_e_benefit.py` (R1/R2,
   mặt hại trên lotl) → `rca_coverage.py`, `rca_follow_up.py` (H6). Khác: `cluster_threshold.py`, `session_model.py`
   (B2/B3), `model_aging.py` (mô hình cũ trên normal mới), `token_load.py`.
6. **Đo chi phí và giới hạn:** `scripts/overhead_ab.sh` + `analysis/overhead_ab.py` + `testbed/bench/syscall_bench.c`;
   `scripts/map_capacity_test.py` + `testbed/bench/gram_stress.c`.

---

## 6. Khái niệm then chốt (từ điển)

- **Bảng chữ select1f:** token = syscall + (errno của 27 syscall gồm futex / nhóm log2 cỡ đọc-ghi trả về, 16 nhóm /
  chế độ mở + thư mục đầu). **probe1f** = cùng bảng chữ, theo thứ tự probe phát (syscall không hook phát lúc vào).
- **39 syscall có hook:** cần giá trị trả về nên phát token ở `raw_tp/sys_exit` (một chương trình chung, không phải 39
  fexit — vì chi phí ftrace khi Tetragon cũng hook openat). Chỉ 5 trong 39 thực sự cần trên LID-DS (RQ2).
- **4-gram theo thread, Witten–Bell nội suy;** điểm cửa sổ = trung bình top-10 (−ln p).
- **Ngưỡng Gumbel (moment, bỏ 1% cao nhất)** trên cực đại giữ ra (bản ghi trên dataset, khối 60 s trên cụm);
  α′=0,0002×0,9=0,00018; τ = trung bình + 6,27 độ lệch chuẩn. α′ là núm chỉnh, không phải tỉ lệ báo nhầm bảo đảm.
- **Đường cảnh báo = chỉ nhánh token** (từ v5); cây + support chạy shadow.
- **Thẻ dòng dõi native/session:** native = cây process của workload; session = vào qua runtime exec (`kubectl exec`,
  exec probe của kubelet) và con cháu. **Chỉ là telemetry:** đường cảnh báo vẫn chấm cả cửa sổ. Mọi tấn công của
  campaign vào qua `kubectl exec` nên thuộc session; H1 của lượt v6 kiểm "chấm riêng phần native thì lệnh quản trị và
  binary vô hại không còn bị gắn cờ".
- **Trial, tập chính, PAD, lotl:** trial = control + lệnh quản trị + binary vô hại + tấn công (+ lotl ở v6); tập chính =
  tốc độ 6/12/24 lần/s; PAD = số cặp getpid+sched_yield chèn sau mỗi thao tác tấn công (pha loãng, H3); lotl = tấn công
  bằng tool có sẵn trong image (`sh`, `cat`, `ls`) — mặt hại của luật R1 (H4).
- **Gánh cảnh báo:** số đợt (các cửa sổ báo của cùng container cách nhau < 15 s) trên mỗi replica-giờ normal.
- **W1–W8** ([PAPER_PLAN.md](PAPER_PLAN.md)): W1 hành vi hợp lệ/dòng dõi, W3 né tránh (pha loãng, nhánh tần suất),
  W4 baseline (baseline học sâu chủ đồ án bỏ 15/11), W6 chi phí, W7 thứ tự RCA, W8 ngưỡng.

---

## 7. Protocol, biên nhận, test — vì sao tin được số

- **Protocol** `sentinel_pulse/protocol/*.json`: định nghĩa thí nghiệm *trước khi* chạy (`registered_at`,
  `registered_before`). Sửa = amendment (`*-amendment-N.json`). Đang dùng: `lidds-ml-v5.json`, `ml-final-study-v1*.json`,
  `pulse-live-v6-v1*.json`, `lidds2019-confirmation-v2.json`, `token-probe-overhead-v1*.json`, `map-capacity-v1.json`.
- **Biên nhận** `validation-evidence/results-YYYYMMDD/<study>/`: README + JSON thô + lệnh tái lập.
- **Kiểm toán** `scripts/audit/headline_numbers.py`: tính lại số trong đồ án LaTeX từ biên nhận (100/100 câu).
- **Test** `tests/`: 586 test.

---

## 8. Tái lập một con số (ví dụ)

- **Official LID-DS 2021 (97,40%):** `validation-evidence/results-20261110/lidds-ml-v5/README.md`; gate tái lập bằng code
  khác: `results-20261117/lidds2019-gate/`.
- **ML-only vs ML+rule** (báo nhầm lệnh quản trị 0,977→0): `results-20261115/rule-e-benefit/README.md`.
- **Mô hình lão hoá** (0,59% vs 0,26%): `results-20261117/model-aging/README.md` → `model_aging.py`.

---

## 9. Đọc tối thiểu nếu chỉ có 30 phút

`sentinel_pulse/ebpf/pulse_token_ids.h` (token là gì) → `sentinel_pulse/detector/token_model.py` (mô hình) →
`scripts/analysis/token_branch_fit.py` (ngưỡng trên cụm) → một biên nhận `validation-evidence/results-20261110/lidds-ml-v5/`.

---

## 10. Trạng thái chú thích tiếng Việt trong code

Xong 18/11, theo thứ tự §1. Mọi đợt được kiểm bằng máy là chỉ thêm chú thích (Python: AST không đổi; C: code sau khi bỏ chú
thích không đổi; shell: các dòng không phải chú thích không đổi).

| Phần | Mức chú thích |
|---|---|
| `sentinel_pulse/ebpf/` (kernel, header, loader, fixture, Makefile) | chi tiết từng hàm, struct, map, hook |
| `sentinel_pulse/detector/token_model.py` | chi tiết: công thức P₀, Witten–Bell, điểm top-10, TokenBranch |
| `sentinel_pulse/collector/token_capture.py`, `cgroup_resolver.py` | chi tiết |
| `sentinel_pulse/pipeline/plan_matched_run.py`, `matched_worker.py` | chi tiết (vòng segment, frame, phần token, niêm phong) |
| `sentinel_pulse/attack/preview_campaign.py`, `testbed/attack/runtime_attack_with_benign_control.c` | chi tiết (trial, bước, PAD, lotl, 5 kịch bản) |
| `sentinel_pulse/ops/alert_bridge.py`, `sentinel_pulse/rca/service.py`, `ranking.py` | chi tiết |
| `scripts/launch_run.sh`, `scripts/analysis/token_branch_fit.py`, `pulse_live_v4.py` | chi tiết từng bước / hàm |
| Các module còn lại của `sentinel_pulse/` | đoạn mô tả đầu file; module của hệ thống cũ ghi rõ "(Hệ thống cũ ... shadow)" hoặc "(Lịch sử)" |
| Mọi script trong `scripts/` (62 script phân tích + script vận hành), `paper/tools/` | đoạn mô tả đầu file: làm gì, thuộc chặng nào, còn dùng hay lịch sử |
| `tests/`, script trong `validation-evidence/`, `docs/meetings/` | không chú thích (tên test tự mô tả; script cạnh biên nhận giữ nguyên như lúc tạo biên nhận) |
