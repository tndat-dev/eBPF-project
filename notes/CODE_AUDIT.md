# Audit codebase (10/11/2026)

Trạng thái trước audit: tag `archive/pre-audit-20261110`. Mọi thứ đã xoá lấy lại được từ tag đó.

## Cách làm

1. Bản đồ tham chiếu: với từng file code, tìm mọi nơi import, gọi hoặc nhắc tên (code, test, protocol, notes, thesis).
2. Tập gốc "đang dùng": hệ thống chạy thật (probe token → worker → bridge/RCA, campaign, planner), phân tích hiện tại
   (`lidds-ml-v4/v5`, fit cho cụm, `pulse_live_v4.py`), công cụ của đồ án (kiểm toán số, hình), và việc còn treo (LID-DS 2019, so
   sánh có/không luật, baseline, ablation vòng 2, overhead ứng dụng).
3. Chỉ xoá khi kiểm được: không còn gì trong tập gốc tham chiếu, thí nghiệm đã xong và không nằm trong kế hoạch. Thứ tự ưu tiên:
   xoá, rồi đơn giản hoá.
4. Kiểm sau khi sửa: toàn bộ test (548 passed, 1 skipped), import từng module, kiểm toán số liệu đồ án (50/50), và với probe là
   so mã máy trước và sau.

## Đã xoá (4.811 dòng, 48 file)

| Nhóm | Nội dung | Vì sao chắc chắn thừa |
|---|---|---|
| Thế hệ pilot 08–14/10 | `syscall_histogram_{pilot,analysis,cohort}.py`, `syscall_capture_campaign.py`, `syscall_addition_experiment.py`, `syscall_frequency_report.py`, `audit_matched_fits.py`, `syscall_histogram.bpf.c` + loader, `extended_collection.py`, 5 unit systemd, `rotate_control_capture.sh`, `install_node.sh` | Chỉ tham chiếu lẫn nhau; biên nhận của chúng (`validation-evidence/pulse/`) không được đồ án hay bộ kiểm toán dùng; các unit không còn cài trên node nào |
| Công cụ một lần | `freeze_idle_reference_candidate.py`, `bundle_candidate.py`, `replay_preview_campaign.py`, `rca/validate_runtime.py`, `runtime_probe.c`, 3 manifest k8s | Không code, script hay protocol nào gọi; policy Tetragon `pulse-detail` không được áp trên cụm |
| Probe `exec-intent` | Bộ đếm theo process dưới cờ `PULSE_EXEC_INTENT`, target `exec-intent` | Chưa hoàn thiện (phần user space chưa viết), và hướng giảm binary vô hại đã chuyển sang gate trên token (`lidds-ml-v5`) |
| Biến thể `fexit` của probe token | 39 chương trình `fexit`, `--token-exit`, `PULSE_TOK_SKIP` | Đã đo và loại 07/11 (làm chậm `open` của cả node); mặc định là một `raw_tp/sys_exit` |
| Các ABI cũ của probe | Nhánh `#ifdef` cho bản legacy, projected, tracked-slot; target `all`, `projected`, `extended`; test C của ABI cũ | Hệ thống chỉ dùng hai bản build: `matched` và `tokens` |
| File requirements | 3 file trong `sentinel_pulse/` | Chỉ `install_node.sh` dùng |

Kèm theo: 9 file test của các module đã xoá.

**Kiểm chứng phần probe.** Build bản cũ và bản mới trên `.234`, cùng kernel header:

- Bản `matched`: mọi section chương trình giống hệt; loader sau `strip` giống từng byte.
- Bản `tokens`: bốn section còn lại (`sys_enter`, `sys_exit`, `__seccomp_filter`, `.text`) giống từng byte; khác biệt duy nhất là
  mất 39 section `fexit` và số thứ tự kiểu BTF.
- Còn thiếu: chạy `token_probe_proof.py` với bản build mới trên worker (chỉ làm được khi lượt live đã dừng). Cho tới khi có
  proof mới, các lượt chạy vẫn dùng bản build đã có proof ở `/home/dat/pulse-tokens-20261107`.

## Phản biện: giả định yếu và chỗ phức tạp quá mức

Chưa sửa các mục này trong đợt này; lý do ghi ở từng mục.

1. **Hợp đồng "mỗi job một script" làm repo chỉ có thể lớn lên.** README coi `scripts/*.sh` là bằng chứng của biên nhận, nên 33
   script của các lượt đã xong (1.473 dòng) và 26 script phân tích của thí nghiệm đã xong (2.496 dòng) vẫn nằm ở HEAD. Nhưng chỉ
   13/63 thư mục biên nhận ghi commit đã chạy, nên script ở HEAD cũng không bảo đảm là bản đã sinh ra con số. Đề xuất: xoá khỏi
   HEAD, giữ bằng tag, và từ nay mọi biên nhận ghi commit. Đây là thay đổi phương pháp của chủ đồ án nên chờ quyết định.
2. **Status của campaign sai với nhánh token.** `preview_evaluation.py` chỉ đếm dòng của nhánh đếm, nên lượt 1109 báo recall 34%
   trong khi nhánh token bắt 525/525. Ở lượt v5 (nhánh đếm chạy shadow) nó sẽ báo 0%. Số đúng lấy từ `pulse_live_v4.py`. Chưa sửa
   vì file này là đường chạy của lượt live 24 giờ sắp tới và còn được phân tích các lượt cũ dùng.
3. **Resolver trên worker chạy bản code cũ không được khoá.** Unit `sentinel-pulse-resolver` chạy
   `/opt/sentinel-pulse/sentinel_pulse` theo đường dẫn module trước 18/10, không thuộc snapshot hay proof của lượt chạy. Đây là
   thành phần duy nhất của đường live nằm ngoài cơ chế khoá. Chưa sửa vì đổi nó là đổi đường thu dữ liệu giữa capture và lượt live.
4. **Bộ máy của hệ thống cũ còn trong worker.** Calibration tự làm mới (kết quả âm, 771 dòng ở `live_recalibration.py` và
   `rolling_recalibration.py`), trao đổi giữa worker và chiết khấu theo replica (đã bỏ khỏi ML 01/11), novelty. Tripwire còn cần
   trao đổi giữa worker, và so sánh có/không luật chưa làm, nên chưa gỡ được cả cụm; riêng calibration tự làm mới có thể xoá.
5. **Khoá 13 file chấm điểm cho một nhánh đang ở shadow.** Cơ chế frozen source bảo vệ cây + support; khi hai nhánh này không còn
   báo, chi phí vận hành của nó (snapshot, amendment mỗi lần lệch) lớn hơn lợi ích. Giữ tới khi quyết định số phận hai nhánh.
6. **Ngưỡng Gumbel không giữ mức thiết kế.** Trên cụm, tỉ lệ khối vượt ngưỡng gấp 12,8–16,6 lần mức α. Mức α đang là núm chỉnh,
   không phải bảo đảm; đồ án đã ghi vậy. Nguyên nhân đo được ở lượt 1109: capture 12 giờ chưa phủ sự kiện hiếm.
7. **Cờ cấu hình luôn tắt:** `stop_on_miss`, `stop_on_false_positive`, `zero_alert_gate`, `automatic_promotion`, `fresh_blind` trong
   planner và campaign. Xoá được, cùng lúc với mục 2.
8. **Dọn trên cụm:** timer `tetra-orphan-reaper` còn bật trên worker dù nguyên nhân gốc đã sửa 25/10; bản loader legacy ở
   `/opt/sentinel-pulse/bin`. Dọn sau lượt live.
9. **Tài liệu trùng và cũ:** `TODO.md` còn các mục "đang chạy" từ 29/10; `notes/STATE.md` mới là trạng thái thật. Là file của chủ
   đồ án nên không tự xoá.

## Thứ tự đề xuất cho phần còn lại

1. Sau lượt live v5: sửa mục 2 và 7 cùng nhau, rồi chạy một lượt smoke.
2. Khi chủ đồ án đồng ý mục 1: xoá 59 script, sửa README, thêm commit vào mọi biên nhận mới.
3. Xoá calibration tự làm mới (mục 4) kèm protocol và test của nó.
4. Sau so sánh có/không luật: quyết định mục 4 (phần còn lại) và mục 5.
