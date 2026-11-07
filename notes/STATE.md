# Trạng thái làm việc (bản ghi cho Claude, cập nhật 07/11/2026)

File này thay bốn file trạng thái cũ (`SENTINEL_PULSE_STATUS.md`, `SYSCALL_FEATURE_EXPERIMENT_STATUS.md`,
`RCA_RUNTIME_STATUS.md`, `RULE_INTEGRATION_STATUS.md`), xoá ngày 07/11 theo yêu cầu của chủ đồ án. Toàn văn còn trong
git: `git show 8b1bc44:SENTINEL_PULSE_STATUS.md` (tương tự với ba file kia). Nhật ký từng bước: [WORKLOG.md](WORKLOG.md).

## Mục tiêu và quyết định đang áp dụng

- Mục tiêu: ML học từ normal phát hiện blind attack; recall ≥ 95%, precision ≥ 95%, p95 ≤ 3 s; binary vô hại và gánh cảnh
  báo càng thấp càng tốt. Luật (tripwire, novelty, bỏ phiếu) chỉ thêm sau khi ML chốt, để so sánh có/không có luật (01/11).
- Quy trình: chọn trên LID-DS 2021 development + CB-DS → official LID-DS 2021 → live blind → LID-DS 2019 cuối cùng.
- Official LID-DS 2021 đã chấm hai lần (v2 05/11, v3 07/11); chủ đồ án cho phép chấm lại không cần hỏi, nhưng protocol và
  biên nhận phải ghi rõ.
- Bỏ cổng chiết khấu theo replica khỏi ML (01/11). Nới giới hạn overhead cho probe token (06/11): đo và báo, không còn đạt/trượt.
- Tạm dừng: baseline học sâu (kết quả từng phần giữ ở `results-20261102/dl-baseline-partial/`), exec-intent (chờ số binary
  vô hại của lượt live ML mới).
- Tài liệu họp (docx, pptx): không CI, không biểu đồ phức tạp, không chữ "luận văn"; chủ đồ án tự sửa deck, nên chèn vào bản
  của họ, không dựng lại.

## ML hiện tại: `lidds-ml-v3` (protocol `sentinel_pulse/protocol/lidds-ml-v3.json`)

- Nhánh: mô hình token (4-gram theo thread, Witten-Bell, điểm = trung bình 10 −log p lớn nhất) trên bảng chữ `select1f`
  (errno của 27 syscall gồm futex, log2 cỡ đọc ghi không chia đôi, chế độ mở + thư mục đầu), cùng cây tham chiếu và support
  của ML cũ (249 đặc trưng đếm, bỏ cổng khởi động). Ngưỡng: Gumbel theo moment trên điểm lớn nhất mỗi bản ghi validation,
  mỗi nhánh α/3, α = 0,0002; một cửa sổ vượt ngưỡng là báo.
- Official: 97,32% (1.237/1.271, Wilson 96,29–98,08), báo nhầm 0,44% (35/7.938), precision 97,25%, p95 2,09 s,
  trong 3 s 96,2%. Juice-Shop 52/85 là chỗ yếu duy nhất; trần thông tin 1.243. Development 97,43% / 0,50%; CB-DS 891/891, 2/1.410.
- Lịch sử: ML ban đầu 63,9%; `lidds-ml-v1` 65,2% (âm); `lidds-ml-v2` 95,99% / 0,57% (bảng chữ cũ, cỡ chia đôi).
- Code: `scripts/analysis/lidds_ml_token_alphabets.py` (token), `lidds_ml_scores.py --all-windows` (cây, support),
  `lidds_ml_v2.py --token-column select1f --protocol …v3.json` (chọn và chấm). Biên nhận `validation-evidence/results-20261107/lidds-ml-v3/`.
- Đã kiểm (development): ngưỡng Gumbel bằng oracle một mức chung, oracle từng kịch bản chỉ hơn 7 bản ghi; LSTM lớn không hơn
  n-gram tổng thể; luật đếm token chưa thấy ngang mô hình (giới hạn đã ghi).

## Hệ thống chạy trên cụm (ML cũ)

- Lượt cuối `pulse-final-system-confirm` (25–26/10): recall 99,4%, precision 99,4%, control 0,6%, p95 1,97 s (ML + tripwire),
  binary vô hại 89,5%, gánh 1,76 đợt/replica-giờ. Bỏ cổng replica (tính lại): 99,4% / 97,5% / gánh 5,60.
- Calibration tự làm mới không thắng (29–30/10). Luật phá hoà RCA theo thời điểm khởi chạy: top-1 100% blind.
- Ngưỡng theo khối thời gian với riêng cây + support trên dữ liệu live: recall chỉ 52–78% → trên cụm, recall phải do nhánh token mang.

## Việc đang làm và tiếp theo

1. **Probe token đã viết (07/11)**: `make tokens` (`sentinel_pulse/ebpf/pulse_token_ids.h`, `pulse_tokens.bpf.h`, loader
   `--tokens exit-nofutex|exit|grams`), token 32 bit, thư mục đầu từ `bpf_d_path` ở `security_file_open`, cửa sổ trong khoá
   map; worker ghi `tokens.jsonl` (cfg `tokens`), chấm trực tuyến khi có `tokens.models` (`detector/token_model.py`
   `TokenBranch`, mô hình đếm bằng `TokenLM` offline tới 1e-12). Thay đổi so với thiết kế: mục 7 của
   `reports/Thiết kế probe token Pulse.md`. Gắn 40 hook mất khoảng 10 s.
2. Overhead A–D (`token-probe-overhead-v1`): đang đo trên 3 worker (unit `token-probe-overhead`, `/var/tmp/token-probe-overhead/`).
3. Sau đó: kiểm lưu lượng trên pod thật (`scripts/analysis/token_probe_volume.py`); proof collector cho bản build token; lượt
   thu normal có token để học mô hình token theo workload và ngưỡng theo khối; rồi lượt live blind ML mới. Lượt thu và lượt
   live không chạy chồng ablation vòng 2 (đang dump điểm trên `.234`, dừng/tiếp được theo `TERMINAL.json` từng segment).
4. Ablation vòng 2 (3 seed, 45 cấu hình) chạy nền trên `.234` từ 07/11 07:57.
5. LID-DS 2019 một lần (dữ liệu, bộ chuyển đổi, protocol `lidds2019-confirmation-v1` đã sẵn).
6. Sau đó: so sánh có/không luật; mở lại baseline.

## Dữ liệu và tài nguyên

- `.234` (`/var/tmp/lid-ds-2021`): 15 archive LID-DS 2021, `ml-scores-allwin` (cây, support), `ml-tokens` (token v2),
  `ml-v3-tokens` (full, full1, select1f, mọi bản ghi), `ml-links` (symlink cho scorer). Ablation: `/var/tmp/syscall-loo` (vòng 1 và 2). CB-DS: `/var/tmp/cb-ds/archives`.
  LID-DS 2019: `/var/tmp/lid-ds-2019`. Bảng cửa sổ các lượt live: `/var/tmp/burden-levers/table-*.npz`.
- NFS `.233`: `/mnt/sentinel-pulse-archive` (các lượt live, bản sao tài liệu). Dịch vụ còn chạy: `pulse-alert-bridge-rca-viewer`
  (xem case RCA trên Grafana).
- Mọi unit phân tích trên `.234`: `systemd-run -p MemoryMax=… -p OOMPolicy=continue`, tổng trần ≤ khoảng 45 GB (balloon dao động tới 70 GB).

## Kiểm tra

- Số liệu bản LaTeX: `python3 scripts/audit/headline_numbers.py` (khớp biên nhận). Build: `cd thesis && tectonic main.tex`.
- Test: `uv run -q --no-project --with numpy --with scikit-learn --with pytest python -m pytest -q tests/…`.
