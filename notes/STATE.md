# Trạng thái làm việc (bản ghi cho Claude, cập nhật 09/11/2026)

File này thay bốn file trạng thái cũ (`SENTINEL_PULSE_STATUS.md`, `SYSCALL_FEATURE_EXPERIMENT_STATUS.md`,
`RCA_RUNTIME_STATUS.md`, `RULE_INTEGRATION_STATUS.md`), xoá ngày 07/11 theo yêu cầu của chủ đồ án. Toàn văn còn trong
git: `git show 8b1bc44:SENTINEL_PULSE_STATUS.md` (tương tự với ba file kia). Nhật ký từng bước: [WORKLOG.md](WORKLOG.md).

## Mục tiêu và quyết định đang áp dụng

- Mục tiêu: ML học từ normal phát hiện blind attack; recall ≥ 95%, precision ≥ 95%, p95 ≤ 3 s; binary vô hại và gánh cảnh
  báo càng thấp càng tốt. Luật (tripwire, novelty, bỏ phiếu) chỉ thêm sau khi ML chốt, để so sánh có/không có luật (01/11).
- Quy trình: chọn trên LID-DS 2021 development + CB-DS → official LID-DS 2021 → live blind → LID-DS 2019 cuối cùng.
- 09/11: chủ đồ án chốt `lidds-ml-v4` và yêu cầu tài liệu không cần ghi số lần chấm trên LID-DS 2021. Protocol đã đăng ký và lịch
  sử git giữ nguyên; không viết câu nào khẳng định ngược lại (ví dụ "chỉ chấm một lần").
- Bỏ cổng chiết khấu theo replica khỏi ML (01/11). Nới giới hạn overhead cho probe token (06/11): đo và báo, không còn đạt/trượt.
- Tạm dừng: baseline học sâu (kết quả từng phần giữ ở `results-20261102/dl-baseline-partial/`), exec-intent (chờ số binary
  vô hại của lượt live ML mới).
- Tài liệu họp (docx, pptx): không CI, không biểu đồ phức tạp, không chữ "luận văn"; chủ đồ án tự sửa deck, nên chèn vào bản
  của họ, không dựng lại.

## ML đã chốt: `lidds-ml-v4` (protocol `sentinel_pulse/protocol/lidds-ml-v4.json`, chốt 09/11)

- Khác v3 ở cách học và đặt ngưỡng: token học training + validation; ngưỡng token là Gumbel trên điểm giữ ra của cross-fit 5 fold, bỏ
  1% cao nhất; α 0,0002 chia token 0,9, cây 0,05, support 0,05. Mô hình token, cây và support giữ nguyên như v3.
- Official: 97,40% (1.238/1.271), báo nhầm 0,45% (36/7.938), precision 97,17%, p95 1,47 s, trong 3 s 1.234. Development 530/544, 12/3.403,
  p95 1,52 s; CB-DS 891/891, 3/1.410. Biên nhận `results-20261109/lidds-ml-v4/`. Trên cụm: `pulse-live-v3-v1-amendment-2`, cross-fit theo đoạn 30 phút.

## ML trước đó: `lidds-ml-v3` (protocol `sentinel_pulse/protocol/lidds-ml-v3.json`)

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

1. **Probe token (07/11)**: `make tokens`; mặc định `--token-exit sys_exit` (một raw tracepoint), thư mục đầu bằng đi ngược
   dentry từ fd (không còn ftrace_ops: `fexit`/`fentry` va chạm kprobe Tetragon, xem amendment 1–2 của
   `token-probe-overhead-v1`). Worker: `tokens.jsonl`, chấm token (`TokenBranch`), nhánh đếm v3 (`v3_counts`). Proof:
   `scripts/token_probe_proof.py` (đúng 1 token/syscall). Overhead 3 lần trong `results-20261107/token-probe-overhead/`;
   bản cuối so với A: getpid +127–174 ns, open + close +0,94–1,23 µs, futex +216–298 ns. Sơ đồ kiến trúc: `docs/architecture/`.
2. Bản build chính thức `/home/dat/pulse-tokens-20261107/{build,proof}` (46e9039, proof đạt 3 worker); lưu lượng trên pod thật
   75–290 KB/s mỗi worker (`results-20261107/token-probe-build/`). Sẵn sàng cho lượt thu.
3. `pulse-live-v3-v1` giai đoạn 1 xong: `pulse-token-capture-1107` (t0 07/11 20:29 = `selection_start` 1794058145.54, học
   [t0, t0 + 8 h), validation tới hết lượt). Fit v4 theo amendment 2, ra `/mnt/sentinel-pulse-archive/pulse-live-v4-fit-1109/`.
   Khoá sha256 trong `results-20261109/pulse-live-v4-fit/`.
   **Lượt live blind `pulse-live-v4-1109` đang chạy:** t0 09/11 13:59, tấn công từ 15:31, kết thúc 10/11 13:59. Source
   `runtime-1167481-20261109`, không chạy job nặng tới khi xong. Pha selection (tới 15:29) có một can thiệp: 14:01 tạo lại 5 pod
   (`payment-service` ×4, `order-service` ×1) restart tại chỗ lúc sau reboot, điểm support 18,8 so với khoảng 1,2 lúc capture.
   **Sau lượt live:** Prometheus scrape MinIO (`up=0` từ trước capture, STRICT mTLS); sentinel thấy replica Redis ở IP node nên đánh dấu
   `s_down` (replication vẫn online, nhưng failover qua sentinel có thể không chạy); cả hai làm đổi hành vi workload đã học nên hoãn.
   **Chờ chủ đồ án:** GitHub CI không chạy được vì tài khoản bị khoá do billing.
4. Ablation vòng 2: **tạm dừng** 07/11 20:20 theo chủ đồ án (dump worker1 18/49, worker3 46/49, worker4 6/49); chạy lại cùng lệnh
   systemd-run (trần 42 GB) sau lượt live v3.
5. **`lidds-ml-v5` (đăng ký 09/11, chưa chấm):** gate nhánh token để giảm binary vô hại và gánh, tuỳ chọn bỏ cây + support. Sau khi `pulse-live-v4-1109` xong:
   `scripts/lidds_ml_pool_run.sh` (unit có MemoryMax) → `lidds_ml_v5.py` chọn trên development + CB-DS phải giữ số v4 → chọn trên trial của lượt 1109 → `--official` một ứng viên
   phải giữ 1.238/1.271, 36/7.938, p95 ≤ 1,5 s → fit lại trên capture cũ → live `pulse-live-v5-<MMDD>` có lệnh admin thật (`ADMIN_CONTROL=1`, `TOKEN_GATE`). Trượt thì bỏ gate.
6. LID-DS 2019 một lần (protocol `lidds2019-confirmation-v1` đã sẵn). Sau đó: so sánh có/không luật; mở lại baseline.

## Dữ liệu và tài nguyên

- `.234` (`/var/tmp/lid-ds-2021`): 15 archive LID-DS 2021, `ml-scores-allwin` (cây, support), `ml-tokens` (token v2),
  `ml-v3-tokens` (full, full1, select1f, mọi bản ghi), `ml-links` (symlink cho scorer). Ablation: `/var/tmp/syscall-loo` (vòng 1 và 2). CB-DS: `/var/tmp/cb-ds/archives`.
  LID-DS 2019: `/var/tmp/lid-ds-2019`. Bảng cửa sổ các lượt live: `/var/tmp/burden-levers/table-*.npz`.
- NFS `.233`: `/mnt/sentinel-pulse-archive` (các lượt live, bản sao tài liệu). `pulse-alert-bridge-rca-viewer` (xem case RCA trên
  Grafana) mất khi vCenter khởi động lại 09/11 10:19 vì là unit tạm; lượt live dựng bridge riêng trên cùng cổng 9478.
- Mọi unit phân tích trên `.234`: `systemd-run -p MemoryMax=… -p OOMPolicy=continue`, tổng trần ≤ khoảng 45 GB (balloon dao động tới 70 GB).

## Kiểm tra

- Số liệu bản LaTeX: `python3 scripts/audit/headline_numbers.py` (khớp biên nhận). Build: `cd thesis && tectonic main.tex`.
- Test: `uv run -q --no-project --with numpy --with scikit-learn --with pytest python -m pytest -q tests/…`.
