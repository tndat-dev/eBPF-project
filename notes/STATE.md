# Trạng thái làm việc (bản ghi cho Claude, cập nhật 12/11/2026)

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

## Hệ thống hiện tại: `lidds-ml-v5` chỉ token (10/11); trước đó `lidds-ml-v4` (chốt 09/11)

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

## Việc đang làm và tiếp theo (kế hoạch 12/11, protocol `ml-final-study-v1`)

Hệ thống hiện tại: `lidds-ml-v5` (chỉ token), live `pulse-live-v5-1110` xong, đồ án và tài liệu họp 13/11 đã cập nhật. Lịch sử các
bước trước: [WORKLOG.md](WORKLOG.md) và git.

**Giai đoạn 1: nghiên cứu offline, không cần lượt live** (protocol `sentinel_pulse/protocol/ml-final-study-v1.json`, đăng ký 12/11 21:50)
1. A, tách recall live: burst khởi chạy hay hành vi tấn công (`scripts/analysis/live_attribution.py`, unit `ml-final-a` trên `.234`,
   ra `/var/tmp/ml-final/live-attribution.json`). Mô tả, không đổi hệ thống.
2. B, học hoạt động quản trị như normal, bỏ-một-lệnh (cùng unit). Đạt tiêu chí thì đề xuất lượt live xác nhận có fit lại.
3. D, tín hiệu tần suất cho tấn công chỉ dùng chuỗi đã thấy trên cache development (`lidds_token_rate.py`). Đạt tiêu chí thì một lần
   chấm official đã khai.
4. C, ngưỡng trên cụm từ phân vị thực nghiệm của cực đại khối 60 s giữ ra (`token_branch_fit.py --dump-maxima`).
5. Chốt ML cuối (v6) từ kết quả 1–4; ghi vào đồ án như development.

**Kết quả giai đoạn 1 (13/11):** A đạt (recall live đo đúng hành vi tấn công); B, B2, C, D không đạt tiêu chí, ML giữ `lidds-ml-v5`. B3
(amendment 1): dòng native sạch (0 lần báo trên control, lệnh quản trị, binary vô hại), mô hình phiên với ngưỡng Gumbel không bắt tấn công,
nên chưa dựng thẻ dòng dõi theo tiêu chí đã đăng ký. Chi tiết và thiết kế thẻ dòng dõi: [RESEARCH_NOTES.md](RESEARCH_NOTES.md); lộ trình bài
báo: [PAPER_PLAN.md](PAPER_PLAN.md).

**Thẻ dòng dõi (amendment 2, 13/11):** probe gắn thẻ native/session cho từng thread (`pulse_tok_lineage`, `pulse_tok_fork`), loader ghi
thêm phần session của mỗi cửa sổ, đường cảnh báo không đổi. Proof đạt trên k8s-worker1 (`results-20261113/lineage-probe/`). Chưa có bản
build chính thức cho lượt chạy; chưa đo chi phí hook fork.

**Giai đoạn 2: rule sau khi chốt ML** (E): R1 hạ cảnh báo khi chỉ có runtime exec của tool có trong image, R2 gắn nhãn drift cho binary
lạ; đo trên dữ liệu v5, so sánh có và không có rule.
- **Nửa-lợi đã đo (15/11, `validation-evidence/results-20261115/rule-e-benefit/`, `scripts/analysis/rule_e_benefit.py`):** scorer phát
  số **tách hẳn hai hệ** (khối `comparison` trong json): **ML-only** (chỉ mô hình token = alert path v5 đã triển khai) vs **ML+rule**
  (mô hình + rule part E, alert = mô hình kêu VÀ không bị R1 hạ). Trên campaign v5 — bảng primary 6/12/24 req/s (`pulse_live_v4.PRIMARY`; full set 1/3/6/12/24):

  | Chỉ số | ML-only | ML+rule |
  |---|---|---|
  | Recall tấn công | 314/314 = 1.000 | 314/314 = 1.000 |
  | Báo nhầm admin (dùng tool-của-image) | 256/262 = 0.977 | **0/262 = 0.000** |
  | Benign-exec operator (non-image → drift) | 314/314 | 314/314 (giữ, nhãn drift) |

  (pooled mọi rate: recall 521/522; admin 422/439 → **0/439**; benign-drift 520/523 không đổi; báo nhầm gộp 942/1487 → 520/1487.)
  Kết: **chỉ số rule layer thay đổi là báo nhầm admin 0.977→0, recall tấn công giữ nguyên**. **Mặt-hại (R1 bỏ sót tấn công
  dùng tool-của-image, living-off-the-land) CHƯA đo được — cần part F của pulse-live-v6** (đúng protocol). Dùng lại loader
  token-branch của live_attribution; ML alarms chính là của mô hình v5.
- **W3(b) nhánh tần suất — ĐÃ ĐO end-to-end (15/11, `results-20261115/w3b-rate-signal/`, `lidds_token_rate.py`):** input vẫn
  còn đủ trên `.234` (`token-study/cache` + alarms inventory snapshot + raw zip) — nhận định "blocked/chờ regen" hôm trước là
  chẩn nhầm thư mục. So ML-only (`model`) vs ML+nhánh (`model_or_rate`): arm `model` tái lập đúng v5 dev **530/544 FA 6**
  (cross-check không hardcode); **nhánh rate thêm 0 phát hiện** (LID-DS 530→530, CB-DS 891→891), **chỉ thêm báo nhầm** (LID-DS
  6→12 α chung, →7 với split-α amendment-3; CB-DS 3→4). `joins=False`, `joins_split=False` (LID-DS FA 7>6, CB-DS 4>3). Kết:
  trên benchmark tĩnh nhánh tần suất **không đáng nhận**; giá trị chống pha-loãng cần **fixture W3(a) của lượt live**. Nhánh giữ
  shadow, alert path vẫn chỉ token (khớp kết quả D "không đạt tiêu chí" của Giai đoạn 1).

**24/11: không có lượt live nào chạy. Ngưỡng theo mức tải không nhận (load-threshold-v1). S1 bị chặn trên dataset (523/544); S1a đã chốt (amendment 2, 24/11 13:18; native ở ngưỡng t3, session ở α′ 0,00015; dataset trùng t3; gánh 0,273). Sau chẩn đoán cảnh báo tải cao: capture thêm hoặc chạy MỘT lượt live cuối `pulse-live-diurnal-final-<MMDD>` (diurnal, campaign như lượt cuối, fit `pulse-live-diurnal-fit-1123`, TOKEN_SESSION=SESSION-S1a.json).** **21/11 tối: capture diurnal 24 h `pulse-token-capture-diurnal-1121` đang chạy (tới 22/11 19:56). Sau đó, theo thứ tự: session-stream-v1 offline (fit session gộp/theo workload trên capture v6 + selection lượt cuối; S0/S1/S2 trên lượt cuối; S3 LOFO + chéo v6), A (mô hình t3 trên capture diurnal theo chế độ), fit diurnal, LID-DS chạy lại nếu nhận nhánh session, rồi live diurnal ≥ 24 h. Bridge đã sửa lỗi chỉ mục case RCA (nguyên nhân push chậm).** **21/11: lượt cuối xong và đã phân tích: H0, H3, H7, H8 đều đạt (296/296, control 0/296, precision 100%, p95 0,46 s; PAD 300 95/95; 0,1/s 99/99, 0,5/s 100/100; bật-tắt 96/96); gánh 0,36 đợt/replica-giờ; biên nhận `validation-evidence/results-20261121/pulse-live-final-1119/`. Rule track (`rule-intent-v1`) xong: không nhận (control 461/694, gánh 6,44). Đồ án và paper đã sang t3 và lượt cuối. Đang nén segment lượt cuối (`compress-final-1119` trên 3 worker). Báo cáo/slide 20/11 đã bị chủ đồ án xoá. Chủ đồ án: khoảng không chạy được (136 cặp Kafka, event-generator không chép được vào /tmp 5 MiB) lọc khỏi kết quả và KHÔNG nhắc trong mọi tài liệu; biên nhận vẫn ghi số.** **19/11 09:50: lượt live cuối `pulse-live-final-1119` (protocol `pulse-live-final-v1`) đang chạy, kết thúc khoảng 21/11 06:50 (+07); không chạy job nặng trên mọi node, không pull code lên worker tới khi xong; lượt chạy hết chu kỳ. Sau đó: phân tích theo protocol (H0, H3, H7, H8, event-generator, dòng native, gánh trên 6 giờ normal cuối, sự kiện K8s, RCA), rồi cập nhật đồ án/paper/báo cáo/slide sang t3. Bộ ghi sự kiện K8s dừng 02:49 UTC (user unit), chạy lại 03:59 UTC thành system unit; khoảng trống thật khoảng 02:49–02:59, trước tấn công.** **19/11: lượt live v7 đã dừng theo chủ đồ án (18/11 19:28 UTC, trước tấn công) để chạy vòng cải thiện `improvement-round-v1` (D1–D18). Nhận: D1 map đầy → cảnh báo, D2, D3 hàng đợi bền; không nhận: D4, D5b, D6, D10, D11, D14, D15, D16; D13 đã đóng bởi seccomp; D12, D18 sẵn cho lượt cuối. Còn chạy: D7 (`improve-app-overhead`), D8/D17 (`improve-rich`). Lượt live cuối chạy sau khi mọi hướng xong và qua các cổng: (1) kết quả D7, D8/D17; (2) diễn tập `REHEARSAL=1` khoảng 20 phút, kiểm mọi bước (event-generator trong workload musl/distroless, tốc độ 0,1/s, PAD 300, bật-tắt, cảnh báo có nhãn stream, hàng đợi bridge, ghi sự kiện K8s, phân tích chạy được); (3) đăng ký `pulse-live-final-v1`; probe `pulse-tokens-final-f8ccbb2`, mô hình `pulse-live-v7-fit-1118` (t3).** **18/11 tối: LID-DS 2019 chấm một lần, C1 không đạt (723/1.162, 62,22%); amendment 1 (dung sai nhãn 1 s, phân tích sau) cho 1.056/1.162 (90,88%), 2021 không đổi — vẫn dưới 95% vì Heartbleed và độ trễ. Thử trên 30% development (lidds2019-development-v1): không ứng viên nào (23 + 90 tổ hợp + nhánh tần suất) giữ LID-DS 2021 mà tăng recall → giữ lidds-ml-v5, holdout không chấm; cận dưới độ trễ của mọi bộ phát hiện dựa trên độ lạ trên 2019 là p95 9,39 s.** **18/11: lượt live `pulse-live-v6-1117` xong và đã phân tích (H0, H1, H3 đạt; R1 không nhận vì hạ hết tấn công lotl; RCA hạng 1 76% cần giải thích) — biên nhận `results-20261118/pulse-live-v6-1117/`. Tiếp: LID-DS 2019 (lidds2019-confirmation-v2), cập nhật đồ án và paper.** Trước đó:, không chạy job nặng nào trên mọi node tới khi xong; sau đó các phân tích H0–H6 (`pulse_live_v4.py`, `live_attribution.py`, `native_stream.py`, `rule_e_benefit.py`, `rca_coverage.py`, `rca_follow_up.py`). Fit `pulse-live-v6-fit-1117` xong 11:47. **17/11: capture `pulse-token-capture-v6-1116` xong; kiểm lão hoá xong (v5 trên normal mới 0,59% khối vượt ngưỡng so với 0,26% giữ ra, `results-20261117/model-aging/`); đang fit `pulse-live-v6-fit-1117` (unit `pulse-v6-token-fit`), snapshot `runtime-8b997df-20261117`.** Lệnh khởi chạy sau khi fit xong (trên `.234`, user dat, từ `$SNAP`): `LAB_SSH_PASSWORD=$(cat /home/dat/.pulse-recovery-credential-20261005) RUN=pulse-live-v6-<MMDD> SNAP=/mnt/sentinel-pulse-archive/runtime-8b997df-20261117/source CANDIDATE=/mnt/sentinel-pulse-archive/pulse-next-run-model/model-bundle MODEL_HASH=4bad16dcd88b004f55d81c1a9721b9224a55b7a2cc2f35023cf57c8bb11d7fbc POLICY=sentinel_pulse/protocol/policy-2of2-a10-refreshed.json POLICY_HASH=9c41ebc06243461a8abce9ceec3becdb17869db42f51a85b3137b87d030d1540 SECONDS_TOTAL=93600 TOKEN_BUILD=/home/dat/pulse-tokens-lineage-5fc5f37 TOKEN_MODELS=/mnt/sentinel-pulse-archive/pulse-live-v6-fit-1117/token/MODELS.json V3_COUNTS=/mnt/sentinel-pulse-archive/pulse-live-v6-fit-1117/count-thresholds.json ADMIN_CONTROL=1 ADMIN_COMMANDS=v6 RANDOM_ORDER=1 LOTL_ATTACK=1 DILUTION_PADS=30,300 LOCAL_DECISIONS=1 ATTACK_RATES=1,3,6,12,24 bash scripts/launch_run.sh all`. Trước đó: thu normal `pulse-token-capture-v6-1116` theo `pulse-live-v6-v1`, build có thẻ dòng dõi
`/home/dat/pulse-tokens-lineage-5fc5f37` (proof token và dòng dõi đạt trên 3 worker), snapshot `runtime-59390d0-20261116`. Không chạy job
nặng nào trên mọi node tới khi xong. Sau đó: kiểm lão hoá (mô hình v5 không đổi chấm toàn bộ capture, `scripts/analysis/model_aging.py --heldout validation-evidence/results-20261113/ml-final-study/cluster-threshold.json`, mô tả, không quyết định gì), rồi fit (`token_branch_fit.py` như v5, `--extra-run pulse-live-v5-1110`, `--dump-maxima`, tuần tự,
trần 20 GB trên `.234`), rồi live 26 giờ (amendment 1, giữ đủ 735 trial; campaign ước lượng 22,7 h, dư khoảng 1,8 h): `TOKEN_BUILD` như trên, `TOKEN_MODELS` của fit, `ADMIN_CONTROL=1 ADMIN_COMMANDS=v6 RANDOM_ORDER=1
LOTL_ATTACK=1 DILUTION_PADS=30,300 LOCAL_DECISIONS=1 SECONDS_TOTAL=93600 ATTACK_RATES=1,3,6,12,24`. Đã đo xong trước lượt: chi phí thẻ dòng
dõi (không đo được, `results-20261116/lineage-overhead/`), sức chứa map (`results-20261116/map-capacity/`).

**Giai đoạn 3: một lượt live mới `pulse-live-v6-<MMDD>`** (protocol riêng, đăng ký trước): tấn công bằng tool của image, thêm kỹ thuật ATT&CK (discovery, credential access, persistence, impact, network scan), thứ tự ngẫu nhiên,
RCA recheck, lệnh quản trị mới chưa dùng khi học. Đo riêng: chi phí trên request (bật/tắt probe xen kẽ), tải tới khi map đầy.
16/11: chủ đồ án không đồng ý dịch vụ thử có đường gọi chạy thao tác trong process; dòng native không được thử với tấn công trên
cụm (giới hạn của `pulse-live-v6-v1`), bằng chứng cho trường hợp đó là LID-DS 2021.

**Giai đoạn 4:** LID-DS 2019 đúng một lần theo `lidds2019-confirmation-v2` (đăng ký 17/11 12:28, sau lượt v6; cần viết driver và gate tái lập official 2021); paper USENIX Security '27 trong `paper/` (README ghi bước); so sánh có/không có rule; mở lại baseline học sâu.

## Dữ liệu và tài nguyên

- `.234` (`/var/tmp/lid-ds-2021`): 15 archive LID-DS 2021, `ml-scores-allwin` (cây, support), `ml-tokens` (token v2),
  `ml-v3-tokens` (full, full1, select1f, mọi bản ghi), `ml-links` (symlink cho scorer). CB-DS: `/var/tmp/cb-ds/archives`.
  LID-DS 2019: `/var/tmp/lid-ds-2019`. Cache của token-design-study: `/var/tmp/lid-ds-2021/token-study/cache` (development, CB-DS).
- NFS `.233`: `/mnt/sentinel-pulse-archive` (các lượt live, bản sao tài liệu). `pulse-alert-bridge-rca-viewer` (xem case RCA trên
  Grafana) mất khi vCenter khởi động lại 09/11 10:19 vì là unit tạm; lượt live dựng bridge riêng trên cùng cổng 9478.
- Mọi unit phân tích trên `.234`: `systemd-run -p MemoryMax=… -p OOMPolicy=continue`, tổng trần ≤ khoảng 45 GB (balloon dao động tới 70 GB).

## Kiểm tra

- Số liệu bản LaTeX: `python3 scripts/audit/headline_numbers.py` (khớp biên nhận). Build: `cd thesis && tectonic main.tex`.
- Test: `uv run -q --no-project --with numpy --with scikit-learn --with pytest python -m pytest -q tests/…`.
