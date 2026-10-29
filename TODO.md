# TODO — đồ án Sentinel Pulse

Cập nhật 29/10/2026 15:25. Số liệu và bằng chứng chi tiết: [Pulse](SENTINEL_PULSE_STATUS.md) ·
[syscall](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) · [RCA](RCA_RUNTIME_STATUS.md) · [rule, tách khỏi ML](RULE_INTEGRATION_STATUS.md) · [đánh giá tổng thể và ý tưởng](RESEARCH_IDEAS.md).
Ký hiệu: `[x]` xong · `[~]` đang chạy · `[ ]` chưa làm · **(cần bạn)** là việc chỉ bạn làm được.

## Đang chạy

- [x] **LID-DS** (Pulse 5.32, xong 29/10 15:01): hệ thống 77,3% phát hiện, 3,0% bản ghi normal bị báo nhầm; STIDE 100% / 60,8%; biên nhận `results-20261029/lidds/`. [ ] Chạy lại độ nhạy với alias tên syscall (`lidds-evaluation-v1` amendment 1) **sau** lượt live calibration; xong thì xóa `/var/tmp/lid-ds-2021/converted*` trên `.234` (giữ 15 file zip).
- [x] **G7, độ trễ request của ứng dụng có/không probe** (Pulse 5.30): p50 +0,5–3%, p95 +3–8% ở trung vị; CI quá rộng để nói dưới 5% (luật đăng ký); probe 0,09–0,21 core mỗi node; biên nhận `results-20261029/app-overhead/`, dữ liệu thô trên `.234` đã xóa.
- [x] **Smoke calibration tự làm mới** `pulse-recal-smoke` (14:57 → 16:13): epoch 1 áp dụng lúc 16:05 trên 3 worker, kiểm cài đặt khớp 100% (62.887 dòng); biên nhận `results-20261029/recal-smoke/`; đã dọn.
- [x] **Nghiên cứu cải thiện Pulse trên LID-DS** (29/10, báo cáo `reports/Cải thiện Pulse trên LID DS.md`, ghi chú `research_notes/Cải thiện Pulse trên LID DS/`): 407/412 bản ghi bỏ sót là exploit chỉ đổi dữ liệu (path, số byte, errno); chưa nguồn nào đạt 90–95% với báo nhầm thấp trên đủ 15 kịch bản LID-DS 2021. Lộ trình 4 bậc (trần cộng dồn): chỉnh trong khung ≤ 87%; feature argument/return (tiền tố path mới, errno, histogram byte) ≤ 93,5%; n-gram theo thread có ngưỡng ≤ 100% (tín hiệu duy nhất cho Heartbleed). [x] Chủ đồ án cho làm (29/10); protocol `lidds-evaluation-v2` đăng ký 21:30 (H1 ≥ 90% @ ≤ 3,0% báo nhầm, H2 ≥ 95%, H3 không thụt lùi); code + 7 test; [~] unit `lid-ds-v2` chờ phân tích lượt live xong rồi tự chạy (chuyển đổi alias + chấm v2). [ ] Đọc kết quả v2. [ ] Protocol + tải + chạy xác nhận trên LID-DS 2019 và CB-DS. [ ] Nếu v2 đạt: đưa tín hiệu mới vào probe eBPF (hook `sys_exit`, `security_file_open`, lịch sử syscall theo thread), đo overhead, lượt live có fixture trong process. [ ] Sau v2: xóa `/var/tmp/lid-ds-2021/converted` (v1) nếu không cần nữa.
- [~] **Lượt `pulse-live-recal-confirm`** (protocol `live-recalibration-confirmation-v1`): khởi chạy 29/10 16:16, pha chọn tới 17:49, capture 24 giờ; unit `after-recal-confirm` tự phân tích. Đọc kết quả khoảng 18:30 ngày 30/10; sau đó chạy lại LID-DS (amendment 1).

Các mục dưới là việc đã xong gần đây.


- [x] **`after-stable-refreshed`**: final, baseline lặp lại, chiến lược calibration (Pulse 5.13b, 5.15b, 5.17) và nén 3 lượt (NFS 291 → 85 GB) xong 16:17.
- [x] **`pulse-stable-selection-1022`**: replay cấu hình gộp đạt (16:28).
- [x] **Lượt live `pulse-peer-discount-confirm`** (Pulse 5.26, 5.27): 24/10 10:55 → 25/10 11:06, **xác nhận** ở mức ≤ 3 s (recall 98,7%, precision 98,7%, control 1,3%, p95 2,88 s) → `policy-k2of2-a5-peer30` là ML stable. [x] Final chạy lại: gánh live 1,69 đợt/replica-giờ (−63% so với CUSUM `keep`, −72% so với stable cũ; điều kiện gánh đạt), kiểm cài đặt 99,9999%. [x] Log Falco lên NFS; bridge và subscriber RCA dừng, biên nhận vào repo. [ ] Kafka worker1 vẫn lệch (preview 4,25% so với ~0,05%): calibration theo replica hoặc dựng lại broker.
- [x] **Lượt live xác nhận `pulse-stable-confirm`**: 23/10 01:19 → 24/10 01:29, 3 worker success. Campaign **không đạt luật** (precision 94,6%, control 5,8%); test blind 5.22 mức ≤ 3 s **đạt** (Pulse 5.25).
- [x] **`feature-groups-primary-1022`**: xong 23/10 00:35; gộp ở syscall 5B.3. [x] `fg-branches-1023`: xong 23/10 01:27, cả hai nhánh p-value đều cần (5B.3).
- [x] **`after-stable-confirm`** (snapshot `1e2ae7f`): [x] giai đoạn campaign xong 12:33 (Pulse 5.25, RCA 5.15); [x] final xong 24/10 02:29, nén xong 02:50 (gánh live + CI, test blind 5.22, lý do nghi phạm RCA, phân loại cảnh báo), rồi nén.
- [x] **`pulse-57d-1022`**: 5.7d xong (`rolling-12-1` −37% trên soak 48 giờ).
- [x] **`syscall-cusum-1022`**: xong 02:30; 11 cấu hình và nhóm feature dưới CUSUM `cap` không đổi kết luận nào (SYSCALL 5C).
- [x] **`pulse-alert-bridge-pulse-stable-confirm`** (RCA 5.14): chạy hết lượt, dừng 24/10 01:47; biên nhận trên NFS và trong `results-20261023/alert-bridge/`.
- [x] **CUSUM nhớ alarm sang trial sau** (5.19 bổ sung 1): phát hiện trước khi chạy live, sửa bằng `cap`, đóng băng lại.
- [x] **`pulse-burden-levers-1022`** (Pulse 5.22): xong 17:26; đề xuất cho cả 2 mức độ trễ (chiết khấu theo replica), chờ test blind.

## Việc kế tiếp (theo thứ tự)

1. [x] 16:28: replay cấu hình gộp đạt (5.19 bước 3); đóng băng `policy-cusum-b3-h6.json` (`9bf0b216…`).
2. [x] Kết quả `burden-reduction-v1` (5.22): đề xuất mức < 2 s (2,2–2,3 đợt) và ≤ 3 s (1,5–1,7 đợt). [x] Test blind trên lượt xác nhận: mức ≤ 3 s **đạt** (replica 30 s + k2of2 α×5: gánh 1,74, control 2,9%, precision 97,2%, p95 2,68 s), mức < 2 s không đạt (p95 2,16 s). [x] Chiết khấu theo replica trong đường live (5.26). [~] Lượt live xác nhận `pulse-peer-discount-confirm` (protocol `peer-discount-confirmation-v1`): chạy từ 24/10 10:55, campaign xong khoảng 22:00, capture tới khoảng 25/10 11:00; [x] chép log Falco giữa lượt (22:05); [ ] sau lượt: chép lần cuối rồi lên NFS. [ ] Lượt sau: khoảng hở nhịp chấm do page cache chạm `MemoryMax` (giả thuyết, 5.26): `posix_fadvise(DONTNEED)` sau ghi hoặc nâng `MemoryMax`; bỏ ghi NFS khỏi vòng chấm điểm. [x] Đẩy Alertmanager thất bại của bridge (25/10): 13 lần quá hạn 3 s trong 4 đợt (24/10 08:23, 10:41, 15:35, 16:56 UTC), làm 6/5.181 episode không tới qua đường push (episode ngắn hơn chu kỳ refresh 5 s nên không có lần đẩy khác); sửa: thử lại tối đa 3 lần cách 0,5 s, lần refresh cũng ghi nhận lần tới đầu tiên (`alert_bridge.py`, có test), áp dụng từ lượt sau.
3. [x] Lượt live xác nhận `pulse-stable-confirm` (5.19 bước 4): xong 24/10 01:29; không đạt; tốc độ 1, 3/s (G4) có số; test blind 5.22 đạt mức ≤ 3 s; dữ liệu cho so sánh có/không rule.
3b. [x] Log Falco của lượt xác nhận (xong 24/10 01:45, trên NFS `pulse-stable-confirm/falco-logs/`, SHA khớp, bản local đã xóa): [x] chép lần 1 về đĩa local từng worker (`/var/tmp/falco-logs-pulse-stable-confirm/`, 23/10 11:40; worker1 xoay vòng 4 giờ/lần nên phải chép giữa lượt). [x] Lần 2 (13:05, `cp -u`): đã có file xoay vòng 05:15 UTC của worker1; file xoay vòng còn được giữ ~16 giờ nên lần chép cuối sau lượt là đủ. [x] Sau lượt: chép lần cuối, chuyển lên NFS (24/10 01:45); giữ tới khi so sánh có/không rule xong.
4. [x] Nhóm feature trên holdout chính đã gộp (5B.3); 5C bản `cap` cho 11 cấu hình xong. [x] 2 biến thể p-value (cần cả hai). [x] Nhóm feature dưới `cap`: không đổi kết luận (5C).
5. [x] **ML đã hoàn thiện 25/10** (stable `policy-k2of2-a5-peer30`, Pulse 5.27); việc tiếp: tích hợp rule và **so sánh không có rule với có rule** trên cùng dữ liệu ([RULE_INTEGRATION_STATUS](RULE_INTEGRATION_STATUS.md) R6). [x] Bổ sung 2 của protocol (12:56), code + test (13:07). [x] R6 xong 16:02 (RULE_INTEGRATION_STATUS R6): không rule nào tăng recall ở tập chính; ML + tripwire là nhánh duy nhất giữ mọi số ML ở mức ≤ 3 s (p95 −0,47 s, gánh +0,066 đợt/replica-giờ, recall tốc độ chậm +2,1 điểm); Falco mặc định +79% gánh do một rule trên một workload; triage chờ case RCA −23% gánh nhưng p95 5,90 s. [x] Chủ đồ án chọn hệ thống cuối = ML + tripwire (B2, 25/10 17:30). [x] Tripwire A1 chạy trong worker live (Pulse 5.28, 5.29). [x] Dữ liệu phụ `pulse-stable-confirm` (chỉ báo cáo, 17:02): cùng hướng. [ ] Đường triage nhanh nếu muốn dùng B3.
6. [~] **Viết luận văn bằng LaTeX** (chủ đồ án 29/10): `thesis/` (Tectonic, `cd thesis && tectonic main.tex`), 8 chương + tài liệu tham khảo (natbib từ `references/catalog.json`), 7 hình; G7 (6.11) và LID-DS (6.12) đã điền. Bản Claude Docs là nháp cũ, không sửa nữa. [ ] Trang bìa: tên trường, khoa, học viên, người hướng dẫn (**cần bạn**); [ ] kết quả lượt calibration tự làm mới; [ ] lượt chạy lại LID-DS.
7. [x] **Lượt live của hệ thống cuối đạt** (Pulse 5.29, đọc 29/10): S recall 99,4%, precision 99,4%, control 0,6%, p95 1,97 s; gánh tripwire +0,049 [+0,005; +0,124]; tripwire live khớp offline 100%. RCA 5.17: top-1 tụt 99,8% → 14,1% (binary vô hại tên riêng đứng hạng 1), số attack bị gộp không giảm (40). [x] Dọn sau lượt: unit, bản decision local, bản bridge local (đã lên NFS, trùng từng byte), launcher, env, snapshot phân tích, 14 bản sao code RCA trong `/opt/sentinel-pulse-rca/`. [x] RCA: quy từng trial bị gộp cho một lý do từ chối (`rca_grouping_causes.py`, RCA 5.17: bước kiểm exec chiếm 25/40). [x] Code ghi vết quyết định case tiếp nối + thời điểm nhận exec (RCA 5.18, bật từ lượt sau). [ ] Đo độ trễ của exec log so với case theo sau ở lượt sau; [x] luật phá hoà xếp hạng: theo tên là artifact, theo thời điểm khởi chạy cho top-1 14,1% → 100% (development, RCA 5.19); [ ] kiểm blind trên `pulse-live-recal-confirm` sau campaign (protocol `rca-ranking-recency-v1`); [ ] một lượt có thứ tự binary vô hại/tấn công ngẫu nhiên; luật xếp hạng cho hai process mới gần nhau. Ghi chú gốc: một lượt live 24 giờ của hệ thống cuối (ML đóng băng + tripwire trong worker) để có bằng chứng cho các sửa đổi mới. Code phải làm trước: tripwire live trong worker; tách ghi NFS khỏi vòng chấm điểm (ghi qua hàng đợi riêng hoặc đĩa local rồi chép); RCA nhận trigger từ Alertmanager (code có, chưa chạy live); bridge thử lại push lỗi (có); đổi tên binary vô hại (đăng ký trước). Không gộp calibration tự làm mới vào lượt này: nó đổi ML và sẽ cần một lượt xác nhận riêng.
8. [ ] Cho paper (RESEARCH_IDEAS, mục "Đủ bằng chứng để viết paper chưa?"): LID-DS (G3, một phần G2; [x] đã tải 15/15 file, 87 GB, mỗi zip qua `testzip`, headless Chromium trên `.234` vì Proton Drive giải mã trong trình duyệt; [x] bộ chuyển đổi `sentinel_pulse/lidds/convert.py` dựng lại frame của loader eBPF rồi chạy qua đúng `ExtendedFeatureStream`, có test, thử trên 200 bản ghi thật: 249 feature, 0 tên syscall không ánh xạ; [x] protocol `lidds-evaluation-v1` đăng ký 29/10 09:17 trước mọi fit (tham số lấy nguyên từ hệ thống live, không chỉnh trên LID-DS); [x] script `lidds_evaluate.py` có test đầu-cuối; [~] 29/10 từ 09:10: `lid-ds-convert` (4 kịch bản song song) rồi `lid-ds-evaluate` tự chạy trên `.234` (ML, tripwire, hệ thống, STIDE)), exploit thật (G2, chủ đồ án tự dựng), [~] độ trễ ứng dụng (G7, đang đo, Pulse 5.30). Chủ đồ án quyết định 29/10: **không làm** review nhãn độc lập (G8), bản gốc của 10 tài liệu dựng lại, balloon ESXi và kiểm overhead trên kernel/distro khác; các điểm này ghi là giới hạn.
9. [x] **Calibration tự làm mới khi live: code** (Pulse 5.31; `pipeline/live_recalibration.py`, `rolling-12-1`, 6 test, chưa chạy). [ ] Smoke trên cụm sau khi G7 xong. [ ] Protocol và lượt xác nhận riêng (đổi ML). Chủ đồ án quyết định 29/10: loại khoảng campaign như bản offline, ghi là giới hạn. Đã có 7 hình và bảng tổng hợp lượt live (`docs/figures/`, sinh lại bằng `scripts/figures/thesis_figures.py`).

## Pulse — vấn đề còn mở

- [~] **Gánh cảnh báo, control, false positive:** CUSUM b3/h6 giảm còn 5,32 đợt/replica-giờ (−21%, 5.13b), ngân sách 0,1. Chỉnh ngưỡng không giải được (CUSUM đã tối ưu khi bằng chứng cố định). Bằng chứng tốt hơn: chiết khấu theo replica đạt test blind (1,74 đợt/replica-giờ, 5.25), đang xác nhận live (5.26).
  - [x] Calibration theo (workload, node) (5.6b): là `mondrian-6-1` của 5.17; không thắng trên dữ liệu mới, không thắng trên soak (p95).
  - [x] Phân rã theo thời gian (5.23): 90 phút traffic thay đổi gấp ~2 lần traffic ổn định; không drift trong 20 giờ. [ ] Một lượt có chế độ traffic rải suốt lượt để đo gánh dưới traffic biến động (cho paper).
  - [x] Review các đợt kéo dài trên lượt xác nhận (5.24): postgres worker1 báo 96% thời gian do replica CNPG `cnpg-2` hỏng sau failover 22/10 09:41 UTC (sự cố thật, không phải tấn công). [x] Kafka worker1 (67,7% thời gian, 6/18 control dương; 5.25): replica lệch hệ thống so với 2 broker kia (trung vị tree_p 0,05 so với 0,37–0,67; preview 46,5% so với ~4%), calibration gộp theo workload không phù hợp; chiết khấu theo replica xử lý được. [ ] Sau lượt (khi giai đoạn final đã dựng bảng cửa sổ): `python3 scripts/analysis/replica_compare.py --table /var/tmp/burden-levers/table-pulse-stable-confirm.npz --workload production/aims-kafka-dual-role:kafka --exclude 1792698877,1792733344 --output /mnt/sentinel-pulse-archive/pulse-stable-confirm/analysis/kafka-replicas.json` (so `tree_p`/`support_p`, phần cửa sổ bị gắn cờ có/không exec của 3 broker, ngoài khoảng campaign; chỉ mô tả). Chạy tương tự cho `aims-postgres-cnpg:postgres` và `inventory-service:app`.
  - [x] Sửa replica `cnpg-2` (24/10 01:38, dựng lại từ primary, stream trên timeline 9; Pulse 5.25). [x] Báo cáo lượt xác nhận tách riêng đóng góp của container này (post-hoc, 5.25).
- [ ] **Tách attack khỏi process vô hại mới (G5):** ML vẫn gắn cờ 80,7–95,1% binary vô hại qua 6 lượt live (89,7% ở lượt cuối); tripwire (trong hệ thống cuối) chỉ tách được lớp syscall hiếm.
  - [x] Độ bền tín hiệu: T = 5 s, f = 0,7 lặp lại trên lượt mới (tách khoảng 35 điểm, p95 6,5 s, chỉ dùng làm triage). Chờ 1 s: p95 3,23 s, không đạt.
  - [x] Novelty có xét exec (5.7c, 5.8h): 100% cho `ptrace`/`execveat`/`setns`, binary vô hại 0,3%.
  - [x] Tripwire A1 (rule) đạt blind: xem [phần rule](RULE_INTEGRATION_STATUS.md) R3.
  - [ ] Thông tin ngoài tần suất: tham số syscall, quan hệ cha–con của process từ Tetragon.
- [x] **Độ trễ:** CUSUM b3/h6 đạt blind (5.13b): p95 1,70 s, mức < 2 s, gánh còn giảm. Cauchy trượt (gánh +16%).
- [x] **Bằng chứng gần tối ưu cho chính sách** (5.8j, 5.13b): lưới mịn trên 2 lượt; gánh thấp nhất trong tập khả thi ổn định (~4 đợt); CUSUM trội mọi k-of-n ở mức < 2 s.
- [x] **Baseline trên cùng dữ liệu (5.15a, 5.15b):** AE và `tree_ae` không thay base29 trên dữ liệu mới (tách kém khoảng 26 điểm). [x] Kiểm định nhiều so sánh (Holm, 24 phép kiểm, 24/10): kết luận ở ngân sách 1 đứng vững.
- [x] Recall theo tốc độ attack (5.15c): Pulse yếu dần ở 6/s. [x] Campaign 1–3/s (5.25): recall 93,1% ở 1/s, 99,0% ở 3/s; p95 3,4–4,3 s.
- [ ] Recall thấp ở `mprotect` và `seccomp` khi ngân sách chặt (syscall 5.8).
- [x] Đo độ trễ kernel → cảnh báo đến người nhận thật (RCA 5.14): trên toàn campaign, push p95 2,89 s tập chính (268/282 trial có cảnh báo mới; 3,04 s nếu chỉ tính đợt mở từ cửa sổ nằm trọn trong trial), 3,56 s mọi tốc độ. [ ] Chép biên nhận vào repo sau lượt.
- [x] Review nhãn (5.20): 4.766 cảnh báo normal, không case nào có dấu hiệu độc hại; người gán không độc lập.
- [ ] Khi viết luận văn: mục mô hình đe dọa + bảng độ phủ ATT&CK (RESEARCH_IDEAS mục 5); nêu recall là cận trên với đường vào qua exec.
- [x] Baseline luật Falco: chuyển sang [phần rule](RULE_INTEGRATION_STATUS.md) R2 (trial và normal xong).
- [ ] Kịch bản tấn công thật (G2): để mở. Claude không tự dựng phần này (22/10); nếu làm cho paper thì chủ đồ án tự triển khai trong môi trường riêng.
- [~] Dataset công khai LID-DS (G3): đã tải, đã có bộ chuyển đổi, protocol `lidds-evaluation-v1` đăng ký; chuyển đổi và đánh giá đang chạy (29/10, mục "Việc kế tiếp" 8).

## Thí nghiệm syscall — còn lại

- [x] Giai đoạn B nhóm feature trên holdout thứ hai (syscall 5B.2, tạm thời): không thành phần nào bỏ được; Pulse 4b đã cập nhật.
- [x] Giai đoạn B trên holdout chính và `pulse-attack-dev`: xong, gộp theo luật bổ sung (5B.3).
- [x] Pulse 5.7d xong (`rolling-12-1` −37% trên soak).
- [x] 5C: 11 cấu hình + nhóm feature dưới CUSUM `keep`/`cap`: không đổi kết luận nào.
- [ ] Paired blind attack theo protocol v2. Chưa mở được, vì chưa cấu hình nào đạt ngân sách 0,1 đợt/giờ; ghi là giới hạn.

## RCA — còn lại

- [x] Luật `privilege_drop_at_start` trên dữ liệu mới (RCA 5.11): top-1 100%, luật cũ 91,9%.
- [~] Attack không có case riêng: 42/315 (5.11); 69/525 ở `pulse-stable-confirm` (56 gộp sau case binary vô hại, 5.15); 65/524 ở `pulse-peer-discount-confirm`; 56/525 ở lượt cuối (40 gộp sau case binary vô hại, RCA 5.17). [x] Đặt tên file khác cho binary vô hại (lượt cuối): **không** giảm số bị gộp. [x] Quy nguyên nhân từng trial (29/10, `rca_grouping_causes.py`): 25/40 do bước kiểm exec của case tiếp nối, 8 không có episode mới, 5 quá gần case trước, 2 đợt cảnh báo kéo dài. [ ] Lượt sau: đo độ trễ sự kiện exec vào exec log so với lúc quyết định (giả thuyết: exec chưa vào log khi trigger tới).
- [x] Baseline binary mang qua các lượt (RCA 5.12): seed từ khoảng normal của 2 lượt trước, dùng từ lượt `pulse-stable-confirm`. [x] Hiệu quả trên lượt đó: binary mới/chưa biết ở hạng 1 giảm 11,3% → 6,8% case normal (RCA 5.15).
- [x] Nhãn triage probe trên mỗi case (chỉ là nhãn), chạy từ lượt sau.
- [x] Cảnh báo vận hành thật (RCA 5.14, 5.17): Pulse → Alertmanager/Prometheus/Grafana chạy hết 3 lượt cuối; RCA dựng case từ cảnh báo Alertmanager đã giao (chế độ `alert_trigger_file`) chạy live ở lượt cuối; kernel → người nhận qua push p95 2,31 s (mọi tốc độ, ML + tripwire).
- [x] Ánh xạ IP node (hostNetwork/SNAT) bị gán nhầm cho node-exporter: sửa thành `Node` không xác định (RCA 5.13, áp dụng lượt sau). [x] Lịch sử inventory: không làm, có lý do (0,9% IP trong cụm không ánh xạ được, RCA 5.13). [x] Địa chỉ probe kubelet của Istio ambient → `KubeletProbe`. [ ] Backend sau DNAT và client thật sau waypoint (Istio ambient; cần Hubble hoặc access log) — ghi là giới hạn nếu không làm.

- [x] **Zombie dưới Tetragon (25/10, đã sửa, xem mục dọn tài nguyên):** mỗi lần luồng `tetra getevents` của RCA xoay vòng (`timeout 900` qua `kubectl exec`) để lại một process `timeout` zombie. Tetragon là PID 1 trong namespace PID riêng và không thu dọn chúng. Đếm 25/10 16:45: worker1 1.983, worker4 1.523, worker3 425 (khoảng 300/ngày trên worker1 từ 18/10); `pids.max` 154.589 nên chưa hại. Sửa trước lượt RCA sau: `shareProcessNamespace: true` trên DaemonSet `tetragon` (pause container làm PID 1, thu dọn zombie); khởi động lại pod Tetragon thì xóa được số đã có. Sự kiện cùng đợt: `cnpg-2` khởi động lại sạch (exit 0) lúc 25/10 04:25 UTC, lúc containerd trên worker1 bị nghẽn ("context deadline exceeded"); cụm CNPG khỏe, 3/3.

## Repo và bằng chứng

- [x] Biên nhận 22–23/10 chép vào `validation-evidence/results-20261022/` (README ghi script và bản gốc của từng file); ví dụ cây RCA thật (`validation-evidence/rca/examples-20261023/`).
- [x] README gốc: hướng dẫn đọc repo, từ con số đến bằng chứng.
- [x] `references/`: danh mục 87 nguồn; 70 bài, mỗi bài một PDF tên `năm-tác giả-tiêu đề` (60 bản gốc, 10 bản dựng lại; ngoài git, bản sao NFS). [x] Tổng hợp tri thức theo chủ đề cho luận văn: `references/KNOWLEDGE_SYNTHESIS.md` (23/10). Bản gốc của 10 bài dựng lại: **không làm** (chủ đồ án, 29/10); khi viết, không trích số liệu chỉ có trong bản dựng lại.
- [x] Biên nhận lượt `pulse-stable-confirm`: campaign, final, so sánh replica, bridge trong `validation-evidence/results-20261023/`; log Falco trên NFS.
- [x] Quét repo 23/10: link hỏng trong mọi `.md` đã sửa; gỡ snapshot cũ `SENTINEL_PULSE_VA_THI_NGHIEM_SYSCALL.md` (bản gốc qua `git show 5e1ed2f:…`); không có bí mật trong file tracked; mọi script job đều được báo cáo nhắc tới; bảng tên gọi và trạng thái cập nhật.
- [x] 1,3 GB dữ liệu thô cũ (pulse500, projected, canary 08–10/2026; 642 file): đã chuyển lên `/mnt/sentinel-pulse-archive/host-evidence-pre-refactor-20261023/` (24/10 01:58, `SHA256SUMS` khớp trên NFS và khớp bản host trước khi xóa); đã xóa bản ở host, bản tạm trên `.234` và 5 dòng trong `.gitignore`.

## Hạ tầng

- [x] `.234`: `mask` `unattended-upgrades`, `apt-daily-upgrade.timer`, `apt-daily.timer` như worker (24/10), sau khi tự nâng cấp `zlib1g` đã khởi động lại bridge và subscriber RCA giữa lượt (Pulse 5.25). Nâng cấp gói làm tay khi không có lượt live.

- [x] Collector 1 s đã dừng, tắt và xóa dữ liệu (22/10 12:47).
- [x] Đã xóa `/var/tmp/pulse-live-copy`, `falco-baseline` và 4 snapshot không dùng (22/10). [x] `/var/tmp/syscall-cusum` (4 GB, bản sao NFS, đã đối chiếu danh sách file) xóa 23/10. [x] `/var/tmp/feature-groups` (7,6 GB): đã nằm trên NFS `matched-parallel-r4-20261015/feature-groups/` (kiểm 25/10, 7,6 GB), bản trên `.234` không còn. Giữ `/var/tmp/burden-levers` (calibration và bảng cửa sổ 2 lượt xác nhận) và `/var/tmp/baselines/models` (model baseline đóng băng).
- [x] Nén `pulse-stable-candidate`, `pulse-stable-refreshed`, soak 48 giờ (NFS 291 → 85 GB, 22/10 16:17).

- [x] **Dọn tài nguyên cụm (29/10 09:40):** zombie `timeout` cuối cùng (dưới redis của `redis-ha-node-0`, replica; master là node-2) hết sau khi xóa pod, replica đồng bộ lại; 0 zombie trên 7 máy. Xóa file Pulse cũ trong `/tmp` (28/9–14/10: bundle, script, unit, bản sao báo cáo) trên 3 worker và `.234`, venv và trình duyệt Playwright (683 MB, chỉ dùng để tải LID-DS), 2 file lock rỗng trong `/home/dat`. Giữ: `/var/tmp/burden-levers`, `/var/tmp/baselines/models`, file `/tmp` không rõ là của dự án (`aims_*`, file tạm không tên), file cá nhân.
- [x] **Dọn tài nguyên cụm (25/10 17:10–17:40, sau khi mọi job xong):**
  - Zombie: 3.931 process `timeout` dưới Tetragon (3 worker) và 45 dưới `redis-ha` → 0 trên cả 7 máy. Tetragon: `shareProcessNamespace: true` trên DaemonSet (sửa gốc; kiểm 3 lệnh `timeout … tetra getevents` qua `kubectl exec` không còn để lại zombie). Lưu ý: DaemonSet do Helm quản lý (release `tetragon`, values mặc định), `helm upgrade` sau này sẽ ghi đè thay đổi này. `redis-ha`: khởi động lại container redis tại chỗ (`crictl stop`) từng pod một, không xóa pod (image `bitnami/redis:latest`, `IfNotPresent`).
  - Unit của 4 lượt đã xong: 12 unit trên `.234` (campaign, traffic, RCA), 4 unit worker mỗi node, unit collector 1 s và `control-rotate` (đã tắt từ 22/10). Các unit này vẫn đang **enabled** trong `multi-user.target.wants`, nên sẽ tự chạy lại nếu máy khởi động lại; đã gỡ cả symlink. Unit transient launcher bị lỗi đã `reset-failed`.
  - Config worker của các lượt cũ trong `/etc/sentinel-pulse/` (6 file mỗi worker; giữ config của lượt cuối `pulse-peer-discount-confirm`) và 3 file env của launcher các lượt đã xong trên `.234` (`launch-*.env`, quyền 600).
  - `.234`: bảng cửa sổ `pulse-stable-candidate`/`refreshed` (1,8 GB, sinh lại được bằng `burden_levers.sh`), 2 snapshot nguồn, bản sao JSON đã có biên nhận trong repo; `/var/tmp/baselines` trừ `models` (model baseline đóng băng, protocol `baseline-fresh-replication-v1` trỏ tới); `/var/tmp/rule-integration`; trạng thái bridge local (trùng NFS từng byte) và 2 snapshot nguồn của bridge; 52 file script tạm của Claude trong `/tmp` (từ 15/10). Giữ: `cal-pulse-live-recalibrated.npz` và bảng cửa sổ của 2 lượt xác nhận.
  - NFS: 3 snapshot `runtime-*` mà không config lượt chạy nào trỏ tới (`11492a4`, `16982eb`, `9d1e477`, của các job phân tích 22/10). Báo cáo nhắc 3 sha này như commit của code đã chạy; cả 3 là commit trong git, nên code vẫn lấy lại được bằng `git archive <sha>`.
  - Giữ có chủ đích: `/opt/sentinel-pulse/models` trên worker (bản duy nhất của model thế hệ trước mà bằng chứng 06–14/10 trong repo trỏ tới), `/home/dat/pulse-matched-20261015` (loader eBPF và proof của worker đang dùng), dữ liệu RCA các lượt trong `/var/lib/sentinel-pulse-rca/`, các file trước 15/10 và file cá nhân.
  - Đường dẫn `/var/tmp/...` ghi trong biên nhận JSON là nơi chạy gốc; giữ nguyên vì là bản ghi lịch sử.
- [x] `.234` (25/10 17:54): cài thư viện cho Chromium headless (Playwright, để tải LID-DS); apt nâng kèm bản vá `libglib2.0` và needrestart khởi động lại vài dịch vụ hệ thống (polkit, udisks2, open-vm-tools, ModemManager…). kubelet, containerd và control plane không bị khởi động lại (kiểm ngay sau đó). Đã có sẵn kernel 6.8.0-147 chờ reboot từ trước, không reboot.
- [x] Xóa 15 config RCA của các lượt đã xong trong `/etc/sentinel-pulse-rca/` (25/10 18:28).
- [x] RAM NFS (`k8s-nfs`): chủ đồ án nâng cấu hình và khởi động lại 24/10 10:35 (31 GiB RAM, 8 CPU); cả 6 node đọc được mount, ghi thử 64 MiB đạt 307 MB/s.
- Balloon RAM của ESXi: **không làm** (chủ đồ án, 29/10).
- [x] Đo overhead A/B (G7, Pulse 5.21): ~250–450 ns mỗi syscall khi theo dõi, ~80–230 ns khi không (microbenchmark, worker4). Kernel/distro khác: **không làm** (chủ đồ án, 29/10; giới hạn: chỉ Ubuntu 24.04 x86-64). [~] Độ trễ request của ứng dụng thật có/không probe (Pulse 5.30).

## Quy tắc đang áp dụng

- Không chạy job đọc NFS nặng hoặc tốn RAM trên bất kỳ node nào khi lượt live đang chạy; không chạy trên master2/master3.
- Lượt live chạy hết chu kỳ, không dừng giữa chừng; khoảng thời gian xấu được loại trừ khi phân tích.
- Không thử reboot, mất NFS, backlog hay thao tác nào tác động vào hạ tầng.
- Không cài watcher; khi có job chạy ngầm, ghi giờ cần nhắc.
- Code đồng bộ giữa GitHub `main`, máy local và `/home/dat/eBPF-project` trên .234 và 3 worker (`scripts/sync_cluster_checkouts.sh` sau mỗi lần push).
- Phép đo mới phải đăng ký tiêu chí trước khi có số; không đổi lựa chọn sau khi xem kết quả.
- Rule (Falco, tripwire) chỉ quyết định song song với ML, tích hợp sau cùng, khi ML đã stable.
- Chỉ giữ tài nguyên còn được tham chiếu; dọn đồ thừa của job ngay; không đụng file cá nhân và backup của chủ đồ án.
