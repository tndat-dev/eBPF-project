# TODO — đồ án Sentinel Pulse

Cập nhật 23/10/2026 13:20. Số liệu và bằng chứng chi tiết: [Pulse](SENTINEL_PULSE_STATUS.md) ·
[syscall](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) · [RCA](RCA_RUNTIME_STATUS.md) · [rule, tách khỏi ML](RULE_INTEGRATION_STATUS.md) · [đánh giá tổng thể và ý tưởng](RESEARCH_IDEAS.md).
Ký hiệu: `[x]` xong · `[~]` đang chạy · `[ ]` chưa làm · **(cần bạn)** là việc chỉ bạn làm được.

## Đang chạy

- [x] **`after-stable-refreshed`**: final, baseline lặp lại, chiến lược calibration (Pulse 5.13b, 5.15b, 5.17) và nén 3 lượt (NFS 291 → 85 GB) xong 16:17.
- [x] **`pulse-stable-selection-1022`**: replay cấu hình gộp đạt (16:28).
- [~] **Lượt live xác nhận `pulse-stable-confirm`**: 23/10 01:19 → 24/10 01:29 (chính sách `cap`, `93dd1478`), 3 worker success. [x] Campaign xong 12:29: **không đạt luật** (precision 94,6%, control 5,8%, recall 100%, p95 2,53 s; Pulse 5.25). [ ] Final: gánh cảnh báo, test blind 5.22, so sánh có/không rule.
- [x] **`feature-groups-primary-1022`**: xong 23/10 00:35; gộp ở syscall 5B.3. [x] `fg-branches-1023`: xong 23/10 01:27, cả hai nhánh p-value đều cần (5B.3).
- [~] **`after-stable-confirm`** (snapshot `1e2ae7f`): [x] giai đoạn campaign xong 12:33 (Pulse 5.25, RCA 5.15); [ ] final (gánh live + CI, test blind 5.22, lý do nghi phạm RCA, phân loại cảnh báo), rồi nén.
- [x] **`pulse-57d-1022`**: 5.7d xong (`rolling-12-1` −37% trên soak 48 giờ).
- [x] **`syscall-cusum-1022`**: xong 02:30; 11 cấu hình và nhóm feature dưới CUSUM `cap` không đổi kết luận nào (SYSCALL 5C).
- [~] **`pulse-alert-bridge-pulse-stable-confirm`** (RCA 5.14): đường cảnh báo vận hành thật, chạy hết lượt xác nhận; chép biên nhận và ghép với thời điểm kernel sau lượt.
- [x] **CUSUM nhớ alarm sang trial sau** (5.19 bổ sung 1): phát hiện trước khi chạy live, sửa bằng `cap`, đóng băng lại.
- [x] **`pulse-burden-levers-1022`** (Pulse 5.22): xong 17:26; đề xuất cho cả 2 mức độ trễ (chiết khấu theo replica), chờ test blind.

## Việc kế tiếp (theo thứ tự)

1. [x] 16:28: replay cấu hình gộp đạt (5.19 bước 3); đóng băng `policy-cusum-b3-h6.json` (`9bf0b216…`).
2. [x] Kết quả `burden-reduction-v1` (5.22): đề xuất mức < 2 s (2,2–2,3 đợt) và ≤ 3 s (1,5–1,7 đợt); test blind trên lượt xác nhận.
3. [~] Lượt live xác nhận `pulse-stable-confirm` (5.19 bước 4, `stable-confirmation-v1` + bổ sung 1, chính sách `cap`): chạy từ 23/10 01:19, 24 giờ. Kèm tốc độ 1, 3/s (G4); test blind cho 5.22; dữ liệu cho so sánh có/không rule.
3b. [x] Log Falco của lượt xác nhận (xong 24/10 01:45, trên NFS `pulse-stable-confirm/falco-logs/`, SHA khớp, bản local đã xóa): [x] chép lần 1 về đĩa local từng worker (`/var/tmp/falco-logs-pulse-stable-confirm/`, 23/10 11:40; worker1 xoay vòng 4 giờ/lần nên phải chép giữa lượt). [x] Lần 2 (13:05, `cp -u`): đã có file xoay vòng 05:15 UTC của worker1; file xoay vòng còn được giữ ~16 giờ nên lần chép cuối sau lượt là đủ. [ ] Ngay sau lượt: chép bổ sung file mới rồi chuyển lên NFS; giữ tới khi so sánh có/không rule xong.
4. [x] Nhóm feature trên holdout chính đã gộp (5B.3); 5C bản `cap` cho 11 cấu hình xong. [x] 2 biến thể p-value (cần cả hai). [x] Nhóm feature dưới `cap`: không đổi kết luận (5C).
5. [ ] **Sau khi ML hoàn thiện** (stable đóng băng, 5.22 quyết xong, lượt live xác nhận xong): tích hợp rule và **so sánh không có rule với có rule** trên cùng dữ liệu ([RULE_INTEGRATION_STATUS](RULE_INTEGRATION_STATUS.md) R6). Trong lượt live xác nhận: giữ log Falco, chạy tripwire trên normal, RCA gắn nhãn triage mọi case.
6. [ ] Viết luận văn **chỉ sau khi** bằng chứng của cả Pulse, thí nghiệm syscall và RCA đầy đủ (quyết định 22/10). Đã có 4 hình (`docs/figures/`, sinh lại bằng `scripts/figures/thesis_figures.py`).

## Pulse — vấn đề còn mở

- [~] **Gánh cảnh báo, control, false positive:** CUSUM b3/h6 giảm còn 5,32 đợt/replica-giờ (−21%, 5.13b), ngân sách 0,1. Chỉnh ngưỡng không giải được (CUSUM đã tối ưu khi bằng chứng cố định). Đang thử bằng chứng tốt hơn: calibration theo lớp launch, so với replica khác, so với lịch sử của chính container (5.22).
  - [x] Calibration theo (workload, node) (5.6b): là `mondrian-6-1` của 5.17; không thắng trên dữ liệu mới, không thắng trên soak (p95).
  - [x] Phân rã theo thời gian (5.23): 90 phút traffic thay đổi gấp ~2 lần traffic ổn định; không drift trong 20 giờ. [ ] Một lượt có chế độ traffic rải suốt lượt để đo gánh dưới traffic biến động (cho paper).
  - [x] Review các đợt kéo dài trên lượt xác nhận (5.24): postgres worker1 báo 96% thời gian do replica CNPG `cnpg-2` hỏng sau failover 22/10 09:41 UTC (sự cố thật, không phải tấn công). [~] Kafka worker1 (67,7% thời gian, 6/18 control dương; 5.25): ổn định từ giờ đầu, case chủ yếu là probe liveness, log và tài nguyên bình thường. [ ] Sau lượt (khi giai đoạn final đã dựng bảng cửa sổ): `python3 scripts/analysis/replica_compare.py --table /var/tmp/burden-levers/table-pulse-stable-confirm.npz --workload production/aims-kafka-dual-role:kafka --exclude 1792698877,1792733344 --output /mnt/sentinel-pulse-archive/pulse-stable-confirm/analysis/kafka-replicas.json` (so `tree_p`/`support_p`, phần cửa sổ bị gắn cờ có/không exec của 3 broker, ngoài khoảng campaign; chỉ mô tả). Chạy tương tự cho `aims-postgres-cnpg:postgres` và `inventory-service:app`.
  - [x] Sửa replica `cnpg-2` (24/10 01:38, dựng lại từ primary, stream trên timeline 9; Pulse 5.25). [x] Báo cáo lượt xác nhận tách riêng đóng góp của container này (post-hoc, 5.25).
- [ ] **Tách attack khỏi process vô hại mới (G5):** 94% binary vô hại vẫn bị gắn cờ.
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
- [ ] Dataset công khai LID-DS (G3): tạm hoãn; xem lại khi viết paper.

## Thí nghiệm syscall — còn lại

- [x] Giai đoạn B nhóm feature trên holdout thứ hai (syscall 5B.2, tạm thời): không thành phần nào bỏ được; Pulse 4b đã cập nhật.
- [x] Giai đoạn B trên holdout chính và `pulse-attack-dev`: xong, gộp theo luật bổ sung (5B.3).
- [x] Pulse 5.7d xong (`rolling-12-1` −37% trên soak).
- [x] 5C: 11 cấu hình + nhóm feature dưới CUSUM `keep`/`cap`: không đổi kết luận nào.
- [ ] Paired blind attack theo protocol v2. Chưa mở được, vì chưa cấu hình nào đạt ngân sách 0,1 đợt/giờ; ghi là giới hạn.

## RCA — còn lại

- [x] Luật `privilege_drop_at_start` trên dữ liệu mới (RCA 5.11): top-1 100%, luật cũ 91,9%.
- [~] 13% attack không có case riêng: 42/315 (5.11); 69/525 trên lượt xác nhận, 56 gộp sau case binary vô hại; lý do từ chối nhiều nhất "binary không mới" (RCA 5.15). Đã xác nhận trên dữ liệu: mọi cặp dùng chung đường dẫn binary (RCA 5.15). [ ] Campaign sau: đặt tên file khác cho binary vô hại (đăng ký trước lượt; Pulse không bị ảnh hưởng vì không thấy đường dẫn).
- [x] Baseline binary mang qua các lượt (RCA 5.12): seed từ khoảng normal của 2 lượt trước, dùng từ lượt `pulse-stable-confirm`. [ ] Kiểm hiệu quả trên lượt đó.
- [x] Nhãn triage probe trên mỗi case (chỉ là nhãn), chạy từ lượt sau.
- [~] Cảnh báo vận hành thật (RCA 5.14): Pulse → Alertmanager/Prometheus/Grafana đang chạy thử. [x] RCA nhận trigger từ webhook Alertmanager: code + test (chế độ `alert_trigger_file`). [ ] Chạy ở lượt sau.
- [x] Ánh xạ IP node (hostNetwork/SNAT) bị gán nhầm cho node-exporter: sửa thành `Node` không xác định (RCA 5.13, áp dụng lượt sau). [x] Lịch sử inventory: không làm, có lý do (0,9% IP trong cụm không ánh xạ được, RCA 5.13). [x] Địa chỉ probe kubelet của Istio ambient → `KubeletProbe`. [ ] Backend sau DNAT và client thật sau waypoint (Istio ambient; cần Hubble hoặc access log) — ghi là giới hạn nếu không làm.

## Repo và bằng chứng

- [x] Biên nhận 22–23/10 chép vào `validation-evidence/results-20261022/` (README ghi script và bản gốc của từng file); ví dụ cây RCA thật (`validation-evidence/rca/examples-20261023/`).
- [x] README gốc: hướng dẫn đọc repo, từ con số đến bằng chứng.
- [x] `references/`: danh mục 87 nguồn; 70 bài, mỗi bài một PDF tên `năm-tác giả-tiêu đề` (60 bản gốc, 10 bản dựng lại; ngoài git, bản sao NFS). [x] Tổng hợp tri thức theo chủ đề cho luận văn: `references/KNOWLEDGE_SYNTHESIS.md` (23/10). [ ] **(cần bạn, nếu muốn)** lấy bản gốc của 10 bài dựng lại qua thư viện (danh sách trong `references/README.md`).
- [~] Biên nhận lượt xác nhận: [x] giai đoạn campaign và độ trễ đường cảnh báo trên toàn campaign đã vào `validation-evidence/results-20261023/` (13:30). [ ] Sau lượt: giai đoạn final, file đợt/giao của bridge, log Falco lên NFS.
- [x] Quét repo 23/10: link hỏng trong mọi `.md` đã sửa; gỡ snapshot cũ `SENTINEL_PULSE_VA_THI_NGHIEM_SYSCALL.md` (bản gốc qua `git show 5e1ed2f:…`); không có bí mật trong file tracked; mọi script job đều được báo cáo nhắc tới; bảng tên gọi và trạng thái cập nhật.
- [~] 1,3 GB dữ liệu thô cũ (pulse500, projected, canary 08–10/2026), bị gitignore trong `validation-evidence/` trên máy host, không còn được tham chiếu. Chủ đồ án đồng ý chuyển lên NFS rồi xóa ở host (23/10). [x] Đã chép sang đĩa local `.234` `/var/tmp/host-evidence-pre-refactor/`, 642/642 file khớp `SHA256SUMS` (23/10 11:35). [ ] **Sau lượt live:** chuyển lên `/mnt/sentinel-pulse-archive/host-evidence-pre-refactor-20261023/`, kiểm lại `SHA256SUMS` trên NFS, rồi xóa bản ở host, bản tạm trên `.234` và 5 dòng tương ứng trong `.gitignore`.

## Hạ tầng

- [x] `.234`: `mask` `unattended-upgrades`, `apt-daily-upgrade.timer`, `apt-daily.timer` như worker (24/10), sau khi tự nâng cấp `zlib1g` đã khởi động lại bridge và subscriber RCA giữa lượt (Pulse 5.25). Nâng cấp gói làm tay khi không có lượt live.

- [x] Collector 1 s đã dừng, tắt và xóa dữ liệu (22/10 12:47).
- [x] Đã xóa `/var/tmp/pulse-live-copy`, `falco-baseline` và 4 snapshot không dùng (22/10). [x] `/var/tmp/syscall-cusum` (4 GB, bản sao NFS, đã đối chiếu danh sách file) xóa 23/10. [ ] `/var/tmp/feature-groups` (7,6 GB): `study`, `workloads`, `score-dump` là bản duy nhất → chuyển lên NFS sau lượt live rồi xóa. Giữ `/var/tmp/burden-levers` (bảng cửa sổ cho test blind và so sánh rule) và `/var/tmp/baselines` (model baseline).
- [x] Nén `pulse-stable-candidate`, `pulse-stable-refreshed`, soak 48 giờ (NFS 291 → 85 GB, 22/10 16:17).

- [ ] **(cần bạn)** RAM NFS (`k8s-nfs`): tăng lên 8 GB và đặt reservation. Cần tắt VM, nên chỉ làm khi không có lượt live.
- [ ] **(cần bạn)** Host ESXi đang thu hồi RAM qua balloon: xem mức dùng RAM của host; đặt reservation cho 3 worker nếu host vẫn overcommit.
- [x] Đo overhead A/B (G7, Pulse 5.21): ~250–450 ns mỗi syscall khi theo dõi, ~80–230 ns khi không (microbenchmark, worker4). [ ] Kiểm trên kernel/distro khác (hiện chỉ Ubuntu x86-64).

## Quy tắc đang áp dụng

- Không chạy job đọc NFS nặng hoặc tốn RAM trên bất kỳ node nào khi lượt live đang chạy; không chạy trên master2/master3.
- Lượt live chạy hết chu kỳ, không dừng giữa chừng; khoảng thời gian xấu được loại trừ khi phân tích.
- Không thử reboot, mất NFS, backlog hay thao tác nào tác động vào hạ tầng.
- Không cài watcher; khi có job chạy ngầm, ghi giờ cần nhắc.
- Code đồng bộ giữa GitHub `main`, máy local và `/home/dat/eBPF-project` trên .234 và 3 worker (`scripts/sync_cluster_checkouts.sh` sau mỗi lần push).
- Phép đo mới phải đăng ký tiêu chí trước khi có số; không đổi lựa chọn sau khi xem kết quả.
- Rule (Falco, tripwire) chỉ quyết định song song với ML, tích hợp sau cùng, khi ML đã stable.
- Chỉ giữ tài nguyên còn được tham chiếu; dọn đồ thừa của job ngay; không đụng file cá nhân và backup của chủ đồ án.
