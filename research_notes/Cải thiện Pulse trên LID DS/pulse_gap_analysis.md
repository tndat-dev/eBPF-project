# Vì sao Pulse đạt 99,4 % live nhưng 77,3 % trên LID-DS 2021, và giới hạn nằm ở đâu trong pipeline của Pulse

Phạm vi: chỉ dùng repo local (`/home/tndat/Downloads/eBPF-project`, commit `ecd8b8b`), không truy cập cụm, không web. Mọi số lấy từ file và khóa JSON ghi kèm. Các số "tính lại" là phép tính python3 thư viện chuẩn trên chính các file đó (công thức ghi kèm). As-of: biên nhận LID-DS chạy 29/10/2026 09:10–15:01 (`validation-evidence/results-20261029/lidds/README.md`); biên nhận live `pulse-final-system-confirm` 25/10 22:05 → 26/10 22:15 (`SENTINEL_PULSE_STATUS.md` mục 5.29).

Viết tắt: `LE` = `validation-evidence/results-20261029/lidds/lidds-evaluation.json`; `CL` = `validation-evidence/results-20261029/lidds/convert.log`; `FS` = `validation-evidence/results-20261026/pulse-final-system-confirm/final-system.json`; `EV` = `scripts/analysis/lidds_evaluate.py`; `ST` = `SENTINEL_PULSE_STATUS.md`.

## 1. Khác biệt về chỉ số: 99,4 % live và 77,3 % LID-DS không đo cùng một thứ

### Takeaway
Live 99,4 % vừa là recall vừa là precision (TP 313, FN 2, control FP 2, thiết kế 1:1, đơn vị là trial 15 s). LID-DS 77,3 % là tỉ lệ phát hiện theo bản ghi (tương đương recall). Tính theo cùng kiểu, precision trên LID-DS là 80,7 % ở tỉ lệ nền thật (1 attack : 6,25 normal) và 96,3 % nếu quy về 1:1. Báo nhầm quy về 15 s là 1,03 % trên LID-DS so với 0,64 % control live. Vậy khoảng cách chủ yếu nằm ở **recall**, và nó dồn vào 5/15 kịch bản: bỏ 5 kịch bản này thì LID-DS phát hiện 1.212/1.217 = 99,6 %, ngang live.

### Cited Findings
- **Live, hệ thống S (ML + tripwire), tập chính 6/12/24 lần/s:** recall 0,99365 (TP 313, FN 2), precision 0,99365, control 0,00637 (2/314), p50 0,631 s, p95 1,974 s. Nguồn: `FS` → `arms.B2.primary.{attack,TP,FN,control_FP,precision,control,p50,p95}`; `ST` mục 5.29 (bảng). ML riêng (A) cùng recall/precision, p95 2,251 s (`FS` → `arms.A.primary`).
- **Precision live = TP/(TP + control FP):** 313/(313+2) = 0,99365, trùng đúng `arms.B2.primary.precision`. Binary vô hại (benign-exec, cùng đường `kubectl exec`) bị gắn cờ 89,5 % (282/315) nhưng **không** tính vào precision: `FS` → `arms.B2.primary.benign` = 0,8952; `ST` mục 3 (thuật ngữ "binary vô hại") và mục 5.29 ("báo kèm"). Tính lại nếu coi benign là FP: 313/(313+2+282) = **52,4 %**.
- **Recall live ở mọi tốc độ (1–24/s):** 0,9638 (506/525), p95 2,18 s (`FS` → `arms.B2.all_rates.{attack,TP,FN,p95}`). ML theo tốc độ: 1/s 79,0 % (83/105), 3/s 90,2 % (92/102), 6/12/24/s 99/99/100 % (`ST` mục 5.29, "Theo tốc độ"). Con số 99,4 % chỉ dùng tập chính 6–24/s.
- **Đơn vị live:** một trial gồm control 15 s → binary vô hại 15 s → attack 15 s trên cùng container; tập chính có 315 attack và 314 control (tỉ lệ khoảng 1:1). Nguồn: `ST` mục 3 ("cặp attack/control"); `FS` → `arms.B2.primary.TP+FN` = 315.
- **LID-DS, hệ thống, gộp 15 kịch bản:** phát hiện 1.403/1.815 = 0,7730 [0,7532; 0,7917]; bản ghi normal báo nhầm 336/11.341 = 0,0296; 2,479 đợt/giờ normal; 32 đợt báo nhầm trước exploit trong bản ghi attack; p50 0,774 s, p95 2,712 s. Nguồn: `LE` → `pooled.system.{detected,attack_recordings,detection_rate,detection_ci95,false_alarm_recordings,normal_recordings,false_alarm_rate,false_alarm_episodes_per_hour,false_alarms_before_exploit,latency_p50,latency_p95}`.
- **Định nghĩa phát hiện LID-DS:** bản ghi attack được tính là phát hiện khi có **bất kỳ** cửa sổ báo động nào kết thúc sau thời điểm exploit đầu tiên. Không giới hạn thời gian, nên báo động muộn hàng chục giây vẫn tính. Bản ghi normal có bất kỳ cửa sổ báo động nào là bản ghi báo nhầm. Nguồn: `EV` dòng 145–151 (`recording_outcome`), dòng 154–167 (`summarize`); `sentinel_pulse/protocol/lidds-evaluation-v1.json` → `metrics.per_recording`.
- **Tỉ lệ nền LID-DS:** 11.341 normal / 1.815 attack = 6,25 : 1 (`LE` → `pooled.system.normal_recordings`, `attack_recordings`).
- **Độ dài đơn vị LID-DS:**
  - bản ghi normal trung bình 137,535 h × 3600 / 11.341 = **43,7 s** (`LE` → `pooled.system.normal_hours`), khoảng 2,9 lần trial 15 s;
  - bản ghi attack trung bình khoảng 20 s ở đa số kịch bản (số cửa sổ 0,5 s / số bản ghi trong `CL` → `counts["test-normal_and_attack:windows"]` / `counts["test-normal_and_attack:recordings"]`). Ví dụ Heartbleed 4.817/120 = 40,1 cửa sổ = 20,1 s; ZipSlip 19,8 s; CVE-2017-7529 11,8 s. Riêng CVE-2012-2122 là 790,8 s.
- **Precision LID-DS tính theo cùng kiểu (tính lại từ `LE` → `pooled.system`):**
  - ở tỉ lệ nền thật: 1.403/(1.403+336) = **80,7 %**; nếu tính cả 32 đợt trước exploit là FP: 79,2 %;
  - quy về 1:1 như live, theo tỉ lệ: 0,7730/(0,7730+0,0296) = **96,3 %**;
  - xác suất báo nhầm trong 15 s, suy từ tỉ lệ đợt: 1 − exp(−2,479 × 15/3600) = **1,03 %**, so với control live 0,64 %.
- **Theo kịch bản, precision quy 1:1:** Heartbleed (CVE-2014-0160) 27,3 %, ZipSlip 36,9 %, 13 kịch bản còn lại 96,2–99,0 %. Tính lại từ `LE` → `scenarios.<s>.arms.system.{detection_rate,false_alarm_rate}`.
- **Bản ghi bị bỏ sót:** 412 bản ghi; ZipSlip 114, CVE-2014-0160 113, CVE-2019-5418 100, Juice-Shop 44, CVE-2017-7529 36, Bruteforce 5, 9 kịch bản còn lại 0. Năm kịch bản yếu chiếm 407/412. Bỏ 5 kịch bản này, hệ thống phát hiện 1.212/1.217 = **99,6 %**. Tính lại từ `LE` → `scenarios.<s>.arms.system.{attack_recordings,detected}`; `ST` mục 5.32 ("yếu ở …").
- **Gánh báo nhầm:** LID-DS 2,48 đợt/giờ (`LE` → `pooled.system.false_alarm_episodes_per_hour`), live S 1,55 đợt/replica-giờ (`FS` → `arms.B2.burden`) và A 1,50 (`arms.A.burden`).

### Inferences
- Hai con số đầu bài nói về hai chiều khác nhau. Live 99,4 % trả lời "báo đúng bao nhiêu trên tổng số báo" (và tình cờ trùng recall). LID-DS 77,3 % trả lời "bắt được bao nhiêu exploit". So cùng chiều thì: recall 99,4 % (live, tập chính) hay 96,4 % (live, mọi tốc độ) so với 77,3 % (LID-DS). Precision quy 1:1 là 99,4 % so với 96,3 %. Báo nhầm theo 15 s là 0,64 % so với 1,03 %. Tức là phía báo nhầm gần tương đương; phía recall mới lệch.
- Precision 80,7 % ở tỉ lệ nền thật của LID-DS là con số trung thực hơn cho người vận hành. Live 1:1 là thiết kế campaign, không phải tỉ lệ nền ngoài thực tế. Nếu coi binary vô hại là FP thì precision live chỉ còn 52,4 %.
- Định nghĩa phát hiện của LID-DS dễ hơn live ở một điểm: không có trần thời gian. Báo động 77 s sau exploit vẫn tính. Còn live yêu cầu báo trong trial 15 s, và p95 được báo theo kernel → cảnh báo. Nếu áp trần ≤ 3 s hay ≤ 15 s, phát hiện LID-DS chỉ có thể giảm, không tăng (xem mục 3).
- Ngoài 5 kịch bản yếu, Pulse trên LID-DS gần như ngang live (99,6 %), nên không thể nói chung chung "Pulse kém trên dữ liệu công khai". Nói đúng hơn: Pulse kém ở một **lớp exploit** cụ thể (mục 2).

### Gaps
- `LE` chỉ lưu p50/p95 độ trễ, không lưu độ trễ từng bản ghi (`EV` dòng 154–167 chỉ ghi phân vị). Vì vậy không tính được phát hiện có trần ≤ 3 s hay ≤ 15 s. Chỉ biết cận: ở mỗi kịch bản, tối đa 5 % bản ghi được phát hiện có độ trễ vượt p95.
- Độ dài từng bản ghi attack và vị trí exploit trong bản ghi không có trong `LE` hay `CL`. Độ dài trung bình ở trên là số cửa sổ chia số bản ghi, không phải phân phối.

## 2. Khác biệt về tấn công: fixture tự viết qua `kubectl exec` so với exploit thật chạy trong process dịch vụ

### Takeaway
Live chỉ có 5 fixture, đều là process mới đi vào qua exec, dùng syscall hiếm hoặc bất thường. Detector tần suất bắt rất mạnh dấu hiệu "process mới" (binary vô hại cũng bị gắn cờ 89,5 %), còn tripwire bắt syscall vắng mặt trong hồ sơ. Trên LID-DS, Pulse thắng ở đúng các kịch bản có ID syscall mới: cả 9 kịch bản tripwire đạt 100 % thì hệ thống đều đạt 100 %. Pulse thua ở các exploit chạy trong process dịch vụ mà không thêm ID mới (Heartbleed, ZipSlip, CVE-2019-5418, CVE-2017-7529, phần lớn Juice-Shop). Ở nhóm tripwire 0 %, nếu bỏ Bruteforce, ML chỉ phát hiện 23,9 %.

### Cited Findings
- **5 fixture live:** `anonymous_mprotect_churn`, `child_ptrace_handshake`, `execveat_resolution_probe`, `invalid_setns_burst`, `seccomp_api_probe`. Recall tập chính lần lượt 100/100/100/100/96,8 %. Nguồn: `FS` → `arms.B2.primary.recall_by_scenario`.
- **Đường vào live:** "Một process mới chạy trong container qua exec từ bên ngoài", tức giai đoạn sau khi đã xâm nhập. Mỗi lượt chạy 15 s ở 6, 12, 24 lần/s, và mọi thao tác chắc chắn thất bại trước khi đổi trạng thái host. Nguồn: `RESEARCH_IDEAS.md` mục 5.1 (bảng). Ngoài ra "Mọi fixture của đồ án đi vào bằng exec. Recall đo được vì vậy là cận trên cho tấn công vào qua exec" (`RESEARCH_IDEAS.md` mục 4.4, ý 4) và mục 5.4.
- **Detector bắt process mới:** "detector tần suất bắt 'process mới' chứ chưa phân biệt được ác ý. Binary vô hại … bị gắn cờ 80,7–95,1 % qua 5 lượt live" (`ST` mục 1); lượt cuối 89,5 % (`FS` → `arms.B2.primary.benign`).
- **Tripwire live:** chỉ bắt được các attack dùng `ptrace`/`setns`/`execveat` (`ST` mục 1); riêng tripwire recall 60,0 %, control 0 %, benign 0 % (`FS` → `standalone.tripwire.primary.{attack,control,benign}`).
- **Bằng chứng feature:** syscall hiếm trong normal (`ptrace`, `setns`, `execveat`, `mount`, `unshare`, `pivot_root`, `recvmmsg`) "chính là tín hiệu tấn công" và bằng 0 trên 185 triệu lượt gọi normal. Hai kịch bản dùng syscall phổ biến (`mprotect`, `seccomp`) là điểm yếu chung của mọi bộ syscall (70–83 %); muốn sửa cần thông tin ngoài tần suất, ví dụ tham số syscall. Nguồn: `ST` mục 4b (bảng và "Giới hạn của bằng chứng").
- **LID-DS:** container attacker khai thác container victim qua mạng (`RESEARCH_IDEAS.md` mục 5.2, dòng LID-DS 2021). `ST` mục 5.32 ghi một cách giải thích khả dĩ, **chưa kiểm**: "ở các kịch bản yếu, exploit chạy trong chính process của dịch vụ và không cần syscall mới".
- **Tách theo tripwire** (tính lại từ `LE` → `scenarios.<s>.arms.{ml,tripwire}.detected/attack_recordings`):
  - 9 kịch bản tripwire 100 % (CVE-2012-2122, CVE-2017-12635_6, CVE-2018-3760, CVE-2020-13942, CVE-2020-23839, CVE-2020-9484, CWE-89, EPS_CWE-434, PHP_CWE-434): ML 901/1.078 = 83,6 %, hệ thống 100 % ở cả 9;
  - 5 kịch bản tripwire 0 % (Bruteforce, CVE-2014-0160, CVE-2017-7529, CVE-2019-5418, ZipSlip): ML 248/616 = 40,3 %; bỏ Bruteforce thì 114/477 = **23,9 %**;
  - Juice-Shop (tripwire 62,0 %): ML 5/121 = 4,1 %.
- **Bruteforce (CWE-307)** là ngoại lệ: tripwire 0 % nhưng ML 96,4 %, p95 2,98 s (`LE` → `scenarios.Bruteforce_CWE-307.arms.ml`). Đây là kịch bản lặp nhiều lần đăng nhập, giống kiểu "burst" của fixture live.
- **STIDE như phép chẩn đoán** (`LE` → `scenarios.<s>.arms.stide.{detection_rate,false_alarm_rate}`):
  - Heartbleed: STIDE 100 % với báo nhầm chỉ 3,0 %, còn Pulse 5,8 % với báo nhầm 15,6 %;
  - CVE-2017-7529: STIDE 100 % / 15,2 %;
  - ZipSlip 100 % / 97,8 %, CVE-2019-5418 100 % / 96,8 %, Juice-Shop 100 % / 99,9 %: STIDE báo ở gần như mọi bản ghi normal, nên không tách được.

### Inferences
- Thành công live và thành công LID-DS có chung một cơ chế: ID syscall mới hoặc hiếm, và đợt syscall dày kéo dài. Exploit trong process dịch vụ (đọc lố bộ nhớ, path traversal, ghi file ra ngoài thư mục) chỉ dùng các syscall dịch vụ vốn gọi, nên cả ML tần suất lẫn tripwire đều không có tín hiệu. Đây là mối đe dọa mà `RESEARCH_IDEAS.md` 4.4 ý 3–4 đã nêu (đổi payload, không exec), nay có số đo.
- Heartbleed và CVE-2017-7529 có tín hiệu ở **thứ tự** syscall: STIDE 7-gram theo thread tách được với báo nhầm thấp hoặc vừa. Pulse chỉ giữ cặp syscall liền nhau, băm vào 64 bin, đếm theo 0,5 s, nên tín hiệu này bị pha loãng. Đây là giới hạn của biểu diễn feature (mục 3, ý 10), không phải của ngưỡng.
- ZipSlip, CVE-2019-5418 và Juice-Shop thì ngay cả STIDE cũng không tách được ở cấu hình mặc định. Nhiều khả năng cần tín hiệu theo tham số (đường dẫn file), đúng như `ST` 4b đã kết luận cho `mprotect`/`seccomp`. Đây là suy luận, chưa kiểm.
- Các exploit LID-DS gần với attack chậm (một vài request) hơn là fixture 6–24/s. Live ở 1/s chỉ đạt 79,0 % ngay cả với attack qua exec, nên kém đi trên LID-DS là đúng hướng mong đợi.
- Tên CVE gợi ý Heartbleed, CVE-2017-7529 (nginx range) và CVE-2019-5418 (Rails file disclosure) là exploit một request. Điều này lấy từ kiến thức chung về các CVE, **không** có nguồn local trong repo.

### Gaps
- Repo không có mô tả từng kịch bản LID-DS (ngoài danh sách tên ở `RESEARCH_IDEAS.md` 4.2/5.2), không có số request mỗi exploit, không có danh sách ID mới trong cửa sổ attack. Vì vậy câu "exploit chạy trong process dịch vụ" vẫn là giả thuyết; `ST` 5.32 cũng ghi là chưa kiểm.
- Không có số liệu tripwire novel IDs theo kịch bản. `EV` không ghi ID nào gây báo động; live thì có trường `tripwire_novel_ids` (`sentinel_pulse/rules/tripwire.py` docstring).

## 3. Nguyên nhân nằm trong pipeline của Pulse khi chạy trên LID-DS

### Takeaway
Các tính chất làm giảm phát hiện:
- 13 cửa sổ đầu (6,5 s) của mỗi bản ghi không bao giờ được ML chấm, và báo động ML sớm nhất là ở 7,5 s; trong khi bản ghi attack chỉ dài khoảng 20 s, riêng CVE-2017-7529 khoảng 12 s;
- k2of2 loại bất thường chỉ kéo dài một cửa sổ;
- tripwire bị exec set E che 59 ID;
- 64 bin băm làm mất thứ tự syscall;
- bộ chuyển đổi bỏ `pread`/`pwrite`/`sigreturn`/`prlimit` ở 12/15 kịch bản. Tuy vậy, cả 3 kịch bản bỏ sót nặng nhất về chuyển đổi (Heartbleed, CVE-2017-7529, Bruteforce) đều không bị bỏ syscall nào.

Các yếu tố **không** phải nguyên nhân giảm phát hiện:
- thiếu chiết khấu replica: nó chỉ bớt báo động, không thêm;
- độ phân giải p-value: ngưỡng cao hơn sàn joint p 9–19 lần;
- cỡ dữ liệu fit: đủ, trừ CVE-2017-7529 chỉ bằng một nửa.

### Cited Findings
1. **Không có chiết khấu replica.**
   - Luật live `policy-k2of2-a5-peer30`: cửa sổ chỉ đạt khi joint p ≤ α×5 **và** `novel_peer ≠ 0`; `−1` (không thấy replica khác) thì vẫn giữ. Nguồn: `ST` mục 5.26 ("Chính sách"). `novel_peer` là số ID syscall của ngữ cảnh (cửa sổ hiện tại + tối đa 3 cửa sổ trước) mà không replica nào khác thấy trong 30 s (`sentinel_pulse/detector/novelty.py` dòng 114–118, 78).
   - Trên LID-DS, protocol bỏ chiết khấu vì bản ghi không có replica (`sentinel_pulse/protocol/lidds-evaluation-v1.json` → `ml.decision`; `EV` docstring dòng 7–8).
   - Live, chiết khấu tác động mạnh: lúc kiểm, 94/97 cửa sổ được chấm gần nhất của worker1 bị chiết khấu (`ST` 5.26, "Khởi chạy").
2. **Cỡ train/calibration theo kịch bản.** Mỗi kịch bản có khoảng 15.650–16.440 ngữ cảnh train và 4.370–4.700 ngữ cảnh calibration, tức khoảng 2,2 giờ normal train. Riêng CVE-2017-7529 chỉ có 8.049 / 2.185 (200 bản ghi train được đánh giá; `CL` có 210 bản ghi chuyển đổi). Nguồn: `LE` → `scenarios.<s>.fit.{train_examples,calibration_examples}`, `scenarios.<s>.recordings.training`. Số tọa độ hằng trong train là 78–190/249; CVE-2017-7529 cao nhất với 190 (`fit.support.constant_training_coordinates`).
3. **Ngưỡng so với sàn p-value conformal.**
   - Ngưỡng là `SCALE * ALPHA` = 5 × 0,05/30 = 0,00833 (`EV` dòng 38–39, 105).
   - `joint_p = min(1, 2·min(tree_p, support_p))` (`sentinel_pulse/detector/support_model.py` dòng 78); p-value conformal là (n − rank + 1)/(n + 1) (dòng 15–17).
   - Sàn của từng nhánh là 1/(n+1): 0,000214–0,000229, riêng CVE-2017-7529 0,000457 (`LE` → `scenarios.<s>.fit.minimum_conformal_p`). Sàn joint vì vậy là 0,00043–0,00091, thấp hơn ngưỡng 9–19 lần.
   - Mọi kịch bản đều đủ yêu cầu tối thiểu 1.199 mẫu calibration mỗi nhánh (= ⌈2/α⌉ − 1; `support_model.py` dòng 33–34; `fit.support.minimum_calibration_examples_per_branch`).
   - Để đạt ngưỡng, ít nhất một nhánh phải có p ≤ 0,00417, tức điểm cao hơn tất cả trừ khoảng 18 trong 4.547 điểm validation (Bruteforce).
4. **13 cửa sổ khởi động mỗi bản ghi.**
   - Cửa sổ chỉ `eligible_for_normal_review` khi `history >= 10` (`sentinel_pulse/collector/extended_capture.py` dòng 72); ML cần thêm 3 cửa sổ hợp lệ liền trước (`EV` dòng 75–81, `HISTORY = 3`); snapshot đầu tiên không sinh cửa sổ (`sentinel_pulse/lidds/convert.py` dòng 111–114).
   - Kiểm số học: (số cửa sổ − 13 × số bản ghi) khớp **chính xác** `fit.train_examples` và `fit.calibration_examples` ở 13/15 kịch bản. Hai kịch bản lệch nhẹ: CVE-2017-12635_6 lệch 24, CVE-2017-7529 lệch 3, do vài bản ghi ngắn hơn 13 cửa sổ. Ví dụ Bruteforce: 18.685 − 13 × 210 = 15.955 = `train_examples`; 5.327 − 13 × 60 = 4.547 = `calibration_examples`. Nguồn: `CL` → `counts`, `LE` → `fit`, `recordings`.
   - Hệ quả: cửa sổ ML đầu tiên được chấm kết thúc ở t0 + 7,0 s. Vì k2of2 đòi cửa sổ trước cũng đạt (`EV` dòng 106–110), báo động ML sớm nhất là ở **t0 + 7,5 s**. Tripwire không có khởi động (`EV` dòng 118–119 xét mọi cửa sổ).
   - Thời gian ML được chấm trung bình mỗi bản ghi attack (độ dài trung bình − 6,5 s; tính lại từ `CL`): Heartbleed 13,6 s, ZipSlip 13,3 s, CVE-2019-5418 14,3 s, Juice-Shop 28,7 s, Bruteforce 14,4 s, và **CVE-2017-7529 chỉ 5,3 s** (11,8 s trung bình, khởi động chiếm 55 %).
5. **k2of2 trên các cửa sổ liên tiếp.** Báo động chỉ khi hai cửa sổ liền nhau cùng đạt (`EV` dòng 97–111). Bằng chứng live (development, `ST` 5.3):
   - 1 cửa sổ: recall 99,3 %, control 23,3 %, 37,1 đợt/giờ;
   - 2 of 2: recall 98,3 %, control 13,3 %, 22,3 đợt/giờ;
   - live `policy-1win-a3`: precision 89,1 %, recall 92,8 %, control 11,2 % (`ST` mục 1, lịch sử).
6. **Syscall bị bỏ khi chuyển đổi** (`CL` → `unmapped_names`, đếm trên mọi split):
   - CVE-2014-0160, Bruteforce_CWE-307, CVE-2017-7529: `{}` (không bỏ gì);
   - ZipSlip: `pread` 310.169, `sigreturn` 22.678 (cùng pseudo-event `procexit` 414.454, `signaldeliver` 280.786);
   - Juice-Shop: `pread` 79.693, `pwrite` 1.316, `<unknown>` 2.294.951;
   - CVE-2019-5418: `pread` 327, `sigreturn` 2;
   - lớn nhất: CVE-2020-13942 `pread` 9.175.836; CVE-2017-12635_6 `pread` 1.895.921.
   - Tổng khoảng 15,0 M lượt ở 12/15 kịch bản (`sentinel_pulse/protocol/lidds-evaluation-v1-amendment-1.json` → `finding`).
   - Bảng alias đã thêm (`convert.py` dòng 37–39, `SYSDIG_ALIASES`); pseudo-event vẫn để ngoài như đã đăng ký (amendment → `change`).
7. **Exec set E của tripwire** có 59 ID (`validation-evidence/results-20261021/pulse-stable-candidate/final/exec-set-E.json`):
   - gồm 15 (`rt_sigreturn`), 17 (`pread64`), 302 (`prlimit64`), nhưng không có 18 (`pwrite64`);
   - gồm `mprotect` 10, `execve` 59, `setuid`/`setgid` 105/106, `capset` 126, `seccomp` 317, `clone3` 435, `openat` 257 và nhiều syscall file/thư mục (217, 262, 267, 269, 332, 79, 80, 93, 137, 138; tên theo bảng syscall x86-64);
   - một cửa sổ chỉ báo khi có ID nằm ngoài cả reference lẫn E (`EV` dòng 118–119);
   - reference LID-DS = hợp ID của các cửa sổ **train** (`EV` dòng 114–115; protocol → `tripwire`); live = mọi cửa sổ trong khoảng selection trên mọi node (`sentinel_pulse/rules/tripwire.py` docstring dòng 6–8).
8. **Báo nhầm theo kịch bản (hệ thống)** (`LE` → `scenarios.<s>.arms.system.{false_alarm_recordings,false_alarm_rate,false_alarm_episodes_per_hour}`):
   - CVE-2014-0160: 118/758 = 15,6 %, 12,91 đợt/giờ, chiếm 35 % mọi bản ghi báo nhầm;
   - ZipSlip: 44/760 = 5,8 %, 4,74 đợt/giờ;
   - 13 kịch bản còn lại 0,66–2,73 %.
   - Tripwire chỉ thêm 3 bản ghi báo nhầm ngoài ML (PHP 2, Juice-Shop 1): hệ thống 336 so với ML 333 (`pooled.{system,ml}.false_alarm_recordings`). Bốn bản ghi báo nhầm tripwire của CVE-2020-23839 đều trùng với báo nhầm ML.
9. **Báo nhầm trước exploit:** gộp 32 đợt, trong đó 26 ở CVE-2020-23839 (`LE` → `scenarios.CVE-2020-23839.arms.ml.false_alarms_before_exploit`; `pooled.system.false_alarms_before_exploit`). Bản ghi attack của kịch bản này dài trung bình 42,4 s (`CL`), nên 120 bản ghi có tối đa 1,41 h trước exploit. Tức là ít nhất 18 đợt/giờ, so với 2,11 đợt/giờ trên normal của cùng kịch bản (`arms.ml.false_alarm_episodes_per_hour`).
10. **Độ trễ theo kịch bản** (`LE` → `scenarios.<s>.arms.<arm>.latency_p50/p95`):
    - hệ thống p95 > 3 s ở CVE-2014-0160 (6,46 s), ZipSlip (5,62 s), CVE-2017-7529 (3,82 s), CVE-2020-23839 (3,50 s), Juice-Shop (38,47 s);
    - ML riêng: Juice-Shop p50 76,9 s, p95 159,9 s; CVE-2012-2122 p95 82,6 s (tripwire 0,47 s);
    - tripwire có p50 0,26–0,37 s ở 3 kịch bản CVE-2012-2122, CVE-2018-3760, CVE-2020-13942.
11. **Phát hiện ML có khi chỉ ngang ngẫu nhiên.** Cận trên của "phát hiện nhờ báo nhầm ngẫu nhiên" = 1 − exp(−đợt/giờ của ML × thời gian được chấm của bản ghi attack). Tính từ `LE` → `arms.ml.false_alarm_episodes_per_hour` và `CL`:
    - Heartbleed: cận trên 4,7 %, quan sát 5,8 %;
    - ZipSlip: cận trên 1,7 %, quan sát 3,4 % (4 bản ghi, độ trễ 5,06–5,62 s);
    - CVE-2018-3760 (ML): cận trên 0,8 %, quan sát 4,1 %;
    - Juice-Shop (ML): cận trên 0,4 %, quan sát 4,1 % nhưng p50 76,9 s.

### Inferences
- **Chiết khấu replica không giải thích được recall thấp.** Chiết khấu chỉ loại cửa sổ đạt, nên thiếu nó trên LID-DS chỉ làm báo nhầm cao hơn (2,48 so với 1,50–1,55 đợt/giờ), không làm phát hiện thấp hơn. Ngược lại: với một dịch vụ có replica, exploit trong process không thêm ID nào mà replica khác không thấy, nên `novel_peer = 0` và luật live sẽ chặn báo động. Vì vậy số ML trên LID-DS là **cận trên** của luật live cho kiểu exploit này khi dịch vụ có replica. Đây là suy luận từ định nghĩa, chưa đo.
- **Độ phân giải p-value không phải nút thắt.** Ngưỡng 0,0083 cao hơn sàn joint 9–19 lần. Với Heartbleed và ZipSlip, ngưỡng còn đang quá rộng (báo nhầm 15,6 %, 5,8 %) mà phát hiện vẫn ngang ngẫu nhiên, nghĩa là cửa sổ attack có điểm không khác normal. Nới ngưỡng không cứu được.
- **Lệch giữa validation và test-normal ở Heartbleed.** Calibration trên validation mà test-normal vẫn báo nhầm 15,6 % (các kịch bản khác khoảng 1–3 %). Nhiều khả năng 60 bản ghi validation không đại diện cho test-normal của kịch bản này. Ngưỡng chọn trên validation cũng không thấy được lệch này.
- **Khởi động 6,5–7,5 s là tính chất của thiết kế live, không hợp với LID-DS.** Live, container chạy hàng giờ nên 13 cửa sổ khởi động không tốn gì. Trên LID-DS, mỗi bản ghi là một "container" mới chỉ khoảng 20 s, nên ML bị mù 1/3 thời gian, riêng CVE-2017-7529 hơn một nửa. Nếu exploit rơi vào 7 s đầu và chỉ là một request, ML chỉ còn bắt được hậu quả kéo dài. Ứng viên rõ nhất cho 36 bản ghi bỏ sót của CVE-2017-7529 là đây, nhưng chưa kiểm.
- **k2of2 hợp với attack kéo dài, kém với exploit một request.** Ở live, k2of2 chỉ tốn khoảng 1 điểm recall vì attack kéo dài 15 s ở 6–24/s. Với exploit tạo bất thường đúng một cửa sổ 0,5 s, k2of2 sẽ bỏ. Mức ảnh hưởng trên LID-DS chưa đo được.
- **Lỗi alias không giải thích được các kịch bản thua nặng nhất.** Heartbleed (113 bỏ sót) và CVE-2017-7529 (36) không bị bỏ syscall nào. Alias chỉ có thể tác động tới ZipSlip, Juice-Shop và rất ít ở CVE-2019-5418. Với tripwire, alias chỉ thêm được `pwrite64`, vì 3 ID kia nằm trong E.
- **E che bớt tín hiệu của tripwire trên LID-DS.** E được dựng để nuốt các ID của binary vô hại chạy qua exec trên cụm live. LID-DS không có đường exec đó, nhưng E vẫn che 59 ID, trong đó có nhiều syscall file/thư mục mà exploit path traversal hoặc ghi file có thể dùng (ZipSlip, CVE-2019-5418). Đây là giả thuyết, cần kiểm bằng giao của novel IDs với E.
- **Phát hiện ML ở Heartbleed, ZipSlip, CVE-2018-3760 và Juice-Shop gần như ngẫu nhiên hoặc rất muộn.** Ở 4 kịch bản này, ML gần như không có tín hiệu thật. Chỗ hệ thống đạt 100 % ở CVE-2018-3760 hoàn toàn nhờ tripwire.
- **Báo nhầm trước exploit ở CVE-2020-23839** cao gấp ≥ 8,7 lần mức normal. Điều này gợi ý hoạt động tấn công (do thám hoặc chuẩn bị) bắt đầu trước mốc `exploit` của metadata, hoặc phần đầu bản ghi attack khác bản ghi normal. Khi đó một phần "phát hiện" ML 51,7 % có thể là báo động kéo dài từ trước exploit.

### Gaps
- **Không trả lời được bằng `LE`: bao nhiêu bản ghi attack có ít nhất một cửa sổ ML được chấm (hoặc một cặp k2of2) sau exploit.** `EV` không lưu `exploit_at − t0`, số cửa sổ được chấm sau exploit, hay kết quả từng bản ghi. Cần đọc `test-normal_and_attack.jsonl.gz` đã chuyển đổi trên `.234` (trường `lidds.exploit_at`, `window_end`, `eligible_for_normal_review`). Đây là phép tính nhẹ, nhưng cần truy cập cụm, nằm ngoài phạm vi này.
- Không có phân phối `joint_p` của cửa sổ attack, nên không biết exploit nào nằm sát ngưỡng (nới được) và exploit nào nằm sâu trong vùng normal.
- Không biết `pread`/`pwrite` bị bỏ nằm ở split nào (train hay attack); `CL` chỉ đếm gộp.
- Không tìm thấy trong repo cỡ tập train của model live theo workload (để so với khoảng 2,2 h normal mỗi kịch bản LID-DS).

## 4. Các cải thiện nhanh trong khuôn khổ thiết kế của Pulse, kiểm được bằng protocol đăng ký mới

### Takeaway
Không cách nào trong khuôn khổ hiện tại sửa được Heartbleed hay ZipSlip, vì ở đó cửa sổ attack không khác normal trong không gian feature của Pulse, hoặc báo nhầm đã quá cao. Trần thực tế của các cải thiện nhanh là CVE-2017-7529 (36 bỏ sót), CVE-2019-5418 (100) và một phần Juice-Shop (44): tối đa khoảng 180 bản ghi, tức khoảng +10 điểm phát hiện, nếu thành công hết, và đó là cận trên chứ không phải ước lượng. Thứ tự đề xuất:
1. alias, đã đăng ký;
2. rút ngắn khởi động hoặc chấm nhánh support từ đầu;
3. ngưỡng theo kịch bản chọn trên dữ liệu normal (chỉ nới ở kịch bản báo nhầm thấp);
4. k-of-n (1-of-1 hoặc 2-of-3) kèm α chặt hơn;
5. tripwire bỏ E;
6. reference tripwire = train + validation (chỉ là vệ sinh, giảm tối đa 3 bản ghi báo nhầm).

Mọi số hiệu quả bên dưới là cận hoặc suy luận, chưa có phép đo.

### Cited Findings
- **Điểm xuất phát theo kịch bản (hệ thống / ML / tripwire, báo nhầm hệ thống)** (`LE` → `scenarios.<s>.arms.*`):

  | Kịch bản | Hệ thống | ML | Tripwire | Báo nhầm |
  |---|---|---|---|---|
  | CVE-2014-0160 | 5,8 % | 5,8 % | 0 % | 15,6 % |
  | ZipSlip | 3,4 % | 3,4 % | 0 % | 5,8 % |
  | CVE-2019-5418 | 16,7 % | 16,7 % | 0 % | 0,66 % |
  | CVE-2017-7529 | 69,7 % | 69,7 % | 0 % | 1,65 % |
  | Juice-Shop | 63,6 % | 4,1 % | 62,0 % | 0,79 % (ML 0,66 %) |
  | Bruteforce_CWE-307 | 96,4 % | 96,4 % | 0 % | 2,73 % |

- **Amendment 1 (alias) đã đăng ký** chạy lại đủ 15 kịch bản như phân tích độ nhạy, báo cả hai lượt, không chọn theo số. Nguồn: `sentinel_pulse/protocol/lidds-evaluation-v1-amendment-1.json` → `rerun`, `reporting`; `ST` 5.32.
- **Live, 1 cửa sổ so với k2of2:** control 23,3 % so với 13,3 %, 37,1 so với 22,3 đợt/giờ, recall 99,3 % so với 98,3 % (`ST` 5.3). Thêm α/4 thì recall giảm còn 69,2 % (cùng bảng, dòng "4 of 6, alpha/4").
- **Tripwire góp vào báo nhầm:** chỉ 3 bản ghi ngoài ML (`LE` → `pooled.system/ml.false_alarm_recordings` 336/333).
- **Protocol hiện tại cấm chỉnh trên LID-DS:** "every parameter taken from the live system, nothing tuned on LID-DS" (`lidds-evaluation-v1.json` → `purpose`). Mọi thay đổi dưới đây cần protocol mới đăng ký trước khi chạy và chỉ được dùng dữ liệu normal (train/validation) để chọn.

### Inferences
Bảng ước lượng trung thực từng đòn bẩy (giữ model ExtraTrees + support, 249 feature, luật p-value; mỗi mục là một nhánh của protocol mới):

1. **Alias** (`SYSDIG_ALIASES`, đã đăng ký):
   - ML thay đổi ở 12/15 kịch bản;
   - tripwire chỉ có thể thêm `pwrite64` (18), ở CVE-2012-2122, CVE-2018-3760, CWE-89, PHP và Juice-Shop;
   - *Có thể giúp:* ZipSlip (`pread` 310 k), Juice-Shop (`pread` 80 k, `pwrite` 1,3 k). Cận trên là 114 + 44 = 158 bản ghi; kỳ vọng thực tế nhỏ và chưa rõ chiều, vì cùng thay đổi xảy ra ở train lẫn test;
   - *Không thể giúp:* Heartbleed, CVE-2017-7529, Bruteforce (0 syscall bị bỏ). CVE-2019-5418 gần như không đổi (329 lượt);
   - giá trị chính là so công bằng hơn với STIDE.
2. **Rút ngắn khởi động**, ví dụ:
   - dùng `history >= 3` thay cho `>= 10`, áp nhất quán cho train, validation và test (rolling-10 tính trên ít cửa sổ hơn);
   - hoặc cho riêng nhánh support (chỉ dùng cửa sổ hiện tại) chấm từ cửa sổ đầu tiên, nhánh tree giữ nguyên.
   - *Có thể giúp:* CVE-2017-7529, nơi khởi động chiếm 55 % thời gian bản ghi attack (36 bỏ sót), và các exploit rơi vào 7 s đầu ở mọi kịch bản;
   - *Không giúp:* Heartbleed và ZipSlip nếu exploit nằm sau giây thứ 7, vì ở đó cửa sổ được chấm vẫn không khác normal;
   - phải đo `exploit_at − t0` trước khi đăng ký (Gap mục 3). Đổi này chỉ dành cho replay LID-DS; live không cần.
3. **Ngưỡng theo kịch bản, chọn trên normal**, ví dụ chia validation thành nửa calibration và nửa chọn ngưỡng, nhắm cùng một ngân sách báo nhầm (chẳng hạn ≈ 1,5 đợt/giờ như gánh live):
   - *Có thể giúp* nơi báo nhầm đang thấp, tức ngưỡng còn nới được: CVE-2019-5418 (0,52 đợt/giờ), Juice-Shop ML (0,53), CVE-2017-7529 (2,16, nới được rất ít). Chỉ có lợi nếu `joint_p` của cửa sổ attack nằm ngay trên 0,0083, điều chưa biết;
   - *Sẽ phải siết* ở Heartbleed (12,9 đợt/giờ), ZipSlip (4,7) và có thể Bruteforce (2,2), nên phát hiện ở đó chỉ giảm. Lợi ích duy nhất ở đó là báo nhầm, ví dụ Heartbleed bớt 118 bản ghi;
   - giới hạn: ngưỡng chọn trên validation không thấy lệch validation → test-normal như ở Heartbleed.
4. **k-of-n**: 1-of-1 hoặc 2-of-3 không liền nhau, kèm α nhỏ hơn để giữ báo nhầm.
   - *Có thể giúp* với exploit chỉ tạo một cửa sổ bất thường (ứng viên: CVE-2019-5418, CVE-2017-7529), và giảm độ trễ đi 0,5 s ở mọi nơi;
   - bằng chứng live: bỏ k2of2 làm gánh tăng khoảng 1,7 lần (37,1/22,3) và control gần gấp đôi, nên phải siết α, mà siết α thì có thể triệt tiêu phần lợi (α/4 kéo recall live xuống 69,2 %);
   - *Không giúp:* Heartbleed, ZipSlip (không có tín hiệu tách được).
5. **Tripwire không dùng E trên LID-DS** (E = ∅, hoặc chỉ giữ `execve`/`execveat`/`clone*`), vì LID-DS không có đường `kubectl exec` mà E được dựng để nuốt:
   - *Có thể giúp* ZipSlip, CVE-2019-5418 và phần Juice-Shop còn sót, nếu exploit dùng một ID trong E vắng mặt khi train, ví dụ các syscall thư mục/stat;
   - *Không giúp* Heartbleed và CVE-2017-7529 (đọc bộ nhớ, khả năng cao không có ID mới; STIDE vẫn tách được Heartbleed, nên tín hiệu ở thứ tự chứ không ở tập ID);
   - rủi ro: báo nhầm tăng. Hiện tripwire chỉ có 7 bản ghi báo nhầm trên 11.341.
   - Trước khi đăng ký: đếm novel IDs ∩ E theo kịch bản trên dữ liệu train/validation (normal) để ước lượng mức báo nhầm. Phép này rẻ, không đụng attack.
6. **Reference tripwire = train + validation** (gần với live, nơi reference là toàn bộ normal trước hết khoảng selection):
   - giảm báo nhầm hệ thống tối đa 3 bản ghi (PHP 2, Juice-Shop 1), tức khoảng 0,03 điểm;
   - phát hiện chỉ có thể giảm (rủi ro ở Juice-Shop 62 %);
   - là sửa vệ sinh, không phải đòn bẩy phát hiện.
7. **Sửa cách báo cáo** (không đổi detector):
   - lưu kết quả từng bản ghi: phát hiện, độ trễ, `exploit_at − t0`, số cửa sổ được chấm sau exploit;
   - báo thêm phát hiện có trần ≤ 3 s và ≤ 15 s để khớp ngữ nghĩa trial live;
   - báo precision ở tỉ lệ nền thật và ở 1:1;
   - báo riêng nhóm "có ID mới" và nhóm "trong process".

     Việc này không tăng điểm, nhưng làm so sánh live–LID-DS hợp lệ và trả lời được Gap ở mục 3.
8. **Ngoài khuôn khổ cải thiện nhanh** (ghi để không nhầm):
   - Heartbleed chỉ tách được bằng thông tin thứ tự syscall: STIDE đạt 100 % với báo nhầm 3 %. Bin cặp băm 64 của Pulse không giữ được thông tin này;
   - ZipSlip, CVE-2019-5418 và Juice-Shop cần tham số syscall (đường dẫn) theo `ST` 4b;
   - cả hai là thay đổi thiết kế, không phải chỉnh tham số.

**Ước lượng gộp, trung thực:** nếu mọi đòn bẩy 1–5 thành công tối đa ở các kịch bản "có thể giúp" (CVE-2017-7529 36, CVE-2019-5418 100, Juice-Shop 44, ZipSlip vài chục qua alias/E), phát hiện gộp có thể lên tới khoảng 85–87 % (1.403 + ~180–250 trên 1.815). Đây là **cận trên**, không phải dự báo. Kỳ vọng hợp lý thấp hơn nhiều, vì chưa có bằng chứng cửa sổ attack ở các kịch bản này nằm gần ngưỡng. Heartbleed (113) gần như chắc chắn vẫn bị bỏ sót trong khuôn khổ này.

### Gaps
- Mọi ước lượng hiệu quả ở trên thiếu ba dữ liệu, đều tính được rẻ từ file đã chuyển đổi trên `.234` mà không cần fit lại:
  - phân phối `joint_p` của cửa sổ attack theo kịch bản;
  - `exploit_at − t0` của từng bản ghi;
  - novel IDs ∩ E theo kịch bản.
- Chưa có lượt chạy amendment 1 (alias). `ST` 5.32 và amendment ghi là chạy "sau lượt live kế tiếp", nên hiệu ứng alias hiện chưa biết.
- Repo không có bài báo LID-DS 2021 nào báo cùng chỉ số theo bản ghi (`ST` 5.32, "Không có ngưỡng đạt"), nên chưa đặt được các con số này cạnh kết quả đã công bố.
