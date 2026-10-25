# Tích hợp rule — Falco, tripwire A1, triage probe (tách riêng khỏi kết quả ML)

Cập nhật **25/10/2026 17:10 (UTC+7)**. Giờ trong file là UTC+7, trừ khi ghi UTC.

Đây là báo cáo thứ tư, bên cạnh [Sentinel Pulse — ML](SENTINEL_PULSE_STATUS.md), [thí nghiệm syscall](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) và [RCA](RCA_RUNTIME_STATUS.md). Chủ đồ án yêu cầu (22/10) **tách phần đánh giá ML khỏi việc áp thêm rule**, nên mọi thứ dựa trên luật nằm ở đây.

**Trạng thái: R6 xong (25/10 16:02), kết quả ở mục R6.** ML đã hoàn thiện (Pulse 5.27: stable `policy-k2of2-a5-peer30`, xác nhận live trên `pulse-peer-discount-confirm`). Quyết định của chủ đồ án (22/10): **hoàn thiện ML trước**, rồi mới tích hợp rule và **so sánh hệ thống không có rule với có rule** trên cùng dữ liệu (mục R6). Bổ sung 2 của protocol (25/10 12:56) chốt dữ liệu và định nghĩa trước khi có bất kỳ số rule nào của lượt đó.
- Các số ở R2 (Falco) và R3 (tripwire) là đánh giá **riêng lẻ** từng rule, đo trên cùng campaign với Pulse. Chúng chưa phải kết quả tích hợp.
- `rule_tier.py` chưa chạy riêng; định nghĩa triage của nó được dùng nguyên trong nhánh B3 của R6.

## R1. Nguyên tắc tách

| | Phần ML (báo cáo Pulse) | Phần rule (file này) |
|---|---|---|
| Gồm | Detector Pulse (ExtraTrees + support, conformal, CUSUM), calibration, các hướng giảm gánh L1–L6 (Pulse 5.22): chỉ dùng dữ liệu syscall | Falco (framework có sẵn), tripwire A1 (luật syscall lạ), triage probe (luật dựa trên probe khai báo trong pod spec) |
| Code | `sentinel_pulse/detector`, `attack`, `scripts/analysis/burden_levers.py`… | `scripts/analysis/falco_baseline.py`, `novel_syscalls.py` + `tripwire_verdict.py`, `rule_tier.py` |
| Protocol | `stable-selection-v1`, `burden-reduction-v1` + bổ sung 1… | `tripwire-a1-blind-v1`, `rule-integration-v1` (thay chỗ của bổ sung 2 của burden-reduction-v1, định nghĩa giữ nguyên) |
| Output | `BURDEN-LEVERS.json`, `ideas-verdict.json`… | `RULE-TIER.json`, `falco-baseline-final.json`, `tripwire-verdict.json` |

- **Không số nào ở đây thay đổi số liệu ML.** Script rule lấy nguyên cấu hình ML đã chọn, chấm lại alarm và **kiểm số ML phải trùng** trước khi áp rule (`rule_tier.py`, có test).
- **Thứ tự quyết định** (quyết định của chủ đồ án 22/10):
  - Falco và tripwire chỉ báo **song song**, không chặn hay lọc trước ML;
  - tầng triage chỉ được đặt **sau** preview của ML, mọi preview vẫn được ghi;
  - cho rule quyết định trước hay không: chủ đồ án định sau khi ML stable.
- **Ba thành phần khác nhau về bản chất:**
  - **Falco:** framework rule có sẵn, chạy độc lập trên cụm.
  - **Tripwire A1:** luật do đồ án viết. Tham chiếu là các syscall ID đã thấy lúc bình thường của từng workload, cộng tập exec E đóng băng.
  - **Triage probe:** luật do đồ án viết (`sentinel_pulse/rca/triage.py`, `scripts/analysis/alarm_taxonomy.py`). Nó dùng dữ liệu từ hai công cụ có sẵn: sự kiện exec của **Tetragon** (qua RCA) và danh sách exec probe trong **pod spec** của Kubernetes. Nó không phải một framework có sẵn.

## R2. Falco: framework rule có sẵn, so trên cùng campaign (trước đây Pulse 5.15d; 22/10 00:58–01:00, phần normal 15:15)

- **Falco:** 0.44.1, DaemonSet trên cả 6 node từ 84 ngày nay, bộ rule mặc định đúng như đang triển khai, không chỉnh gì. Log stdout, kể cả file đã xoay vòng, được chép khỏi node lúc 22/10 00:50 (Pulse 5.13, nhật ký 22/10).
- **Script:** `scripts/analysis/falco_baseline.py`, có test. Định nghĩa cố định trước lần chạy đầu:
  - một trial được tính là phát hiện khi có event Falco của đúng container trong [bắt đầu, bắt đầu + 15 s];
  - độ trễ = event đầu tiên − thời điểm sự kiện kernel.
- **Biên nhận:** `results-20261021/pulse-stable-refreshed/falco-baseline-final.json`. Phần trial trùng đúng bản tạm thời; bản tạm thời đã bỏ khỏi repo.

| Trial (campaign `pulse-stable-refreshed`) | Falco (mọi rule) | Pulse ML live (Pulse 5.13a) |
|---|---|---|
| Attack | 35,6% (112/315) | 100% (310/310) |
| ↳ `ptrace` | **100% (63/63)**, rule "PTRACE_TRACEME anti-debug" | 100% |
| ↳ `setns`, `execveat`, `mprotect`, `seccomp` | 19–21%, chỉ nhờ rule drift | 100% |
| Binary vô hại | 21,0% (66/315), rule drift | 94,1% |
| Control idle | 3,2% (10/315), toàn bộ là rule "API Server" bắn trùng lúc | 4,2% |
| Độ trễ attack (p50 / p95) | **0,003 / 0,005 s** (thời điểm event) | 0,94 / 2,26 s (tới preview) |

**Đọc kết quả:**
- **Rule drift** ("Executing binary not part of base image") chỉ bắn ở **10/65** container có trial. Rule chỉ nhận ra file thực thi nằm ở lớp upper của overlayfs (blog Sysdig); ở các container còn lại, binary nhiều khả năng nằm trên volume. Khi bắn, rule drift gắn cờ cả binary vô hại lẫn attack như nhau.
- **Falco bắt tức thì và gần như không nhiễu** với hành vi có rule riêng (`ptrace`), nhưng **không thấy** các hành vi không có rule (thử namespace, exec bất thường, đổi quyền vùng nhớ, seccomp). Pulse thấy tất cả, đổi lại chậm hơn khoảng 1–2 s và gắn cờ binary vô hại nhiều hơn.
- Đây là bổ sung cho nhau chứ không thay nhau: rule cho hành vi đã biết, nhanh; Pulse cho hành vi chưa có rule. Điều này ủng hộ kiến trúc tripwire + ML (A1).
- **Normal (tạm thời):** 6,65 giờ của lượt này (pha chọn và sau campaign tới 17:50 UTC), 520 đợt Falco trong namespace `production` (78 đợt/giờ cho cả cụm). 518 đợt đến từ rule "Unexpected connection to K8s API Server", bắn trên **một pod** là Strimzi entity-operator, một operator K8s hợp lệ.
- **Normal (bản cuối, 22/10 15:15):** đúng khoảng normal của Pulse ở Pulse 5.13b (pha chọn tới hết capture, trừ campaign; 18,3 giờ), log chép lần cuối lúc 12:48.
  - 1.449 đợt Falco, tức **1,19 đợt/replica-giờ** khi chia cho 1.219,3 replica-giờ của Pulse. Pulse trên cùng khoảng: 6,74 (k2of2) hoặc 5,32 (CUSUM).
  - 1.439/1.449 đợt (99,3%) là rule "Unexpected connection to K8s API Server", trên **một pod** Strimzi entity-operator. 10 đợt còn lại là "Shell spawned by untrusted binary" trên Postgres CNPG.
  - Nếu thêm một exception cho entity-operator (việc một đội vận hành sẽ làm), Falco còn khoảng 0,01 đợt/replica-giờ.
  - Phép chia cho replica-giờ của Pulse chỉ gần đúng: Falco xem mọi container `production` trên 3 worker, còn Pulse chỉ tính các container nó chấm.

**Giới hạn:**
- Falco dùng rule mặc định chưa tinh chỉnh cho cụm này; một đội vận hành sẽ thêm exception cho entity-operator.
- Độ trễ của Falco là thời điểm event, chưa phải lúc cảnh báo tới người nhận.
- "Phát hiện" tính mọi rule, kể cả rule bắn trùng lúc (control 3,2%).

## R3. Tripwire A1: syscall lạ ngoài tập exec (trước đây Pulse 5.16; đăng ký 21/10 14:56)

- **Protocol:** `sentinel_pulse/protocol/tripwire-a1-blind-v1.json`.
- **Thời điểm đăng ký:** sau khi campaign của `pulse-stable-refreshed` bắt đầu (13:56), nhưng chưa đọc bất kỳ file feature, decision hay trial nào của lượt này.
- **Luật:** interval có ít nhất một syscall ID không có trong normal tham chiếu của workload và không thuộc tập exec E đóng băng (59 ID, `exec-set-E.json`, sha `a3266613…`). Giống Pulse 5.7c.
- **Bản chính:** tham chiếu là normal từ lúc campaign xong +60 s tới khi worker đầu tiên kết thúc, như Pulse 5.7c. Tiêu chí:
  1. binary vô hại ≤ 10%;
  2. control ≤ 5%;
  3. mỗi kịch bản `ptrace`/`setns`/`execveat` ≥ 90%;
  4. **mới:** p95 độ trễ của tripwire ≤ 2 s ở 3 kịch bản đó. Độ trễ = cuối cửa sổ 500 ms đầu tiên có ID lạ − thời điểm sự kiện kernel.
- **Bản phụ (chỉ mô tả):** tham chiếu chỉ gồm 90 phút pha chọn trước attack, tức tham chiếu mà một tripwire live có được. Nếu nhiễu, tripwire live cần tham chiếu dài hơn, mang từ các lượt trước.
- **Không khẳng định:** tripwire không bắt `mprotect`/`seccomp`. Nó là tín hiệu mức nghiêm trọng đặt cạnh Pulse, không thay Pulse.
- **Code:**
  - `scripts/analysis/novel_syscalls.py` thêm độ trễ và `--secondary-reference-span`. Kết quả các trường cũ trùng bản cũ trên dữ liệu thử; có test.
  - `scripts/analysis/tripwire_verdict.py` áp tiêu chí từ file protocol; có test.
  - Chạy tự động trong giai đoạn final (unit `after-stable-refreshed`).

**Kết quả blind trên `pulse-stable-refreshed` (giai đoạn final 22/10, đọc 15:20; `results-20261021/pulse-stable-refreshed/final/tripwire-verdict.json`): đạt cả 4 tiêu chí**, ở cả bản chính lẫn bản phụ.
- `ptrace`, `setns`, `execveat`: bắt 100%, p95 0,76–0,79 s.
- Binary vô hại 0%, control 0%. Tổng trên mọi attack 60% (không bắt `mprotect`/`seccomp`, như đã nêu trước).
- Bản phụ chỉ dùng 90 phút pha chọn làm tham chiếu mà vẫn không nhiễu, nên tripwire live dùng được tham chiếu của chính lượt chạy.
- Theo quyết định của chủ đồ án, tripwire chỉ báo song song và được tích hợp sau khi ML stable (Pulse 5.19).

## R4. Tầng triage probe sau ML (protocol `rule-integration-v1`, thay bản bổ sung 2 của `burden-reduction-v1`; chủ đồ án cho phép 22/10 16:00)

- **Cách làm:** một đợt cảnh báo của ML không gọi người khi mọi case RCA của cùng container trong vòng 5 s đều là probe-only (định nghĩa của Pulse 5.18, probe khai báo trong pod spec). Đợt không có case thì vẫn gọi (fail-open). **Mọi preview của ML vẫn được ghi.**
- **Không đổi số liệu mức ML:** recall, precision, control, binary vô hại, p95 kernel → preview và số đợt/replica-giờ vẫn là bằng chứng cho detector, và luôn báo trước. Tầng này thêm một mức số liệu thứ hai, **mức gọi người**:
  - số đợt gọi người/replica-giờ, có hai con số:
    - fail-open (cận trên, vì RCA chỉ mở tối đa một case cho mỗi container trong mỗi chu kỳ cooldown, cộng các case tiếp nối);
    - ước tính (đợt không có case được giữ lại theo tỉ lệ của các đợt có case trong cùng workload);
  - recall, precision, control, binary vô hại sau triage.
- **Cái giá nêu trước:**
  - **Độ trễ:** muốn biết probe-only phải chờ case RCA. Hiện preview → case mất p50 2,24 s, p95 2,59 s, nên kernel → gọi người vượt mức 3 s nếu không làm đường triage nhanh hơn. Đường nhanh chỉ cần các exec tới cuối cửa sổ + 0,5 s.
  - **Né tránh:** khớp theo tên binary, không theo tham số. Kẻ tấn công chạy chính interpreter của probe (`python`, `sh`, `redis-cli`…) qua `kubectl exec` sẽ bị giữ lại. Bản triển khai thật phải khớp cả tham số của probe.
- **Đã thấy trước ở mức case (Pulse 5.18, 5.13b):** 50,3% case normal là probe-only; không có trial attack nào mà mọi case đều probe-only.
- **Chạy:** `scripts/analysis/rule_tier.py` (có test), output riêng `RULE-TIER.json`. **Chỉ chạy sau khi ML hoàn thiện**, như một nhánh của phép so sánh ở R6; đã gỡ khỏi unit tối 22/10.

## R5. Từng rule đứng riêng, đặt cạnh ML (chưa phải tích hợp)

- **Cách báo:** các luồng song song cộng cảnh báo lại. Tổng cảnh báo tới người = ML (sau triage) + Falco + tripwire, không khử trùng lặp trừ khi đo được.
- Khi không có kết quả từng trial của rule, recall và control của hợp được báo bằng cận.
- **Hiện có (`pulse-stable-refreshed`):**

| Luồng | Recall attack | Control | Binary vô hại | Đợt/replica-giờ trên normal | Độ trễ attack p95 |
|---|---|---|---|---|---|
| ML (CUSUM b3/h6, Pulse 5.13b) | 100% | 2,9% | 98,1% | 5,32 | 1,70 s (tới preview) |
| Falco, rule mặc định (R2) | 35,6% | 3,2% | 21,0% | 1,19 (99% từ một pod; ~0,01 nếu thêm exception) | 0,005 s (thời điểm event) |
| Tripwire A1 (R3) | 60% (100% ở 3 kịch bản syscall hiếm) | 0% | 0% | chưa đo trên normal dài | 0,76–0,79 s |
| ML sau triage probe (R4) | xem R6 | | | | cộng độ trễ chờ case RCA |

- **Trên lượt xác nhận `pulse-peer-discount-confirm`** (kết quả từng trial, cùng khoảng normal với ML): xem bảng "từng rule đứng riêng" ở R6.

- **Hợp ML ∪ Falco:**
  - recall = 100% (ML đã 100%);
  - control ≤ 2,9% + 3,2% = 6,1% (cận trên, chưa có kết quả từng trial của Falco; log Falco đã xóa theo chính sách giữ dữ liệu);
  - gánh = 5,32 + 1,19 đợt/replica-giờ nếu không khử trùng lặp.

## R6. So sánh không có rule với có rule (sau khi ML hoàn thiện; protocol `rule-integration-v1` + bổ sung 1, đăng ký 22/10 16:12)

**Bổ sung 2 (`sentinel_pulse/protocol/rule-integration-v1-amendment-2.json`, đăng ký 25/10 12:56, trước mọi số rule của lượt):**
- dữ liệu chính: `pulse-peer-discount-confirm`; nhánh A = preview live của `policy-k2of2-a5-peer30` (cột `preview` của bảng cửa sổ);
- một khoảng normal chung cho mọi nhánh: từ cuối khoảng selection tới hết capture, bỏ khoảng campaign; replica-giờ lấy từ bảng cửa sổ ML;
- tripwire B2: tham chiếu = hợp các syscall ID theo workload trên khoảng selection của lượt, tập exec E đóng băng (sha256 `a3266613…`);
- Falco B1 và triage B3: giữ nguyên định nghĩa của `falco_baseline.py` và `rule_tier.py`; khóa container = (pod_uid, container), tên pod của Falco map sang pod_uid bằng metadata resolver của worker;
- độ trễ B3: thời điểm tạo case RCA (quyết định triage), không có case thì lấy thời điểm preview (fail-open);
- so sánh: hiệu ghép cặp theo trial, bootstrap theo workload 10.000 lần; hiệu gánh cùng bootstrap; hiệu p95 bootstrap theo trial.
- **Code:** `scripts/analysis/rule_comparison.py` (có test), `novel_syscalls.py --normal-span` (tham chiếu đủ trước khi xét normal, kết quả từng trial), `falco_baseline.py` (tên container trên event normal); driver `scripts/rule_integration_r6.sh` (commit `be481a5`).

- **Khi nào:** chỉ sau khi:
  1. cấu hình ML stable đã đóng băng (Pulse 5.19 bước 4);
  2. hướng giảm gánh của Pulse 5.22 đã được nhận hoặc bỏ sau test blind;
  3. lượt live xác nhận đã xong.
- **Các nhánh, cùng một dữ liệu:**

| Nhánh | Gồm |
|---|---|
| A — không có rule | Cấu hình ML stable đứng một mình (số liệu luận văn cho detector) |
| B1 | ML + Falco, hai luồng song song |
| B2 | ML + tripwire A1, song song |
| B3 | ML, rồi triage probe trước khi gọi người |
| B — đủ | ML (sau triage) + Falco + tripwire |
| Sau này | Thứ tự rule quyết định trước: chỉ nếu chủ đồ án quyết định, đăng ký riêng |

- **Dữ liệu:**
  - chính: lượt live xác nhận (campaign mới, blind cho mọi nhánh);
  - phụ: `pulse-stable-candidate`, `pulse-stable-refreshed` (development; Falco ở đó chỉ còn số tổng hợp vì log đã xóa).
- **Metric mỗi nhánh:**
  - recall theo kịch bản và tổng, precision, control, binary vô hại;
  - p95 kernel → cảnh báo đầu tiên của nhánh (luồng song song: cảnh báo sớm nhất của bất kỳ luồng nào; triage: cộng thời gian chờ quyết định triage);
  - cảnh báo tới người/replica-giờ trên normal: cộng các luồng, gộp cảnh báo cùng container cách nhau < 15 s;
  - chi phí: bảo trì rule (exception), khả năng bị né.
- **So sánh:** mỗi nhánh B với A trên cùng trial và cùng khoảng normal. Hiệu ghép cặp theo trial, CI 95% bằng bootstrap theo workload; hiệu p95 bằng bootstrap theo trial.
- **Cần chuẩn bị cho lượt live xác nhận:**
  - giữ log Falco tới khi so sánh xong; `falco_baseline.py` phải xuất kết quả từng trial và thời điểm từng event;
  - tripwire chạy trên normal của chính lượt đó (tham chiếu trước campaign, đếm cảnh báo trên normal sau đó);
  - RCA gắn nhãn triage cho mọi case, và báo tỉ lệ đợt ML không có case.

**Còn thiếu:**
- [x] Gánh của tripwire trên normal dài (tham chiếu một khoảng, đo trên khoảng sau): 0,099 đợt/replica-giờ trên 10,6 giờ normal (R6, 25/10).
- [ ] Đường triage nhanh (không chờ case RCA đầy đủ) để giữ kernel → gọi người ≤ 3 s. R6 cho thấy cần thật: chờ case làm p95 tăng thêm 2,3–3,6 s, và 58% đợt ML trên normal không có case nào để triage.
- [ ] Triage khớp cả tham số của probe, không chỉ tên binary (chống né).
- [x] Kết quả từng trial cho Falco ở lượt live sau, để tính hợp chính xác (`pulse-peer-discount-confirm`, 25/10).

### R6 — kết quả (25/10, `pulse-peer-discount-confirm`, bổ sung 2)

**Dữ liệu:**
- 1.572 trial, trong đó 524 attack. Tập chính (6, 12, 24/s) có 315 attack, 315 control, 315 binary vô hại.
- Khoảng normal chung: từ hết campaign tới hết capture, 10,6 giờ, 706,8 replica-giờ. Khoảng campaign bị loại (gồm lề 60 s) bắt đầu 65 s sau khi hết khoảng selection, nên trên thực tế khoảng normal của R6 là phần sau campaign.
- Ghép cặp đủ: mọi trial ML đều có kết quả Falco và tripwire; mọi pod của Falco đều map được sang pod_uid; không event nào của rule rơi ngoài bảng cửa sổ.

**Kiểm số ML (bắt buộc theo protocol):** nhánh A khớp Pulse 5.27: recall 98,7%, precision 98,7%, control 1,3%.
- p95 ở đây là 2,91 s, so với 2,88 s của campaign. Hai số khác nhau vì định nghĩa: ở đây độ trễ = cuối cửa sổ cảnh báo − `kernel_event_at`, đo trên 315 trial của bảng cửa sổ; campaign tính tới lúc ghi preview, trên 310 trial coordinator chấm được. Mọi nhánh R6 dùng cùng một định nghĩa.
- Gánh của A trên khoảng normal R6 là 1,42 đợt/replica-giờ, so với 1,69 của Pulse 5.27. Khác vì khoảng normal khác (1,69 tính từ đầu khoảng selection). Cách gộp đợt không làm đổi số: gộp theo (pod_uid, container) hay theo định danh bảng cửa sổ đều ra 1,418.

**Từng rule đứng riêng, cùng trial và cùng khoảng normal:**

| Luồng | Recall attack, tập chính (mọi tốc độ) | Theo kịch bản | Control | Binary vô hại | Precision | Đợt/replica-giờ | p95 |
|---|---|---|---|---|---|---|---|
| ML (A) | 98,7% (94,5%) | 96,8–100% | 1,3% | 85,7% | 98,7% | 1,42 | 2,91 s |
| Falco, rule mặc định | 36,2% (36,5%) | ptrace 100%, còn lại 19–22% | 1,6% | 21,3% | 95,8% | 1,20 | 0,007 s |
| Tripwire A1 | 60,0% (59,9%) | ptrace, execveat, setns 100%; mprotect, seccomp 0% | 0,3% | 0,6% | 99,5% | **0,099** | 0,79 s |

- **Tripwire lặp lại kết quả blind của R3 trên một lượt mới**, và lần đầu có gánh trên normal dài: 0,099 đợt/replica-giờ, nằm trong ngân sách 0,1.
- **Falco:** 839/845 đợt normal đến từ một rule ("Unexpected connection to K8s API Server") trên một workload (`aims-kafka-entity-operator`, operator Strimzi gọi API server là hành vi hợp lệ). Mọi control dương của Falco cũng đến từ rule này (5 ở tập chính, 8 trên mọi tốc độ).

**Các nhánh, tập chính:**

| Nhánh | Recall (mọi tốc độ) | Control | Binary vô hại | Precision | p50 | p95 (mọi tốc độ) | Đợt/replica-giờ |
|---|---|---|---|---|---|---|---|
| A — ML | 98,7% (94,5%) | 1,3% (4) | 85,7% | 98,7% | 0,86 s | 2,91 s (3,72 s) | 1,42 |
| B1 — ML + Falco | 98,7% (95,2%) | 2,9% (9) | 86,0% | 97,2% | 0,71 s | 2,48 s (3,20 s) | 2,54 |
| B2 — ML + tripwire | 98,7% (96,6%) | 1,6% (5) | 85,7% | 98,4% | 0,68 s | 2,44 s (2,61 s) | 1,48 |
| B3 — ML rồi triage probe | 98,7% (94,5%) | 1,3% (4) | 85,7% | 98,7% | 3,23 s | 5,90 s (6,52 s) | 1,09 |
| B_all | 98,7% (96,6%) | 3,2% (10) | 86,0% | 96,9% | 0,54 s | 4,82 s (4,88 s) | 2,28 |

**Hiệu so với A (tập chính, CI 95%; bootstrap theo workload 10.000 lần, p95 bootstrap theo trial):**

| Nhánh | Recall | Control | Binary vô hại | Đợt/replica-giờ | p95 |
|---|---|---|---|---|---|
| B1 | 0 [0; 0] | +1,6 điểm [0; +4,1] | +0,3 điểm [0; +1,0] | +1,12 [0; +3,25] | −0,43 s [−1,35; −0,01] |
| B2 | 0 [0; 0] | +0,3 điểm [0; +1,0] | 0 [0; 0] | **+0,066 [+0,020; +0,133]** | **−0,47 s [−1,62; −0,04]** |
| B3 | 0 [0; 0] | 0 [0; 0] | 0 [0; 0] | **−0,33 [−0,75; −0,09]** | **+2,3 s đến +3,6 s** (CI của hiệu) |
| B_all | 0 [0; 0] | +1,9 điểm [0; +4,4] | +0,3 điểm [0; +1,0] | +0,86 [−0,41; +3,02] | +0,84 s đến +2,39 s |

CI của gánh B1 có cận dưới đúng 0 vì gần như mọi đợt thêm của Falco nằm ở một workload: các lần lấy mẫu không có workload đó cho hiệu 0.

**Triage (B3):**
- Giữ lại 233/1.002 đợt ML trên normal (−23% gánh); không giữ attack hay control nào.
- Chỉ 421 đợt (42%) có case RCA; 581 đợt còn lại đi qua theo luật fail-open. 44 trial ML dương không có case, nên dùng thời điểm preview.
- Chờ case RCA đẩy p95 lên 5,90 s, quá mức ≤ 3 s.

**Đọc kết quả (mô tả; protocol không có luật nhận/bỏ, chủ đồ án quyết định):**
1. Ở tập chính, không rule nào tăng recall. ML đã bắt 98,7%; 4 trial bỏ sót là `mprotect`/`seccomp`, và cả Falco lẫn tripwire đều không bắt được hai kịch bản này.
2. Ở tốc độ chậm (1, 3/s), tripwire thêm 2,1 điểm recall (94,5% → 96,6%), Falco thêm 0,8 điểm.
3. **B2 (ML + tripwire) là nhánh duy nhất** vừa giữ mọi số ML, vừa ở mức ≤ 3 s, vừa nhanh hơn (p95 −0,47 s), với chi phí gánh nhỏ nhưng có ý nghĩa: +0,066 đợt/replica-giờ (+4,7%) và 1 control dương thêm.
4. **B1 (Falco mặc định):** gánh +79% và control gấp đôi, đều do một rule trên một workload hợp lệ. Muốn dùng phải thêm exception cho rule đó (chi phí bảo trì). Lợi ích: p95 nhanh hơn nhờ phát hiện ptrace trong vài ms.
5. **B3 (triage chờ case RCA đầy đủ):** giảm gánh 23% mà không mất attack, nhưng không dùng được ở thời điểm gọi người vì làm hỏng mức độ trễ. Chỉ dùng được nếu có đường triage nhanh (mục "Còn thiếu").
6. **B_all:** tệ nhất về control và p95, vì cộng nhiễu của Falco với độ trễ của triage.

**Biên nhận:** `validation-evidence/results-20261025/rule-integration/` (`falco-baseline.json`, `tripwire-a1.json.gz`, `rule-comparison.json`; SHA-256 khớp bản gốc trên NFS `pulse-peer-discount-confirm/analysis/rule-integration/`).
- Code: Falco và tripwire chạy trên snapshot `be481a5` (13:09–13:35). Bước ghép chạy lại trên `ae9af77` (15:57–16:02) để thêm số từng rule đứng riêng, tỉ lệ đợt có case và phép kiểm gánh ML; mọi số đã có trước đó giữ nguyên từng trường.

**Dữ liệu phụ (`pulse-stable-confirm`, chỉ báo cáo, không dùng cho kết luận):**
- Nhánh A là luật ≤ 3 s (`joint|peer30|k2of2_a5`) tính lại trên bảng cửa sổ, vì preview live của lượt này là CUSUM `cap`.
- Phép kiểm khớp test blind 5.22 trên cùng lượt: control 2,9%, precision 97,2%, p95 2,68 s.
- Khoảng normal: từ hết campaign tới hết capture, 864,3 replica-giờ.
- Lượt này còn có replica `cnpg-2` hỏng (Pulse 5.24).

| Nhánh | Recall (mọi tốc độ) | Control | Precision | p95 | Đợt/replica-giờ | Hiệu gánh so với A [CI] | Hiệu p95 [CI] |
|---|---|---|---|---|---|---|---|
| A | 99,0% (94,1%) | 2,9% | 97,2% | 2,68 s | 1,50 | — | — |
| B1 + Falco | 99,0% (95,0%) | 4,1% | 96,0% | 2,40 s | 2,55 | +1,05 [−0,03; +3,08] | [−1,20; +0,01] s |
| B2 + tripwire | 99,0% (96,2%) | 2,9% | 97,2% | 2,13 s | 1,54 | **+0,045 [+0,004; +0,113]** | **[−1,96; −0,08] s** |
| B3 + triage | 99,0% (94,1%) | 2,5% | 97,5% | 5,93 s | 1,35 | **−0,15 [−0,32; −0,03]** | **[+1,82; +8,14] s** |
| B_all | 99,0% (96,2%) | 3,8% | 96,3% | 4,88 s | 2,45 | +0,95 [−0,19; +2,99] | [+0,80; +3,18] s |

- Từng rule đứng riêng: Falco gánh 1,16 (gần hết từ `aims-kafka-entity-operator`), recall 38,7%, control 3,2%; tripwire gánh 0,050, recall 60,3%, control 0%, binary vô hại 0%.
- Triage giữ lại 126/1.292 đợt ML; chỉ 352 đợt có case RCA.
- **Cùng hướng với dữ liệu chính:** rule không thêm recall ở tập chính; tripwire thêm recall ở tốc độ chậm (+2,1 điểm) và nhanh hơn với gánh rất nhỏ; Falco mặc định tăng gánh khoảng 70%; triage giảm gánh nhưng quá mức ≤ 3 s.
- Biên nhận: `validation-evidence/results-20261025/rule-integration-secondary/` (SHA-256 khớp NFS `pulse-stable-confirm/analysis/rule-integration/`). Code `43cc1fc` (unit `rule-integration-r6-secondary`, 16:06–17:02). Bước ghép mất 34 phút vì `in_normal` tính lại `max` trên cả bảng cho mỗi event (38.655 event Falco); đã sửa ở `ea3edeb`, số không đổi.

## Nhật ký

| Giờ (22/10) | Việc | Mục |
|---|---|---|
| 00:58–01:00 | Falco: phần trial trên campaign `pulse-stable-refreshed` | R2 |
| 15:15 | Falco: phần normal theo replica-giờ; xóa log Falco | R2 |
| 15:20 | Tripwire A1 đạt blind cả 4 tiêu chí | R3 |
| 16:00–16:03 | Chủ đồ án cho phép tầng triage sau ML; đăng ký (bản bổ sung 2 của `burden-reduction-v1`) | R4 |
| 16:05–16:10 | Theo yêu cầu tách ML khỏi rule: `burden_levers.py` bỏ hẳn phần rule; `rule_tier.py` riêng, kiểm số ML trùng trước khi áp rule; protocol `rule-integration-v1`; chuyển Falco và tripwire từ báo cáo Pulse sang file này | R1–R5 |

| 16:10–16:13 | Theo quyết định "hoàn thiện ML rồi mới tích hợp rule và so sánh có/không rule": gỡ bước `rule_tier.py` khỏi unit tối nay; đăng ký thiết kế so sánh (`rule-integration-v1` bổ sung 1, 16:12) | R6 |
| 23:15 | Chuẩn bị dữ liệu (không tính số rule): `falco_baseline.py` xuất kết quả từng trial và từng event normal (có test), để so sánh ghép cặp có/không rule ở R6 sau khi ML hoàn thiện. Log Falco của lượt xác nhận sẽ được chép tay ngay sau lượt chạy | R6 |
| 23/10 11:40, 13:05 | Log Falco của lượt xác nhận chép về đĩa local từng worker (`/var/tmp/falco-logs-pulse-stable-confirm/`, `cp -u`, gồm file đã xoay vòng): worker1 xoay vòng 4 giờ/lần, lần 2 đã có file 05:15 UTC. Lần chép cuối và chuyển lên NFS sau lượt. Campaign của lượt (Pulse 5.25) là dữ liệu cho R6 | R2, R6 |
| 25/10 12:56 | Đăng ký bổ sung 2 của `rule-integration-v1` (dữ liệu chính `pulse-peer-discount-confirm`, nhánh A = preview live, một khoảng normal chung, khóa container, độ trễ B3) trước mọi số rule của lượt | R6 |
| 25/10 13:07–13:08 | Code R6: `rule_comparison.py` + test (428 test pass), `novel_syscalls.py --normal-span`, tên container trong event Falco; driver `rule_integration_r6.sh`; đồng bộ GitHub, .234 và 3 worker (`be481a5`) | R6 |
| 25/10 13:09 | Chạy R6 trên .234 (unit `rule-integration-r6`, root vì case RCA thuộc root, MemoryMax 24G, mã nguồn chụp `be481a5`). Không có lượt live nào đang chạy. Bước Falco xong 13:10; tripwire đọc toàn bộ feature (11 GB), ước tính 2–3 giờ | R6 |
| 25/10 13:35 | R6 xong lần đầu (Falco, tripwire, ghép 5 nhánh); tripwire đọc toàn bộ feature chỉ mất 21 phút, nhanh hơn nhiều so với ước tính 2–3 giờ | R6 |
| 25/10 15:57–16:02 | Bước ghép chạy lại trên `ae9af77` để thêm phần còn thiếu theo danh sách báo cáo của protocol: từng rule đứng riêng, tỉ lệ đợt ML có case, kiểm gánh ML. Số cũ giữ nguyên từng trường | R6 |
| 25/10 16:03–16:10 | Biên nhận vào repo (SHA khớp NFS); kết quả R6 ghi ở trên | R6 |
| 25/10 16:06–17:02 | Dữ liệu phụ của bổ sung 2 trên `pulse-stable-confirm` (nhánh A = luật ≤ 3 s tính lại, `--ml-rule le3s`): cùng hướng với dữ liệu chính; biên nhận vào repo | R6 |
