# Tích hợp rule — Falco, tripwire A1, triage probe (tách riêng khỏi kết quả ML)

Cập nhật **22/10/2026 16:13 (UTC+7)**. Giờ trong file là UTC+7, trừ khi ghi UTC.

Đây là báo cáo thứ tư, bên cạnh [Sentinel Pulse — ML](SENTINEL_PULSE_STATUS.md), [thí nghiệm syscall](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) và [RCA](RCA_RUNTIME_STATUS.md). Chủ đồ án yêu cầu (22/10) **tách phần đánh giá ML khỏi việc áp thêm rule**, nên mọi thứ dựa trên luật nằm ở đây.

**Trạng thái: chưa tích hợp.** Quyết định của chủ đồ án (22/10): **hoàn thiện ML trước**, rồi mới tích hợp rule và **so sánh hệ thống không có rule với có rule** trên cùng dữ liệu (thiết kế ở mục R6).
- Các số ở R2 (Falco) và R3 (tripwire) là đánh giá **riêng lẻ** từng rule, đo trên cùng campaign với Pulse. Chúng chưa phải kết quả tích hợp.
- `rule_tier.py` chưa chạy và sẽ không chạy trước khi ML hoàn thiện.

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
| ML sau triage probe (R4) | chờ ML hoàn thiện (R6) | | | | cộng độ trễ chờ case RCA |

- **Hợp ML ∪ Falco:**
  - recall = 100% (ML đã 100%);
  - control ≤ 2,9% + 3,2% = 6,1% (cận trên, chưa có kết quả từng trial của Falco; log Falco đã xóa theo chính sách giữ dữ liệu);
  - gánh = 5,32 + 1,19 đợt/replica-giờ nếu không khử trùng lặp.

## R6. So sánh không có rule với có rule (sau khi ML hoàn thiện; protocol `rule-integration-v1` + bổ sung 1, đăng ký 22/10 16:12)

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
- [ ] Gánh của tripwire trên normal dài (tham chiếu một khoảng, đo trên khoảng sau).
- [ ] Đường triage nhanh (không chờ case RCA đầy đủ) để giữ kernel → gọi người ≤ 3 s.
- [ ] Triage khớp cả tham số của probe, không chỉ tên binary (chống né).
- [ ] Kết quả từng trial cho Falco ở lượt live sau, để tính hợp chính xác.

## Nhật ký

| Giờ (22/10) | Việc | Mục |
|---|---|---|
| 00:58–01:00 | Falco: phần trial trên campaign `pulse-stable-refreshed` | R2 |
| 15:15 | Falco: phần normal theo replica-giờ; xóa log Falco | R2 |
| 15:20 | Tripwire A1 đạt blind cả 4 tiêu chí | R3 |
| 16:00–16:03 | Chủ đồ án cho phép tầng triage sau ML; đăng ký (bản bổ sung 2 của `burden-reduction-v1`) | R4 |
| 16:05–16:10 | Theo yêu cầu tách ML khỏi rule: `burden_levers.py` bỏ hẳn phần rule; `rule_tier.py` riêng, kiểm số ML trùng trước khi áp rule; protocol `rule-integration-v1`; chuyển Falco và tripwire từ báo cáo Pulse sang file này | R1–R5 |

| 16:10–16:13 | Theo quyết định "hoàn thiện ML rồi mới tích hợp rule và so sánh có/không rule": gỡ bước `rule_tier.py` khỏi unit tối nay; đăng ký thiết kế so sánh (`rule-integration-v1` bổ sung 1, 16:12) | R6 |
