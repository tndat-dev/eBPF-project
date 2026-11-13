# Ghi chép nghiên cứu các điểm yếu (12–13/11/2026)

Ghi lại mọi thứ đã tìm hiểu và đã đo để cải thiện các điểm yếu của hệ thống `lidds-ml-v5`: câu hỏi, cách làm, số liệu, cách hiểu, kết
quả âm, thiết kế đang cân nhắc và nguồn tài liệu. Lộ trình tổng: [PAPER_PLAN.md](PAPER_PLAN.md). Nhật ký: [WORKLOG.md](WORKLOG.md).

Quy ước: mọi con số lấy từ biên nhận trong `validation-evidence/`; protocol đăng ký trước khi viết code
(`sentinel_pulse/protocol/ml-final-study-v1.json`, amendment 1). Phân tích ở đây là **development**: làm trên dữ liệu đã có (lượt
`pulse-live-v5-1110`, LID-DS 2021 development, CB-DS). Một thay đổi của hệ thống chỉ được nhận sau một lần xác nhận trên dữ liệu mới.

## 1. Tổng hợp nhanh

| Điểm yếu | Đã thử | Kết quả | Trạng thái |
|---|---|---|---|
| Recall live có thể chỉ là "có process mới" | A: bỏ gram khởi chạy rồi chấm lại | 314/314 vẫn bị bắt, 0 trial chỉ nhờ burst | Đã khép: recall đo đúng hành vi tấn công |
| Process vô hại mới bị gắn cờ | B: học 9 lệnh quản trị, chấm lệnh thứ 10 | 362/439 vẫn bị gắn cờ; recall tụt 303/314 | Âm |
| | B2: học phiên quản trị của trial khác trên cùng workload | 372/439 vẫn bị gắn cờ | Âm |
| | B3: tách dòng native / session (proxy) | Dòng native: 0/525, 0/439, 0/523 bị gắn cờ; mô hình phiên với ngưỡng Gumbel không bắt tấn công (0/522) | Một nửa đạt: xem mục 5 |
| | Gate sau execve (lidds-ml-v5, trước đó) | Mất exploit thật trên LID-DS (315–509/544) | Âm |
| Ngưỡng không giữ mức thiết kế | C: phân vị thực nghiệm của 134.905 khối 60 s | Gánh giảm nửa, recall 281/314, LID-DS 498/544 | Âm, giữ Gumbel |
| Tấn công chỉ dùng chuỗi đã thấy | D: tín hiệu tần suất | 225/544 (mô hình: 0); ghép: CB-DS 4 báo nhầm (cần ≤ 3) | Suýt đạt, không ghép |
| Chưa biết tải tới đâu thì map đầy | Đo tải lượt v5 | Tối đa 2,6% map; 0 lần chèn thất bại ở segment cuối | Một phần: chưa có bài stress |
| Tấn công live không phải exploit thật | Khảo sát mã nguồn kịch bản LID-DS | Dựng được trên cụm (mục 7) | Chưa làm |
| Chưa có baseline cùng protocol | Rà kết quả công bố và bản chạy dở 02/11 | Chỉ STIDE có kết quả trên đủ 15 kịch bản (mục 8) | Chưa xong |

Kết luận tới lúc này: không ứng viên nào đạt tiêu chí đã đăng ký, **mô hình ML giữ nguyên `lidds-ml-v5`**. Phát hiện có giá trị nhất là
ở B3: nếu kernel gắn thẻ dòng dõi cho thread, dòng native không còn báo trên phiên của người vận hành, và mọi sự kiện của LID-DS đều
là native nên kết quả dataset không đổi.

## 2. A: recall live đo cái gì

**Câu hỏi.** Mọi tấn công của campaign bắt đầu bằng `kubectl exec`. Binary vô hại cùng trial bị gắn cờ 314/314, và 14 tấn công báo trước
cả khi binary tấn công được exec. Vậy 314/314 đo hành vi tấn công, hay chỉ đo "có process được dựng"?

**Cách làm** (`scripts/analysis/live_attribution.py`). Đọc `tokens.jsonl` của lượt v5 (gram và số lần của từng cửa sổ), chấm lại bằng đúng
mô hình và ngưỡng của lượt. Cổng kiểm: 59.238 cửa sổ chấm lại khớp điểm đã log, sai khác lớn nhất 0,0. Ba cách tính cho mỗi trial tấn công:

- **như đã chạy:** có cửa sổ trong 15 s của đoạn tấn công vượt ngưỡng;
- **riêng của tấn công:** bỏ khỏi cửa sổ mọi gram mà chính container đó đã sinh ra trong đoạn binary vô hại và đoạn lệnh quản trị của
  cùng trial, rồi chấm phần còn lại;
- **sau khởi chạy:** chỉ tính cửa sổ kết thúc ít nhất 1,5 s sau khi đoạn bắt đầu, không bỏ gram nào.

**Kết quả** (`validation-evidence/results-20261113/ml-final-study/live-attribution.json`).

| | Tập chính (6, 12, 24 lần/s) | Mọi tốc độ |
|---|---|---|
| Như đã chạy | 314/314 | 521/522 |
| Riêng của tấn công | 314/314 | 521/522 |
| Sau khởi chạy | 302/314 | 414/522 |
| Chỉ bị bắt nhờ gram khởi chạy | 0 | 0 |

Sau khởi chạy theo tốc độ: 1 lần/s 32/103, 3 lần/s 80/105, 6 lần/s 96/104, 12 lần/s 103/105, 24 lần/s 103/105. Cảnh báo riêng của tấn
công tới sau p50 0,61 s, p95 0,73 s kể từ đầu đoạn (tập chính).

**Cách hiểu.** Recall live không phải sản phẩm phụ của burst khởi chạy: bỏ hết gram khởi chạy thì từng trial vẫn bị bắt. Ở tốc độ thấp,
phần "sau khởi chạy" giảm mạnh (32/103 ở 1 lần/s): tấn công chậm được bắt chủ yếu trong giây đầu, khi thao tác đầu tiên của nó xuất hiện.

**Giới hạn.** Gram khởi chạy mà binary tấn công có nhưng binary vô hại không có (đường dẫn, cỡ khác) được tính là "riêng của tấn công",
nên con số là cận trên cho "bắt được nhờ đúng thao tác tấn công".

## 3. B và B2: dạy mô hình workload các phiên quản trị

**Ý tưởng.** Lệnh quản trị là một phần normal của container production. Nếu mô hình đã thấy vài phiên, nó sẽ không báo nữa.

**B, bỏ-một-lệnh.** Với mỗi lệnh c, mô hình của workload học thêm cửa sổ của 9 lệnh còn lại (mọi trial), rồi chấm các đoạn của lệnh c.
Ngưỡng giữ nguyên của lượt v5.

| Lệnh | Bị gắn cờ khi lệnh chưa học | Với mô hình v5 | Số lần |
|---|---|---|---|
| cat | 46 | 49 | 49 |
| date | 33 | 45 | 50 |
| df | 47 | 51 | 51 |
| env | 31 | 52 | 52 |
| id | 48 | 51 | 51 |
| ls | 38 | 44 | 44 |
| ps | 7 | 7 | 7 |
| python | 33 | 34 | 38 |
| sh | 45 | 46 | 48 |
| uname | 34 | 43 | 49 |
| **Tổng** | **362 (82,5%)** | **422 (96,1%)** | **439** |

Khi mô hình học cả 10 lệnh: binary vô hại 285/314 (v5: 314/314), tấn công tập chính 303/314 (v5: 314/314), riêng của tấn công 299/314,
control 0/525.

**B2, giữ ra theo trial** (`scripts/analysis/session_model.py`). Chia cặp trial vào 5 fold theo số cặp; mô hình của workload học phiên
quản trị của các fold khác trên chính workload đó (mọi lệnh), rồi chấm phiên của fold còn lại: **372/439 (84,7%)** vẫn bị gắn cờ.
Theo lệnh: cat 46/49, date 35/50, df 47/51, env 37/52, id 49/51, ls 38/44, ps 7/7, python 33/38, sh 45/48, uname 35/49.

**Cách hiểu.**

- Học lệnh khác không giúp lệnh mới: phần chung (burst dựng process) chỉ là một phần nhỏ của điều lạ, mỗi lệnh có chuỗi riêng.
- Học cả phiên của cùng lệnh ở trial khác cũng gần như không giúp (B2). Mỗi workload chỉ có khoảng 21 phiên cho 10 lệnh, tức 1–2 lần mỗi
  lệnh; cùng một lệnh ở hai lần chạy cho các gram khác nhau (xen kẽ với thread khác, thư viện, đường đi của kubelet).
- Dạy mô hình workload về phiên còn có hại: recall tấn công giảm (303/314), vì số đếm thêm làm các gram chung bớt bất ngờ. Nếu về sau một
  exploit trong dịch vụ gọi `sh` hay `cat`, mô hình đã học `sh` của admin sẽ coi đó là quen. Đây là lý do chính để **không** trộn phiên vào
  mô hình của workload.

## 4. C: ngưỡng trên cụm

**Câu hỏi.** Ngưỡng Gumbel để 350/134.905 khối 60 s giữ ra vượt ngưỡng (0,259%), gấp 14 lần mức thiết kế 0,018%. Trên cụm có hơn một
trăm nghìn khối, có thể bỏ giả thiết phân bố và lấy thẳng phân vị thực nghiệm.

**Cách làm.** Chạy lại cross-fit đã đăng ký của lượt v5 (`token_branch_fit.py --dump-maxima`, tuần tự, trần 20 GB, 3 giờ 18 phút CPU); ngưỡng
Gumbel của bản chạy lại bằng đúng `MODELS.json` (sai khác 0,0). So ba quy tắc trên dữ liệu lượt v5 (`cluster_threshold.py`).

| Quy tắc | Ngưỡng trung vị | Tấn công tập chính | Riêng của tấn công | Binary vô hại | Lệnh quản trị | Control | Gánh (đợt/replica-giờ, 5 segment đã khai) | LID-DS development | CB-DS |
|---|---|---|---|---|---|---|---|---|---|
| Gumbel (v5) | 12,98 | 314/314 | 314/314 | 314/314 | 422/439 | 0/525 | 0,105 | 530/544, 6 | 891/891, 3 |
| Phân vị thực nghiệm ở α′ | 16,17 | 281/314 | 256/314 | 283/314 | 359/439 | 0/525 | 0,053 | 498/544, 13 | 891/891, 2 |
| Phân vị khớp tỉ lệ vượt của Gumbel | 12,66 | 314/314 | 314/314 | 314/314 | 422/439 | 0/525 | 0,116 | | |

**Cách hiểu.** Phân vị thực nghiệm ở α′ = 0,00018 gần như là cực đại của normal giữ ra: gánh giảm một nửa, nhưng mất 33 tấn công tập
chính, và trên LID-DS (chỉ khoảng 270 cực đại mỗi kịch bản) vừa mất 32 bản ghi vừa thêm báo nhầm. Ngưỡng Gumbel "sai" theo đúng hướng có
lợi: nó để lọt nhiều khối normal hơn thiết kế nhưng giữ được recall. Đồ án tiếp tục báo α′ như một núm chỉnh, không phải tỉ lệ báo nhầm.

## 5. B3: tách theo dòng dõi process (hướng đang theo)

### 5.1 Ý tưởng

Mỗi container có hai dòng sự kiện:

- **native:** thread thuộc cây process của chính workload (entrypoint và con cháu);
- **session:** thread thuộc một process đi vào container qua runtime exec (`kubectl exec`, exec probe của kubelet) và con cháu của nó.

Dòng native được chấm bằng mô hình workload hiện tại, không đổi gì. Dòng session có mô hình riêng. Lợi ích kỳ vọng:

1. Phiên của người vận hành không còn làm mô hình workload báo, mà không phải dạy mô hình workload điều gì về phiên (tránh cái hại ở mục 3).
2. Bản ghi LID-DS 2021 không có runtime exec, nên mọi sự kiện là native: kết quả 1.238/1.271 không đổi theo cấu trúc.
3. Exploit trong dịch vụ (mô hình đe doạ chính của LID-DS) vẫn ở dòng native, kể cả khi nó sinh shell: shell đó là con của dịch vụ.

### 5.2 Kiểm bằng proxy trên dữ liệu v5

Lượt v5 chưa có thẻ dòng dõi. Proxy: gram mà mô hình workload **chưa thấy** (ở đúng độ dài của nó) coi là session, phần còn lại là
native. Proxy này lệch hai chiều: gram của phiên mà workload cũng biết rơi về native, gram mới của chính workload rơi về session.

**Dòng native** (chấm phần native bằng mô hình và ngưỡng v5):

| Đoạn | Bị gắn cờ |
|---|---|
| Control idle | 0/525 |
| Lệnh quản trị | 0/439 |
| Binary vô hại | 0/523 |
| Tấn công (qua `kubectl exec`) | 1/522 |

Tức là toàn bộ cảnh báo của lượt v5 trên các đoạn này đến từ gram chưa thấy. Với thẻ dòng dõi thật, dòng native sẽ không báo trên phiên
quản trị và binary vô hại. Dòng native cũng không thấy tấn công của campaign, vì các tấn công đó đi vào qua exec: chúng thuộc dòng session.

**Mô hình phiên** (một `CountTokenLM` cho cả cụm, học từ phần session của các đoạn lệnh quản trị; 439 đoạn, 2.015 gram khác nhau; ngưỡng
theo quy tắc đã đăng ký trên cực đại giữ ra của từng đoạn):

| Nhánh | Kết quả |
|---|---|
| Tool đã biết (cross-fit theo fold) | 0/439 bị gắn cờ, ngưỡng 37,7 |
| Tool chưa thấy (bỏ-một-lệnh) | 0/439 |
| Chương trình lạ (binary vô hại, mô hình chỉ học lệnh quản trị) | 0/523 |
| Chương trình đã học (thêm binary vô hại của fold khác) | 0/523, ngưỡng 42,4 |
| Tấn công, mô hình chỉ học tool | 0/522 |
| Tấn công, mô hình học cả tool và binary vô hại | 0/522 |

**Quyết định theo tiêu chí đã đăng ký:** dòng native đạt (≤ 5%), tool đã biết đạt (≤ 20%), tấn công không đạt (cần ≥ 95%, được 0%). Vì
vậy theo amendment 1, **chưa** dựng thẻ dòng dõi trên cơ sở này.

**Vì sao mô hình phiên không bắt gì.** Dữ liệu phiên rất ít và không đồng nhất (mỗi đoạn là một lệnh ngắn như `ls /`, `date`), nên cực
đại giữ ra của các đoạn vô hại đã rất cao và phân tán. Quy tắc "trung bình + 6,27 độ lệch chuẩn" khi đó cho ngưỡng 37,7–42,4, cao hơn
mọi điểm đo được. Quy tắc Gumbel hợp với hàng nghìn khối normal của một workload, không hợp với vài trăm phiên ngắn.

**Phân bố điểm (thăm dò, không dùng cho quyết định).** Cực đại của từng đoạn dưới mô hình phiên đã học tool và binary vô hại của
các fold khác:

| Đoạn | p5 | Trung vị | p95 | Lớn nhất |
|---|---|---|---|---|
| Binary vô hại (chương trình đã học) | 0,15 | 0,96 | 5,49 | 7,47 |
| Lệnh quản trị (tool đã biết) | 3,64 | 11,09 | 21,25 | 23,81 |
| Tấn công, tập chính | 9,49 | 17,31 | 28,14 | 28,50 |

- **Tấn công so với binary vô hại:** AUC 1,00; cả 314/314 tấn công tập chính cao hơn lần chạy binary vô hại cao nhất, ở cả 5 kịch bản.
  Một chương trình đã học thì im lặng, và cùng chương trình đó làm thêm thao tác tấn công thì tách ra hoàn toàn.
- **Tấn công so với lệnh quản trị:** AUC 0,73. Lệnh quản trị vẫn cho điểm cao dù "đã biết", vì mỗi lệnh chỉ có 1–2 lần chạy trên mỗi
  image và mỗi lần chạy sinh gram hơi khác nhau. Đặt ngưỡng ở p99 của các đoạn vô hại thì chỉ còn 105/314 tấn công vượt ngưỡng.
- Khi mô hình chỉ học tool (chưa học binary vô hại), binary vô hại và tấn công gần như trùng nhau (trung vị 15,1 và 17,4): chương trình
  chưa thấy thì lạ như nhau, dù vô hại hay không.

**Cách hiểu.** Có ba lớp khác nhau trong "process vô hại mới":

1. **Mô hình workload báo trên phiên:** thẻ dòng dõi khép được (dòng native 0 lần báo).
2. **Chương trình đã học trong dòng session:** tách tốt khỏi tấn công dùng chính chương trình đó.
3. **Tool đa dạng với ít dữ liệu:** chưa tách được bằng một ngưỡng chung. Cần nhiều phiên hơn cho mỗi (image, tool), hoặc exec probe làm
   dữ liệu normal của dòng session, hoặc rule theo danh tính và drift (phần E). Chưa có số đo cho các cách này.

### 5.3 Thẻ dòng dõi trong kernel (đã viết và đã proof 13/11, chỉ là telemetry)

Amendment 2 ghi rõ tiêu chí của amendment 1 không đạt và đăng ký một bước hẹp hơn: thẻ dòng dõi **chỉ để ghi thêm**. Worker vẫn chấm
cả cửa sổ bằng mô hình `lidds-ml-v5` như cũ, nên lượt live sau so sánh được với lượt v5; phần đếm của dòng session được ghi kèm để đo
dòng native bằng thẻ thật thay cho proxy.

**Proof** (`validation-evidence/results-20261113/lineage-probe/`, build từ working tree trên k8s-worker1, kernel 6.8.0-138):

- Proof token cũ vẫn đạt: 411.052 token bằng đúng 411.052 syscall của cgroup, đường seccomp, các token mẫu, 0 lần chèn thất bại.
- Proof dòng dõi trên một pod thật (`scripts/lineage_probe_proof.py`, vào container bằng `crictl exec`, cùng đường với `kubectl exec`
  và exec probe), cả 8 kiểm tra đạt:

| Pha | Cửa sổ | Sự kiện native | Sự kiện session |
|---|---|---|---|
| A, chỉ vòng lặp của container (`cat`, `sleep` là con của pid 1) | 5 | 1.157 | 0 |
| B, exec `ls /; cat /etc/hostname; sleep 1; ls /tmp` | 3 | 712 | 687 |
| C, nghỉ | 2 | 445 | 0 |
| D, lệnh exec đã trả về, process con chạy nền của nó còn sống | 3 | 715 | 198 |
| E, nghỉ | 2 | 445 | 0 |

Con do pid 1 fork ra vẫn là native; exec qua runtime và con của nó là session; process con sống lâu hơn cha vẫn giữ dòng session (pha D),
tức đường "rửa thẻ" đã bị chặn. Chưa đo: chi phí của hook fork, và proof trên hai worker còn lại (làm cùng bản build của lượt chạy).

Thiết kế:

- **Chỗ lưu:** `lineage` (0 native, 1 session) trong `struct pulse_task_state` (`sentinel_pulse/ebpf/pulse_counter.bpf.c`), đưa vào khoá
  gram qua trường `pad` của `struct pulse_gram_key` (`pulse_token_ids.h`). Loader (`pulse_counter_loader.c`: `drain_grams`) in `grams` là cả
  cửa sổ như trước và thêm `session_events`, `session` là phần đếm trên thread session; `sentinel_pulse/collector/token_capture.py`
  kiểm rằng phần session là tập con của cửa sổ rồi ghi vào `tokens.jsonl`.
- **Gán thẻ khi thấy một thread lần đầu** (`pulse_tokens.bpf.h`: `pulse_tok_lineage`, gọi ở đường tạo state của `pulse_record_call`, không
  nằm trên đường nóng):
  - thread không phải leader: lấy thẻ của leader;
  - process có cha ở cùng cgroup: thừa hưởng thẻ của cha;
  - process có cha ở ngoài cgroup: nếu pid trong pid namespace của nó là 1 thì là entrypoint của container (native), nếu không thì là
    runtime exec (session). Đọc `task->thread_pid->numbers[level].nr` bằng CO-RE.
- **Vì sao phân biệt được:** `runc exec` tạo `runc init` ở cgroup của host, được đưa vào cgroup của container rồi mới fork tiếp và exec;
  cha của nó (runc, sau đó là containerd-shim) nằm ngoài cgroup và nó vào pid namespace đã có nên pid khác 1. Entrypoint cũng đi qua
  `runc init` nhưng nhận pid 1 của namespace mới.
- **Lỗ hổng đã thấy trước: rửa thẻ qua đổi cha.** Nếu thẻ chỉ gán ở syscall đầu tiên, kẻ tấn công trong phiên có thể fork, cho cha thoát
  trước khi con gọi syscall; con được nhận lại bởi pid 1 (native) và thừa hưởng nhầm. Cách chặn: gán thẻ ngay lúc fork bằng chương
  trình `raw_tp/sched_process_fork` (`pulse_tok_fork`) chép thẻ của cha sang state của con. Chi phí: một lần ghi map cho mỗi fork trong container được theo dõi.
- **Giới hạn:** pod bật `shareProcessNamespace` (entrypoint không phải pid 1) sẽ bị gán nhầm; cụm hiện có 0 pod như vậy. Process của phiên
  có từ trước khi probe gắn mà đã mồ côi sẽ được coi là native.
- **Exec probe:** 47 container của namespace production có liveness, readiness hoặc startup probe kiểu exec (bảng exec của RCA lượt v5:
  `/bin/wget` 14.206 lần, `python` 9.597, `/bin/nc` 3.270, `redis-cli` 898…). Chúng là runtime exec của kubelet, nên sẽ thuộc dòng
  session, và là dữ liệu normal dồi dào cho mô hình phiên (khác hẳn 439 phiên ngắn của campaign). Dòng native cũng sạch hơn vì không còn
  lẫn probe.
- **Quy danh tính:** API server của cụm đã bật audit log (`/var/log/kubernetes/audit/audit.log`). Một phiên `kubectl exec` có bản ghi
  `pods/exec` kèm người dùng, nên cảnh báo của dòng session có thể gắn với danh tính đã xác thực; exec probe của kubelet thì không có
  bản ghi đó. Đây là đầu vào cho phần rule (phần E), không phải cho ML.

### 5.4 Hệ quả cho campaign

Nếu tách dòng dõi, mọi tấn công hiện tại của campaign (đều qua `kubectl exec`) thuộc dòng session. Muốn đo dòng native trên cụm phải có
tấn công **trong process của dịch vụ**: kịch bản LID-DS chạy live (mục 7), và fixture nằm sẵn trong cây process của workload.

## 6. D: tín hiệu tần suất cho tấn công chỉ dùng chuỗi đã thấy

**Câu hỏi.** Khi bỏ mọi sự kiện có gram hoặc token chưa thấy khỏi bản ghi tấn công, mô hình bắt 0/544. Có tín hiệu nào nhìn vào **tần
suất** của gram quen không?

**Tín hiệu** (`scripts/analysis/lidds_token_rate.py`). Với mỗi gram g, m(g) là số lần lớn nhất g xuất hiện trong một cửa sổ 0,5 s của
normal (cross-fit 5 fold như mô hình). Điểm cửa sổ = max trên các gram đã thấy của log((n(g) + 1)/(m(g) + 1)). Gram chưa thấy không vào
điểm, nên kết quả trên bản ghi tấn công cũng chính là kết quả trên mô phỏng "chỉ dùng chuỗi đã thấy". Ngưỡng theo quy tắc đã đăng ký.

| Nhánh | Development (544 tấn công) | Báo nhầm / 3.403 | CB-DS / 891 | Báo nhầm CB-DS / 1.410 |
|---|---|---|---|---|
| Mô hình (v5) | 530 | 6 | 891 | 3 |
| Riêng tín hiệu tần suất | 225 | 7 | 891 | 3 |
| Mô hình hoặc tần suất | 530 | 12 | 891 | 4 |

**Cách hiểu.** Tín hiệu tần suất bắt được 41% tấn công ngay cả khi kẻ tấn công tránh mọi chuỗi mới, điều mô hình không làm được. Nó
không thêm phát hiện nào cho mô hình (vẫn 530) và thêm 6 báo nhầm trên LID-DS, 1 trên CB-DS. Tiêu chí đăng ký (CB-DS ≤ 3) trượt đúng một
báo nhầm, nên tín hiệu không vào mô hình.

**Hướng đi tiếp (chưa đăng ký).** Hai nhánh hiện dùng chung α′, nên tổng ngân sách báo nhầm bị nhân đôi. Cách có nguyên tắc là chia α′
giữa hai nhánh như `lidds-ml-v4` từng chia (0,9 và 0,1), rồi đăng ký lại với tiêu chí ở cùng tổng ngân sách. Giá trị của nhánh này nằm ở
kẻ tấn công thích nghi, nên phải đánh giá cùng fixture pha loãng (W3 của lộ trình), không chỉ bằng mô phỏng.

## 7. Tải của probe và exploit thật trên cụm

**Tải lượt v5** (`scripts/analysis/token_load.py`, 5 segment đã khai của mỗi worker):

| Mỗi cửa sổ 0,5 s | Trung vị | p99 | Lớn nhất |
|---|---|---|---|
| Sự kiện của một container | 51 | 2.179 | 12.381 |
| 4-gram khác nhau của một container | 26 | 651 | 1.995 |
| Sự kiện của một node | 6.284 | 18.710 | 26.552 |
| 4-gram khác nhau của một node | 1.950 | 5.450 | 6.901 |

Map `pulse_grams` có 262.144 mục; cửa sổ nặng nhất dùng 2,6%. Bộ đếm của loader ở segment cuối: 0 lần chèn thất bại, 0 lần đi dentry bị
cắt, đọc map 3–7 ms. Loader khởi động lại theo từng segment 30 phút, nên file trạng thái của lượt chỉ giữ bộ đếm của segment cuối. Bài
stress tới khi map đầy vẫn phải làm.

**Kịch bản LID-DS trên cụm.** Repo github.com/LID-DS/LID-DS có thư mục `scenarios/` với đủ 15 kịch bản của dataset. Mỗi kịch bản có ba
image tự dựng (`victim`, `normal`, `exploit`, mỗi cái một Dockerfile và `build_images.sh`) và một `main.py` điều khiển: client normal gửi
request theo mẫu thời gian thật (bộ lấy mẫu "usask"), exploit chạy tại một thời điểm ngẫu nhiên. Ví dụ `CVE-2014-0160`: victim là web
server có OpenSSL lỗi, `normal/client.py` và `heartbeat.py` sinh tải, `exploit/exploit.py` gửi heartbeat độc. Node của lab ra được
Docker Hub và GitHub (đã kiểm), nên dựng được image. Cách đưa lên cụm: một namespace riêng nằm trong allow-list của probe, victim là
Deployment, client normal chạy liên tục để thu normal và fit, exploit là Job chạy ở thời điểm của campaign. Đây là thí nghiệm khép điểm
yếu "tấn công live không phải exploit thật, và luôn bắt đầu bằng exec".

## 8. Khảo sát tài liệu (13/11)

**Baseline trên LID-DS 2021.**

- Tác giả dataset chỉ công bố STIDE trên đủ 15 kịch bản (Extended Abstract CRITIS 2022; Dataset Report, Springer 2023). Bản 2021 khó hơn
  bản 2019 với cùng thuật toán. Chương Springer cũng lưu ý kết quả giữa các bài khó so vì định nghĩa phát hiện và báo nhầm khác nhau.
- Electronics 15(9):1856 (2026): TextRank + mô hình học sâu, chỉ 3 kịch bản, tự ghi chưa kiểm trên đủ bộ.
- arXiv 2606.22581 (2026), "From CVE to CWE": 6 kịch bản, Isolation Forest và One-Class SVM theo kịch bản chỉ bắt được ít cửa sổ exploit
  nếu ngưỡng không được chỉnh bằng nhãn. Liên quan trực tiếp: ngưỡng không nhãn của ta đạt 97,40% trên đủ 15 kịch bản.
- Hệ quả: không có bảng số nào để chép; phải tự chạy baseline với cùng split, cùng định nghĩa, cùng quy tắc ngưỡng.

**Bản baseline chạy dở 02/11** (`validation-evidence/results-20261102/dl-baseline-partial/`, tính trên mọi bản ghi test, chưa chia
development/official): CHIDS (El Khairi 2022) mạnh ở nhiều kịch bản nhưng báo nhầm lớn ở vài chỗ (CVE-2020-13942 748/756, EPS_CWE-434
497/759) và 0/120 ở Heartbleed; MLP của thư viện LID-DS 0/120 ở Heartbleed, 0/122 ở CVE-2018-3760, 0/120 ở CVE-2019-5418; LSTM của thư
viện vượt trần 8 giờ CPU ở ba kịch bản. Còn thiếu: MLP và LSTM ở 5 kịch bản, CHIDS ở CVE-2017-7529, CB-DS.

**Process vô hại và `kubectl exec`.**

- Không tìm thấy bài học thuật nào tách phiên exec vô hại khỏi tấn công bằng mô hình. Công cụ thực tế dùng luật kèm ngoại lệ: Falco có
  luật shell trong container và phải miễn trừ entrypoint `sh -c`; luật của Elastic và Splunk cho `docker exec`/`kubectl exec` khuyên thêm
  ngoại lệ theo công cụ và người dùng.
- ReplicaWatcher (NDSS 2024) không học mà so các replica với nhau: precision 91,08%, recall 98,35%; không dùng được khi workload chỉ còn
  một replica. Một bằng sáng chế Mỹ (11811804) dùng dòng dõi process làm đặc trưng và cũng so replica.
- Hệ quả: tách dòng dõi ngay trong kernel rồi dùng mô hình riêng cho từng dòng là hướng chưa thấy ai công bố.

**Né tránh.**

- Wagner và Soto (CCS 2002): chèn syscall vô hại để nguỵ trang. Kruegel et al. (TISSEC 2006): đưa tham số syscall vào mô hình làm việc
  né khó hơn, đúng với việc token của ta mang cỡ, mã lỗi, thư mục. Tấn công bắt chước trên các hệ provenance đạt 100% (NDSS 2023).
- Hệ quả: bài báo cần một thí nghiệm né có chủ đích, chia theo mức hiểu biết của kẻ tấn công, đo cả tỉ lệ đạt mục tiêu của tấn công.

## 9. Việc tiếp theo, theo thứ tự

1. Dòng dõi (mục 5): thẻ trong kernel đã có và đã proof. Còn lại: đưa vào bản build của lượt live sau, đo chi phí hook fork, và cách xử
   lý dòng session phù hợp với dữ liệu ít.
2. Baseline cùng protocol (mục 8), chạy trên `.234`, không cần cụm.
3. Dựng kịch bản LID-DS trên cụm (mục 7).
4. Một lượt live gộp các mục trên; rồi rule, rồi LID-DS 2019.

## 10. Nguồn

- Grimmer et al., Extended Abstract: LID-DS 2021, CRITIS 2022: https://dbs.uni-leipzig.de/file/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf
- Grimmer et al., Dataset Report: LID-DS 2021, Springer 2023: https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf
- From CVE to CWE: Syscall-Based HIDS Generalisation, arXiv 2606.22581: https://arxiv.org/abs/2606.22581
- TextRank-based system call preprocessing and deep learning models, Electronics 2026: https://doi.org/10.3390/electronics15091856
- ReplicaWatcher, NDSS 2024: https://www.ndss-symposium.org/ndss-paper/replicawatcher-training-less-anomaly-detection-in-containerized-microservices
- US patent 11811804, process anomalies in container systems: https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11811804
- Wagner, Soto, Mimicry attacks on host-based intrusion detection systems, CCS 2002: https://www.cs.purdue.edu/homes/ninghui/readings/AccessControl/wagner_soto_ccs02.pdf
- Kruegel et al., Anomalous system call detection, TISSEC 2006: https://www.auto.tuwien.ac.at/~chris/research/doc/tissec06_syscall.pdf
- Mimicry attacks against provenance graph host intrusion detection systems (NDSS 2023): https://par.nsf.gov/servlets/purl/10412012
- Elastic, container management utility run inside a container: https://detection.fyi/elastic/detection-rules/integrations/cloud_defend/execution_container_management_binary_launched_inside_a_container
- LID-DS, mã nguồn kịch bản: https://github.com/LID-DS/LID-DS
