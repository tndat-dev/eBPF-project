# Dựng cây RCA sau alert — thuật ngữ, triển khai và tiến độ

Cập nhật bằng SSH **15:19 ngày 15/10/2026, UTC+7**. Nhánh RCA chạy độc lập
với [Pulse ML](SENTINEL_PULSE_STATUS.md) và [thí nghiệm feature/syscall](SYSCALL_FEATURE_EXPERIMENT_STATUS.md).
Đây là một trong ba báo cáo tiến độ hiện hành, không thêm nhật ký checkpoint.

## 1. Mục tiêu và trạng thái hiện hành

Ba nhánh bổ trợ theo chuỗi nghiên cứu: thí nghiệm syscall/feature cung cấp
bằng chứng cho lần chọn feature của Pulse kế tiếp; Pulse hiện phát
`candidate_alert_preview`; RCA nhận preview đó và ghép context để điều tra.
Kết quả thí nghiệm syscall không tự đổi candidate đang freeze. Pulse hiện chưa
phát operational alert, nên các case live hiện được kích hoạt từ preview.

| Chỉ số live tại 15:12 UTC+7 | Giá trị |
|---|---:|
| RCA service | `pulse-rca-context.service`, PID 262736, NRestarts=0 |
| Active run/output | `parallel-20261015-r3-fastcase`; R3 cũ được giữ riêng |
| Deployed source | `/home/dat/eBPF-project-current`, commit `90a54ec`; dùng policy connect có sẵn |
| Config SHA-256 | `968b5cd8ed9541ea321ceddb40924ebc9202a802805748ba51c537806888e9f9` |
| Case fastcase đã xuất | 103; 41 chưa có connect context |
| Preview quan sát / gom cooldown | 3.982 / 3.879 |
| Preview→subscriber p50 / p95 | 7,73 / 15,54 giây (103 case) |
| Subscriber nhận preview→ghi case p50 / p95 | 2,06 / 2,11 giây (103 case) |
| Preview phát→ghi case p50 / p95 | 9,79 / 17,61 giây (103 case) |
| Connect event đã nhận | 25.424: worker1 13.626; worker4 11.798; worker3 0 |

R3 cũ đo preview→case p50/p95 15,00/22,63 giây trên 495 case. Fastcase mới
đặt `after_seconds=0`, dùng grace 2 giây và giữ nguyên policy connect sẵn có;
không cài hook mới. Trong 103 case, subscriber→case là 2,06/2,11 giây, nhưng
preview→subscriber còn 7,73/15,54 giây. Do đó preview→case tổng p50/p95 là
9,79/17,61 giây trong mẫu 103 case; đây là số liệu mô tả, **không phải gate
đạt/trượt của RCA**. RCA không bị yêu cầu phải đáp ứng latency thấp để được
coi là hoàn thiện. 41/103 case thiếu connect context; stream worker3
chưa có normalized event. `timedatectl` trên master và ba worker báo
`NTPSynchronized=yes`; `chronyc` không có nên chưa biết offset chính xác.

RCA expanded multi-event đã qua pod validation cô lập nhưng chưa bật policy
mở rộng trên production trong lúc R4 normal holdout còn chạy đến **12:38 ngày
16/10/2026 UTC+7**. Fastcase live hiện chỉ ghi connect evidence, chưa có
process/file/credential/namespace/mount/ptrace coverage mở rộng.

Trong validation, hai `TracingPolicyNamespaced` và pod thử nghiệm đã ở
worker1 từ **07:36:34Z đến 08:09:19Z**. Hash evidence C3 đã đối chiếu với
bản lưu NFS; namespace thử nghiệm đã được gỡ. Khoảng can thiệp được ghi trong
`INSTRUMENTATION_INTERVALS.jsonl` và
[receipt holdout](validation-evidence/rca-runtime-validation-20261015-c3/HOLDOUT_INSTRUMENTATION_INTERVAL.json).
Holdout không bị dừng; phần exposure worker1 giao interval phải được báo riêng
và sensitivity-check, không coi là normal.

### Vì sao R3 đợi hậu ngữ cảnh, và RCA đầu tiên có cần đợi không?

R3 cấu hình `after_seconds=5`; `emit_cases()` còn đợi thêm 2 giây trước khi
đóng case. Khoảng này chỉ gom sự kiện xảy ra **sau** preview và cho stream thời
gian chuyển event tới subscriber. Nó không cần thiết để biết workload: preview
đã mang namespace/pod/container. Nhưng identity của pod chỉ trả lời “tín hiệu
đến từ đâu”, không chỉ ra process/syscall nào tạo tín hiệu hay process đó đã
làm gì. RCA cần ghép alert với event buffer theo pod/container và thời gian.
Mốc sớm nhất là 5+2=7 giây tính từ lúc
subscriber đọc preview, không phải từ lúc kernel phát hiện; backlog khiến mẫu
495 case có p50 15,00 giây và p95 22,63 giây.

Fastcase live đổi RCA đầu tiên thành snapshot không hậu ngữ cảnh: ghép ring
buffer trước alert với event đã nhận đến `window_end`. `after_seconds=0`; code
đợi grace 2 giây để drain event đang trên stream, không phải cửa sổ post-context.
Số đo cho thấy subscriber lag là nút thắt lớn hơn phần dựng case. Nếu cần sự kiện xảy ra sau alert, chúng
phải tạo một bản enrichment/update riêng, không trì hoãn RCA đầu tiên; cơ chế
enrichment đó chưa được triển khai. Pulse không cần đợi RCA mới phát hiện.

## 2. Mục tiêu và những gì thực sự đã triển khai

Sau tín hiệu Pulse, thu thập bằng chứng để trả lời: process nào đang hoạt động,
parent là ai, process nào gọi connect, thử kết nối tới đâu và đích K8s nào?

Hiện Pulse chưa phát operational alert. Subscriber nhận
**candidate_alert_preview** đã khớp model/policy hash; không đổi tên preview
thành alert production. Output hiện là **cây/graph bằng chứng điều tra**,
chưa phải thuật toán chứng minh root cause nhân quả, không tự xử lý pod.

| Mục | Trạng thái xác minh |
|---|---|
| VM chạy subscriber | 10.1.16.234 — k8s-master.local |
| Unit | pulse-rca-context.service |
| systemd | active/running, enabled; MainPID 262736, NRestarts=0 |
| Case trong run fastcase | 103 case đã xuất; 41 case thiếu connect context |
| Context ring đang giữ | 8.796 normalized event tại snapshot |
| Stream được mở | Ba sensor trên worker1, worker4, worker3 |
| Stream có connect event đã nhận ở snapshot | worker1 13.626; worker4 11.798; worker3 chưa có normalized event |
| Trigger | candidate_alert_preview, không phải alert production |
| Tự thay model/enforce/cách ly | Không |

Mở stream không chứng minh mọi workload đều có event. Pod ngoài selector,
khoảng thiếu telemetry hoặc không phát sinh connect đều có thể làm thiếu
context; không tự suy ra không có kết nối hay không có anomaly.

Worker3 hiện chỉ có frontend đang Running và thuộc selector của policy;
Kafka/PostgreSQL/RabbitMQ/Redis/waypoint trên node này nằm ngoài selector.
Các pod service tên cũ có `ready=false` trên worker3 là phase `Succeeded`,
không phải microservice đang Running nhưng mất readiness. Sensor và policy
connect trên node này đã được kiểm tra enabled; số normalized event vẫn bằng
0 nên coverage connect của worker3 chưa được xác nhận bằng event.

## 3. Thuật ngữ cần hiểu

| Thuật ngữ | Nghĩa trong nhánh này |
|---|---|
| RCA — Root Cause Analysis | Điều tra nguyên nhân gốc; khác với chỉ phát hiện điểm bất thường |
| Alert/preview | Alert đã publish phục vụ vận hành / tín hiệu ứng viên để đánh giá; hiện dùng preview |
| Evidence graph/tree | Các node và quan hệ có chứng cứ; có thể chia sẻ parent/đích nên không nhất thiết là cây thuần túy |
| Node/edge | Thực thể / quan hệ: process, container, destination; parent_of, called_connect... |
| Process lineage | Quan hệ cha–con giữa các process |
| Exec ID | Identity process gắn với lần khởi chạy; không dùng PID đơn lẻ vì PID có thể tái sử dụng |
| Pod UID/CRI ID | Identity lần tạo pod / container runtime, khác tên pod hoặc tên workload |
| Cgroup | Nhóm tài nguyên mà Pulse đếm; count anomaly là tổng container, chưa chỉ ra process gây ra |
| Socket FD | File descriptor socket trong process; không phải ID duy nhất toàn cụm |
| Connect attempt | Lần gọi connect ở entry hook; chưa có return receipt để biết thành công |
| Destination/inventory | IP/port đích / thông tin Pod, Service, EndpointSlice từ Kubernetes API |
| Identity/time join | Ghép cùng node, Pod UID, container và khoảng thời gian, không chỉ trùng PID/IP |
| Pre/post context | RCA đầu tiên dùng ring buffer trước preview và event đến `window_end`; post-context chỉ dành cho enrichment riêng, hiện chưa triển khai |
| Subscriber | Consumer riêng nhận event/decision; không nằm trong bước tính score |
| JSONL | Mỗi dòng là một JSON; chỉ xử lý dòng hoàn chỉnh để tránh đọc partial write |
| Cursor/checkpoint | Vị trí đọc / trạng thái đã lưu để resume sau restart |
| NFS revalidation | Mở lại file trước khi kiểm tra độ dài để cập nhật trạng thái append từ writer; cached stat có thể chưa thấy dữ liệu mới |
| SQLite WAL | Journal local giúp commit context/case/cursor và phục hồi process |
| Ring buffer/retention | Context gần hiện tại có trần / quy tắc giữ và hết hạn output |
| Cooldown/grouping | Gom nhiều preview cùng identity thành một case, không xóa decision gốc |
| Coverage/unknown | Phạm vi đã quan sát / không đủ bằng chứng; thiếu event không được mặc định là normal |
| Correlation/causality | Xuất hiện liên quan theo identity/thời gian / quan hệ gây ra; nhánh hiện tại mới chứng minh liên quan |
| Payload/L7/TLS plaintext | Nội dung tầng ứng dụng/nội dung giải mã; connect không cung cấp các dữ liệu này |
| Hash/provenance | Checksum và nguồn bằng chứng; hash không thay cho event hoặc nhãn ground truth |

## 4. Luồng và output hiện hành

```mermaid
flowchart TD
    A[Pulse decision dương: candidate preview] --> C[Join theo node + Pod UID + container + thời gian]
    B[Tetragon connect events từ ba worker] --> R[Context ring SQLite local]
    R --> C
    I[Kubernetes Pod / Service / EndpointSlice inventory] --> C
    C --> P[Container và process được quan sát]
    P --> L[Parent / child theo exec identity]
    P --> N[Connect attempt: socket FD + IP/port]
    N --> D[Resolve đích K8s nếu có bằng chứng]
    L --> O[Case JSON node/edge + Markdown]
    D --> O
    C --> U[Thiếu context / stale / ngoài coverage: ghi rõ unknown]
    U --> O
```

1. Subscribe Tetragon qua kubectl exec tới ba sensor, chỉ chuẩn hóa sys_connect
   của policy sentinel-aims-syscalls. Không thay tracing policy/collector.
2. Giữ context normalized trong SQLite local. Raw event chỉ được dùng lúc
   normalize và tính hash, không persist argv, token hoặc request payload.
3. Tail decisions của ba worker từ NFS, kiểm tra model/policy, status và identity.
   Lần đầu bắt đầu ở cuối log hiện tại, ghi byte đã bỏ qua; không giả vờ có
   lịch sử trước subscription. Sau restart dùng lại cursor, không tự seek-tail mới.
4. Gom preview theo identity với cooldown 300 giây. Chờ post-context rồi
   dựng graph bằng chứng trong khoảng window_end−30 s tới window_end+5 s.
5. Xuất một JSON đầy đủ node/edge và Markdown để đọc. Từng connect có raw
   event hash; destination có mapping K8s nếu inventory xác định được.

Không join chỉ theo PID, pod name hoặc địa chỉ IP. Nếu trigger có CRI ID thì
kiểm tra thêm CRI ID. Parent ngoài container có thể xuất hiện vì lineage
kernel; không vì thế kết luận parent là workload hoặc process tấn công.

## 5. Ví dụ thật và kiểm chứng đã làm

[Cây thật và normalized input](validation-evidence/pulse-rca-context-20261015/README.md)
của inventory-service-695bf6f445-ttlgj:

- Case ID: 87ab07911c7413268acae4f4.
- **99 connect attempt**, 10 process, 5 parent, 3 đích.
- Đích resolve được: kube-dns:53 và aims-postgres-cnpg-rw:5432;
  loopback 127.0.0.1:8000 chưa gán một Service K8s.
- Trigger có alert=false, candidate_alert_preview=true. Các kết nối này
  không được tự gắn nhãn attack hoặc nguyên nhân anomaly.
- Replay 99 normalized edge tạo lại cùng nodes/links. Raw Tetragon corpus
  không được lưu trong sample này; không khẳng định raw replay end-to-end.

Đã kiểm tra restart riêng subscriber: ledger case vẫn còn, cursor tăng,
chỉ có ba receipt initial-tail của lần start đầu. **Chưa thử reboot VM**.
Lượt sửa hiện hành đã qua 61 test liên quan trên host; 37 test RCA pass trên VM.
Snapshot triển khai trong receipt có MemoryCurrent 84,7 MiB; đó là cgroup gồm
subscriber và ba kubectl, không phải overhead A/B đã đo.

Audit phát hiện case cũ thiếu trường `policy_evaluated` trong signal được lưu,
mặc dù subscriber kiểm tra policy lúc nhận decision. Runtime hiện hành giữ
trường này cùng binding model/policy. Các case cũ giữ nguyên, không điền bù
receipt thiếu. Đã sửa reader để mở file trước khi so độ dài, tránh bỏ qua
append vì kích thước NFS còn cache. Lượt đăng ký mới dùng output riêng;
Pulse và evaluator syscall tiếp tục chạy trong thời gian cập nhật subscriber.

[Audit SSH hiện hành](validation-evidence/pulse-parallel-live-20261015/inspection.json)
kiểm tra **41/41 case không có lỗi cấu trúc/binding**; 8 có connect context,
33 chưa có, trong đó 8 nằm ngoài selector. Số này gồm giai đoạn đầu sau
subscription nên chưa đủ pre-context 30 giây cho mọi case. Audit kiểm tra
identity, model/policy, graph node/edge và evidence hash; không xác nhận nhãn
attack hay root cause. Một số case còn thiếu context dù thuộc selector.

Audit ban đầu có 41/41 case R3 qua kiểm tra cấu trúc/binding. Mẫu **lịch sử**
495 case của R3 đo preview→case p50 **15,00 giây**, p95 **22,63 giây**, p99
**22,99 giây** tại snapshot 14:51 UTC+7, khi còn chờ hậu ngữ cảnh. Mẫu
fastcase đang chạy được báo riêng ở đầu tài liệu; nó giảm phần chờ sau khi
subscriber nhận preview nhưng hiện vẫn có độ trễ subscriber lớn.

[Sample mới và input normalized](validation-evidence/pulse-parallel-live-20261015/rca-case-replay.json)
giữ case `5b7c1b37393c64bdc4687c41`: **52 connect event, 74 node, 127 edge**.
Dựng lại từ 52 normalized event cho kết quả nodes/edges và số đếm khớp nguyên
case đã xuất; `policy_evaluated` được giữ. Đây là replay từ normalized events,
chưa phải tái dựng từ raw Tetragon corpus hoặc kiểm chứng nguyên nhân tấn công.

Startup từng gặp quyền đọc config do thư mục cha root-only. Đã chuyển config
sang thư mục RCA riêng root:dat 0750/file 0640, giữ journal lỗi; không nới quyền
cấu hình khác. Không dùng NRestarts hiện tại để phủ nhận startup failure cũ.

## 6. Coverage, hiệu năng và retention

| Cấu hình | Ý nghĩa/giới hạn |
|---|---|
| Selector policy hiện tại | `aims.hust.vn/runtime-hardened=true`; không mặc nhiên có connect detail cho mọi workload |
| Context ring | 180 giây, tối đa 20.000 event; vượt trần ghi issue và bỏ context cũ nhất của riêng RCA |
| Case grouping | 300 giây/node/Pod UID/container; decision gốc Pulse vẫn nguyên |
| Cây mỗi case | Tối đa 200 connect event; truncation phải hiện rõ |
| Query guard | Tối đa 10.001 event, có cờ khi chạm cap |
| Case retention | Chỉ giữ 500 case JSON/Markdown gần nhất của subscriber; có counter hết hạn |
| CPU/RAM dịch vụ R3 | Quota 1 core, MemoryMax 512 MiB; MemoryCurrent khoảng 129 MiB tại snapshot; chưa phải A/B overhead |
| Persistence | SQLite WAL local và case/cursor checkpoint; không gắn terminal SSH |
| Boot/retry | enabled + Restart=always; NFS mount không phải prerequisite của unit |

Case local hết retention sẽ bị xóa; sample đã giữ trong Git/evidence không bị
vòng retention này xóa. Counter STATUS có thể mất phần chưa checkpoint trong
khoảng 5 giây khi restart; ledger/cursor SQLite dùng để kiểm chứng resume.

IP mapping lấy từ inventory gần thời điểm nhận event, có tuổi inventory;
chưa có timeline đầy đủ để xử lý mọi lần IP reuse, NAT hay service-mesh mapping.
Stream reconnect được log, transport loss chưa được đo exact. Subscription
đã bắt đầu trước pre-window cũng không bảo đảm không mất event.

Reader NFS còn có thể bị hard-mount stall; đây là rủi ro của consumer RCA.
Thời gian dựng RCA không cộng vào **mốc tính preview của ML**, nhưng latency
tới khi người dùng nhận alert/cây cần đo riêng.
Không có cơ sở claim RCA hoàn tất trong 1–2 giây.

## 7. Tiến độ hoàn thiện

| Hạng mục | Trạng thái |
|---|---|
| Normalize process/parent/socket/destination không lấy payload | Đã triển khai |
| Subscriber ba sensor, join preview có model/policy binding | Đang chạy |
| Local context, durable case/cursor, bounded output | Đã có; restart process đã thử |
| Cây và input evidence thật, replay normalized | Đã có |
| Pod ngoài selector hoặc context thiếu | Đã đánh dấu; coverage chưa toàn workload |
| Operational alert thật làm trigger | Chưa có vì Pulse chưa promote |
| Kết quả connect thành công/thất bại | Chưa có return/flow receipt |
| Process, file, credential, namespace, mount, ptrace trong RCA mới | Đã kiểm chứng ở pod cô lập; chưa bật production |
| Đích qua NAT/mesh và lịch sử inventory | Còn thiếu |
| Causal root-cause ranking, nhãn và benchmark độ đúng | Chưa có |
| Reboot, NFS outage, backlog và transport-loss tests | Chưa hoàn tất |
| Audit cấu trúc/binding của case live | R3 cũ: 41/41 đã audit; fastcase: 103 case, chưa audit lại đầy đủ; không đồng nghĩa causal accuracy |
| Latency tới khi cây sẵn sàng | Fastcase n=103: preview→case p50 9,79s, p95 17,61s; subscriber→case p50 2,06s, p95 2,11s |

RCA runtime candidate mới đã qua kiểm thử isolated live fixture: **34 event**
chuẩn hóa thành **58 node/75 edge**, với **24/24 checks** đạt. Receipt bao gồm
fork→child exec identity, exit status, file open/write, UID/GID/capability,
setns/unshare, mount và ptrace cùng return thành công/thất bại. Đây là kiểm thử
khả năng quan sát thủ công, không phải ML alert, blind attack hay đo causal
accuracy. Mở rộng policy trên production đang chờ normal holdout kết thúc; fastcase
connect-only đã được chuyển riêng mà không thêm hook mới.

## 8. File, service và lệnh kiểm tra

- Source: [rca_service.py](sentinel_pulse/rca_service.py),
  [rca_tree.py](sentinel_pulse/rca_tree.py), [rca_connect.py](sentinel_pulse/rca_connect.py),
  [audit_rca_cases.py](sentinel_pulse/audit_rca_cases.py).
- Runtime source: /home/dat/eBPF-project-current, code commit 61a72e9 khi deploy;
  START/SQLite binding khóa hash source và config, sửa source phải đăng ký lại.
- Config: /etc/sentinel-pulse-rca/parallel-20261015-r3.json.
- Environment file systemd đọc: /etc/sentinel-pulse/rca-context.env.
- Output hiện hành: /var/lib/sentinel-pulse-rca/parallel-20261015-r3.
  Hai output trước vẫn được giữ để đối chiếu, không sửa case cũ.
- Unit: [pulse-rca-context.service](sentinel_pulse/systemd/pulse-rca-context.service).
- Model/policy hash phải trùng candidate trong [báo cáo Pulse](SENTINEL_PULSE_STATUS.md).

    sudo systemctl show pulse-rca-context.service -p ActiveState -p SubState -p NRestarts -p UnitFileState
    python3 -m json.tool /var/lib/sentinel-pulse-rca/parallel-20261015-r3/STATUS.json
    PYTHONPATH=/home/dat/eBPF-project-current python3 -m sentinel_pulse.audit_rca_cases --config /etc/sentinel-pulse-rca/parallel-20261015-r3.json

Không reset Pulse hoặc thí nghiệm syscall nếu subscriber lỗi. Cây điều tra
không tự xác nhận anomaly, false positive, attack hay root cause.
