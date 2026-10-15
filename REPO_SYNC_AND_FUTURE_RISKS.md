# Rà soát repo và tiến trình VM — trạng thái hiện hành

Kiểm tra ngày **15/10/2026**, snapshot hạ tầng khoảng **10:40 UTC+7**, kiểm tra
job tiếp lúc **10:48 UTC+7**. Revision được review và chạy regression:
**0e944eb5fafc70f9f13fc8d54dcab80e7e95a761**.

Phạm vi: inventory toàn bộ tracked repo; parse source/config; đọc sâu các đường
collector → feature → batch scorer → preview → evaluator, study/checkpoint,
systemd/SSH và các điểm nối legacy/Agent. SSH đủ **6 node Kubernetes và VM NFS**,
inventory **6.078 process**, gồm process container và process kiểm tra ngắn hạn.
Đây là review và diagnostic, không thay model, policy hoặc service đang chạy.
Không coi quét cú pháp và test pass là bằng chứng repo không còn lỗi.

## 1. Kết luận quan trọng

1. **Hai lỗi resume đã tái hiện trong fixture cách ly:** mất danh sách model đã
   fit khi chờ worker status; và chấp nhận index đã thay đổi rồi reuse artifact
   thuộc feature dimension cũ. Cần sửa trước khi dựa vào recovery cho lượt xác nhận.
2. **Có memory reclamation ở hypervisor:** VMware Tools báo balloon 83.788 MB
   trên .237 và 83.790 MB trên .239; hypervisor swap .239 là 20.250 MB.
   Chưa thể kết luận host ESXi thiếu RAM hay có limit VM thấp nếu chưa xem ESXi.
3. **Các job hiện hành vẫn tiến triển:** R4 đạt **249/693 model**, chưa ghi
   workload-arm thiếu coverage; ba capture/preview worker khoảng 10,1 giờ/node.
4. **Còn runtime legacy:** detector ngoài checkout Pulse đang chạy trên .234
   và .237 ở dry-run, window 10/30 s; collector nền 1 s còn chạy trên ba worker.
5. **Chất lượng phát hiện chưa được xác nhận trên blind mới:** R3/R5 đã có
   development matrix, còn thiếu matched benign-exec control, review nhãn và
   paired blind evaluation cho các arm syscall.

## 2. Hai lỗi checkpoint có bằng chứng thực nghiệm

### F01 — P1: STATUS chờ worker ghi mất completed-model ledger

Nguồn: [matched_study.py](sentinel_pulse/matched_study.py#L115),
đặc biệt đoạn ghi STATUS tại dòng 129 và đọc lại completed tại dòng 190.

Khi resume một study đang fit, chương trình vẫn vào vòng chờ worker/capture.
Nếu STATUS của một worker tạm thời chưa đọc được, nó ghi một STATUS mới chỉ
chứa trạng thái chờ. Đến khi worker phục hồi, danh sách completed cũ đã mất;
artifact trên disk còn nhưng coordinator không dùng lại qua ledger đó.

Probe dùng START/config thật của hàm, checkpoint trong thư mục tạm và mô phỏng
worker-status chưa có. Kết quả: **completed 1 → 0**,
state thành **waiting_for_clean_selection_capture**. Không tác động R4 live.

Cải thiện: tách model checkpoint khỏi health STATUS; load ledger trước khi
chờ; nếu INPUTS/INDEX đã seal và xác minh đủ thì resume offline fit không cần
phụ thuộc heartbeat của worker. Giữ completed qua mọi trạng thái waiting.

### F02 — P1: đổi INDEX/INPUTS không bị từ chối trước khi reuse model cũ

Nguồn: [matched_study.py](sentinel_pulse/matched_study.py#L188).
INDEX có input_manifest_sha256, STATUS có index_sha256, nhưng nhánh resume
không đối chiếu các giá trị cũ. Nó tính lại index_sha256 rồi reuse model
theo tag workload/arm/seed nếu hash file artifact khớp checkpoint.

Probe sửa arm từ 249 sang 253 chiều và đổi input-manifest hash trong một
fixture tạm. Admission/context được mock để chỉ kiểm tra binding, không train
ML. Coordinator vẫn ghi **completed_matched_fits**, reuse **3 artifact có
feature_dim=249**. Đây là lỗi guard trong test cách ly; chưa thấy INDEX R4 live
bị thay đổi hoặc model live sai dimension.

Cải thiện: kiểm tra chuỗi START → INPUTS → INDEX → model ledger; so old/new
digest trước resume; bind arm spec, feature_dim, seed, schema và software vào
mỗi checkpoint. Nếu integrity sai, giữ evidence và tách lượt sửa; capture/soak
khác vẫn có thể tiếp tục, không cần xóa dữ liệu hoặc chạy toàn bộ từ đầu.

Bằng chứng cho F01/F02:
[probe source](validation-evidence/repo-vm-audit-20261015/reproduce_resume_binding.py),
[probe output](validation-evidence/repo-vm-audit-20261015/resume-probes.json).
SHA source study trong probe là
836d644201a3f6da5f7d6bf147b42c0342a76ee2ec74132470b728b5a338e0fc,
khớp source binding R4 đã lưu. Hai lỗi chưa được hotpatch vào lượt R4 đang chạy.

## 3. Các điểm cần cải thiện trong runtime và thiết kế đánh giá

| ID / mức | Bằng chứng và giới hạn | Hướng cải thiện |
|---|---|---|
| F03 / P1 nghiên cứu | [preview_campaign.py:62–91](sentinel_pulse/preview_campaign.py#L62): control chỉ quan sát nền; attack mới stage/exec fixture. Chưa tách được launch/staging artifact khỏi hành vi scenario. Chưa chứng minh model đang dựa vào artifact đó | Thêm benign fixture cùng stage, exec, runtime, sleep/rate; đánh giá thêm sau giai đoạn startup; dùng cùng input cho tất cả arm |
| F04 / P2 đo latency | [matched_worker.py:156–163](sentinel_pulse/matched_worker.py#L156): preview_emitted_at được đặt trước ghi/flush file. Kernel receipt hiện là execve của fixture, chưa phải syscall bảo mật đầu tiên | Ghi các mốc kernel, feature-end, score-complete, flush/publish, consumer-received; báo từng latency và endpoint cụ thể. Số hiện tại là kernel→preview timestamp |
| F05 / P2 provenance | [preview_campaign.py:81–99](sentinel_pulse/preview_campaign.py#L81): chờ cố định 1 s sau mở tetra stream, không có subscription-ready handshake. R5 trial 15 thiếu exec receipt; chưa xác định đây có phải nguyên nhân | Có readiness/ack hoặc nguồn event journal tin cậy; giữ unknown và raw evidence, không rerun để thay miss/unknown |
| F06 / P2 availability | [matched_worker.py:116–163](sentinel_pulse/matched_worker.py#L116): thu, score và ghi/flush NFS nằm cùng loop; network/filesystem stall có thể chặn đọc telemetry và xuất preview | Local spool/WAL có budget, hàng đợi và archive worker riêng; heartbeat độc lập; đánh dấu gap/unknown rồi tiếp tục sau recovery. Chưa thử ngắt NFS trong lượt review |
| F07 / P2 reproducibility | Study START bind script/config nhưng không bind đầy đủ dependency và imported numerical modules; [idle_candidate.py](sentinel_pulse/idle_candidate.py#L28) đọc manifest software nhưng không kiểm tra version runtime. Hiện ba worker và ML venv đều khớp NumPy 2.5.2/sklearn 1.9.0 | Freeze/pin toàn bộ numerical environment và source cần thiết; kiểm tra khi load/resume. Phân biệt lock candidate với requirements-syscall-experiment của stack legacy |
| F08 / P2 partial staging | [preview_target.py:47–51](sentinel_pulse/preview_target.py#L47) ghi trực tiếp file O_EXCL; [preview_campaign.py:72](sentinel_pulse/preview_campaign.py#L72) stage trước try/finally. Nếu copy/SSH lỗi giữa chừng có thể để file cản lượt sau | Stage qua file tạm riêng, verify rồi publish; receipt/idempotent cleanup có identity/checksum. Đây là rủi ro code, chưa thấy partial fixture tồn đọng trong R5 |
| F09 / P2 performance | [model.py:182](sentinel_pulse/model.py#L182) n_jobs=-1; [matched_services.py:57](sentinel_pulse/matched_services.py#L57) study CPUQuota=200%. Có CFS throttling trên study. OMP/BLAS thread limit không thay thế tham số joblib | Benchmark n_jobs phù hợp quota và batch size. Với inference thử 1/2/-1, xác minh score/p-value/decision trước thay đổi; chưa kết luận một cấu hình chắc chắn nhanh hơn |
| F10 / P2 measurement | completed_seconds tăng theo cadence trước toàn bộ integrity/scoring admission, tại [matched_worker.py:123–144](sentinel_pulse/matched_worker.py#L123) | Báo riêng wall time, collected cadence, valid feature exposure, scored exposure, warming và unknown; không dùng completed_seconds làm số giờ normal hợp lệ |
| F11 / P2 vận hành | Hai detector legacy, ba collector 1 s, nhiều unit cũ và checkout khác revision vẫn tồn tại | Lập owner/consumer/source inventory rồi retire có chủ đích. Đóng băng thành phần chạy trước A/B overhead để không quy chi phí toàn stack cho Pulse |
| F12 / P3 maintenance | Không có .github workflow tracked; scripts/run_artifact_gates.sh tập trung Agent, không chạy Pulse suite. Có 19 file chứa StrictHostKeyChecking=no, 20 file dùng pickle.load | CI theo lock phù hợp từng contract; pin known-host cho entrypoint còn lại; bảo vệ nguồn model tin cậy. PreviewRuntime hiện dùng StrictHostKeyChecking=yes và IdleCandidateScorer đã pin manifest/artifact hash; số file pickle không phải số lỗ hổng đã chứng minh |

Các findings trên không khẳng định tất cả failure đang xảy ra trong live run.
F01/F02 có probe tái hiện; F03 là confound của thiết kế; F04/F06/F07/F08 là
đường code cần harden; F05/F09 có số đo vận hành nhưng cần chẩn đoán thêm quan hệ nhân quả.

## 4. Toàn bộ tiến trình dự án đang chạy

| VM | Tiến trình/service liên quan đang sống | Nhận xét |
|---|---|---|
| .233 — tndat | Kernel nfsd workers, nfs-server active/exited | MainPID=0 ở unit NFS không đồng nghĩa NFS đã dừng |
| .234 — master | pulse-matched-study-parallel-r4-20261015; sentinel-detector; kubelet/containerd/control-plane | R4 249/693, unknown_workload_arms=0, chưa có terminal; legacy detector dry-run, window 10 s |
| .235 — master2 | kubelet/containerd/control-plane | Không thấy Pulse study/capture active ở node này |
| .236 — master3 | kubelet/containerd/control-plane | Không thấy Pulse study/capture active ở node này |
| .237 — worker1 | matched_worker 500 ms + loader; resolver; collector 1 s + capture; sentinel-detector | Legacy detector dry-run, window 30 s |
| .238 — worker4 | matched_worker 500 ms + loader; resolver; collector 1 s + capture | Không thấy legacy detector đang sống trong snapshot |
| .239 — worker3 | matched_worker 500 ms + loader; resolver; collector 1 s + capture | Không thấy legacy detector đang sống trong snapshot |

R3 campaign và R5 RabbitMQ đã terminal; không có attack campaign mới đang inject.
Các unit active/exited của C1/C2/reference/observation là oneshot đã kết thúc,
không phải các thí nghiệm còn chạy.

Ba capture/preview worker:
- .237: **36.392 s**, khoảng **10,11 giờ**; issues=16.
- .238: **36.211 s**, khoảng **10,06 giờ**; issues=129.
- .239: **36.373 s**, khoảng **10,10 giờ**; issues=15.

Heartbeat worker tại lần kiểm tra tiếp đều dưới 5 s. Worker và R4 không restart
trong các snapshot; các episode/gap vẫn được ghi, không bị xóa hoặc khiến toàn
capture dừng. **249/693 = 35,9% chỉ là tiến độ fit model**, không phải phần trăm
hoàn thành nghiên cứu hoặc đạt production-stable.

Có **301 loaded service unit ở failed**, chủ yếu các leg/canary/lifecycle cũ.
Riêng master có 6 failed unit còn enabled; cần audit trước khi retire để tránh
khởi động nhầm sau reboot. snap.prometheus trên .235 cũng failed. Không dùng
số failed lịch sử để kết luận capture hiện hành đang hỏng, và không reset-failed
để che evidence.

## 5. Sức khỏe Kubernetes và storage

Snapshot API: **6/6 node Ready**, DiskPressure/MemoryPressure/PIDPressure đều
False; các Deployment/StatefulSet/DaemonSet đủ replica Ready.

- Toàn cụm: **239 Running, 11 Succeeded, 1 Failed**.
- Production: **67 Running đều Ready, 4 job pod Succeeded**.
- Pod Failed là monitoring-grafana-774fdc6675-hb24b ở monitoring, terminated
  ContainerStatusUnknown/exit 137; controller đã đủ replica thay thế.
- **27/27 Longhorn volume healthy**.
- CNPG aims-postgres-cnpg: **3 ready instances**, Cluster in healthy state.

NFS export chỉ cấp cho 6 IP node, có root_squash, sync. VM có disk **500G**;
LVM tách root **100G** và archive **350G**. Filesystem archive hiển thị khoảng
**344G**, còn **276 GiB**. Do đó không thể hiểu toàn bộ 500G đều là dung lượng
export. Không thay partition/LVM/mount trong lượt kiểm tra.

## 6. CPU, RAM và hypervisor

CPU là mẫu 5 giây, chuẩn hóa theo toàn bộ vCPU của từng VM. Không dùng pcpu
lifetime của ps làm mức CPU tức thời. Sáu node có **24 CPU logic, khoảng
125,9 GiB RAM guest**; NFS có **2 CPU, khoảng 3,8 GiB RAM**.

| VM | CPU busy | MemAvailable guest | Root còn trống | VMware balloon | VMware swap |
|---|---:|---:|---:|---:|---:|
| .233 NFS | 1,1% | 0,8 GiB | 86,0 GiB | 2.546 MB | 202 MB |
| .234 master | 16,9% | 113,4 GiB | 378,7 GiB | 12 MB | 1.821 MB |
| .235 master2 | 2,8% | 118,3 GiB | 534,5 GiB | 0 MB | 0 MB |
| .236 master3 | 3,1% | 117,7 GiB | 537,2 GiB | 0 MB | 0 MB |
| .237 worker1 | 32,5% | 19,3 GiB | 97,4 GiB | 83.788 MB | 4.591 MB |
| .238 worker4 | 30,2% | 96,3 GiB | 92,2 GiB | 9.188 MB | 3.360 MB |
| .239 worker3 | 8,2% | 33,6 GiB | 263,2 GiB | 83.790 MB | 20.250 MB |

Cột VMware giữ nguyên đơn vị MB do vmware-toolbox-cmd xuất. Sáu node có
Linux SwapTotal=0 nhưng VMware vẫn báo swap: đây là lớp quan sát khác với
guest swap. NTP đều synchronized.

Balloon và VMkernel swap là các cơ chế reclaim bộ nhớ. Memory limit riêng của
VM cũng có thể gây chúng ngay khi ESXi host chưa dùng hết RAM; vì vậy chưa thể
kết luận nguyên nhân là host overcommit chỉ từ snapshot guest.
Nguồn: [Broadcom — ảnh hưởng CPU/memory limits](https://knowledge.broadcom.com/external/article/326270/impact-of-virtual-machine-memory-and-cpu.html).

Cần xem memory Limit/Reservation/Shares và biểu đồ MCTLSZ/MCTLTGT,
SWCUR/SWTGT, swap-in/out, %RDY/%MLMTD trên ESXi, đối chiếu thời điểm gap/latency.
Reservation phải phù hợp tài nguyên vật lý thực tế; xem
[Broadcom — memory reservation](https://knowledge.broadcom.com/external/article?legacyId=92688).
Chưa có quyền truy cập/receipt ESXi trong lượt audit này và chưa xác minh
balloon/swap là nguyên nhân của một gap cụ thể.

### Bộ nhớ cgroup của Pulse

Worker MemoryMax=3 GiB; memory.current thường gần ngưỡng. memory.stat cho thấy
anon khoảng **185–187 MiB**, file cache khoảng **2,74–2,78 GiB**, kernel khoảng
36–63 MiB trong các sample. RSS Python khoảng 228–229 MiB ở inventory.
Không được gọi toàn bộ 3 GiB memory.current là dung lượng model ML.

memory.events có max counter tăng tích lũy (.237=20.778, .238=45.540,
.239=3.415), nhưng **oom=0 và oom_kill=0**; memory PSI avg10 bằng 0 ở lần đọc.
Đây là hoạt động reclaim/cache cần theo dõi, chưa phải bằng chứng OOM hiện tại.
R4 giới hạn 4 GiB, anon khoảng 519 MiB; có CPU throttling theo quota 2 core.

File collector 1 s hiện khoảng **0,574 / 0,585 / 0,147 GiB** trên
.237/.238/.239. capture.py append và unit nền chưa có retention/rotation rõ
trong entrypoint này. Cần budget/retention nhưng các file đó hiện không giải
thích hàng chục GiB RAM balloon hay toàn bộ disk usage của worker.

## 7. Git, dependency và regression

| Vị trí | Trạng thái đã kiểm tra |
|---|---|
| Host trước audit | Branch experiment/syscall-id-histogram-pilot, 0e944eb, sạch |
| VM /home/dat/eBPF-project-current | Cùng 0e944eb trước audit, sạch; full regression chạy ở đây |
| VM /home/dat/eBPF-project | ca682ef, main, 37 mục dirty, được giữ nguyên |
| NFS source worker | runtime-matched-7533e66/source, tách khỏi checkout đồng bộ |
| NFS source R4 / R5 | runtime-control-981aef3/source và runtime-control-24912d6/source, tiếp tục ghim riêng |

Trong 19 source/test dirty được đối chiếu ở checkout VM cũ, **9 byte-identical**
và **10 khác** bản hiện hành. Có một test-definition name không trùng; so tên
AST không chứng minh các thay đổi đã được port tương đương. Không pull/reset,
ghi đè hoặc xóa checkout cũ.

Trong lúc audit, báo cáo SENTINEL_PULSE_VA_THI_NGHIEM_SYSCALL.md có thêm chỉnh
sửa ngoài scope audit ở mục 16.4 và việc bỏ mục 20. Các thay đổi này được giữ
nguyên ngoài commit audit; đồng bộ Git không mặc nhiên gồm những sửa đổi local đó.

Môi trường thực tế: Python 3.12; NumPy **2.5.2**, sklearn **1.9.0**,
SciPy **1.18.0**, joblib **1.5.3**, pytest **9.1.1**. NumPy/sklearn/joblib trên
ba runtime worker khớp ML venv và software trong frozen candidate manifest.
requirements-syscall-experiment.txt khóa stack khác cho experiment legacy;
không được tự áp dụng lock đó cho candidate hiện tại.

Quét **2.078 tracked files**, khoảng **109,3 MiB** nội dung tracked; toàn
working tree khoảng 1,4 GiB và .git 56 MiB. **403 Python, 82 shell, 616 JSON,
35 YAML parse pass**, không bỏ JSON lớn trong lần quét. Source/helper audit mới
được kiểm tra riêng; số trên gắn với revision được review.

Full regression VM: **1.258 passed, 20 subtests passed, 2 warnings**, **67,99 s**.
Hai warning là Torch JIT deprecation ở phần legacy/Agent; không phải failure.
Các probe mới chỉ ra những nhánh resume chưa được suite hiện có bao phủ.

Chưa làm security pentest, CVE scan dependency hay formal verification; chưa
semantic-review từng dòng của mọi file legacy. Quét static trên toàn repo
không thay thế các bước đó.

## 8. Thứ tự cải thiện đề xuất

1. Sửa F01/F02 ở coordinator version mới; giữ R4/model/evidence hiện tại.
   Bổ sung regression cho outage lúc resume và đổi index/feature contract.
2. Khi R4 xong, seal input/index/model manifest, xác minh 21 key × 11 arm ×
   3 seed; chạy independent normal và fresh attack có benign-exec controls,
   tất cả arm dùng cùng input/đơn vị horizon.
3. Thêm provenance readiness, mốc publish/consumer, tách archive NFS khỏi
   đường inference; làm fault-injection/recovery có đăng ký mà vẫn giữ episode.
4. Đối chiếu ESXi memory và CPU limits trước khi đổi cấp phát VM; benchmark
   n_jobs/batch/quota và overhead A/B sau khi đã inventory các thành phần legacy.
5. Review control positives/unknown, confusion matrix cùng đơn vị, paired CI
   theo block; chọn feature theo recall và ngân sách false alerts đã đăng ký.
6. CI và dependency lock rõ từng contract; retire entrypoint/unit cũ sau audit
   owner/consumer, hợp nhất tài liệu và source deployment.

Không triển khai các đề xuất trên vào live run trong lượt review. Các model,
policy, service, PVC và raw capture hiện hành được giữ nguyên.

## 9. Bằng chứng và lệnh tái kiểm tra

Thư mục [repo-vm-audit-20261015](validation-evidence/repo-vm-audit-20261015/README.md)
có inventory đầy đủ, API readiness, static scan, kết quả tests, probe và checksum.
Full process inventory nén để giảm dung lượng Git; không xuất password,
environment đầy đủ hoặc argv có credential.

- [Runtime inventory](validation-evidence/repo-vm-audit-20261015/runtime-inventory.json.gz).
- [Kubernetes readiness](validation-evidence/repo-vm-audit-20261015/cluster-readiness.json).
- [Latest job status](validation-evidence/repo-vm-audit-20261015/latest-job-status.json).
- [Cgroup memory/CPU](validation-evidence/repo-vm-audit-20261015/cgroup-memory.json).
- [Legacy comparison](validation-evidence/repo-vm-audit-20261015/legacy-worktree-comparison.json).
- [Regression receipt](validation-evidence/repo-vm-audit-20261015/test-results.json).

Dùng scripts/audit_cluster_runtime.py với biến môi trường PULSE_SSH_PASSWORD
và --output để chụp lại inventory. Tool chỉ đọc VM, pin known-hosts và lưu dữ
liệu local; không start/stop service hoặc inject attack.
