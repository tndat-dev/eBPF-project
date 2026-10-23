# Sentinel Pulse — phát hiện hành vi bất thường của container bằng eBPF

Đồ án xây dựng hệ thống theo dõi container trên Kubernetes ở mức kernel:
- một chương trình eBPF đếm lời gọi hệ thống (syscall) của từng container;
- cứ 0,5 giây gom thành một vector 249 đặc trưng;
- một mô hình học máy, học trên dữ liệu bình thường, chấm điểm xem cửa sổ đó có "lạ" hay không;
- khi có tín hiệu, một dịch vụ riêng (RCA) ghép các sự kiện chi tiết (process, file, kết nối mạng) thành cây bằng chứng cho người điều tra.

Mục tiêu đăng ký trước: precision và recall ≥ 95%, control dương ≤ 5%, p95 độ trễ từ kernel đến cảnh báo < 2 giây (ưu tiên) hoặc ≤ 3 giây (chấp nhận). Hệ thống chạy ở chế độ **shadow**: chỉ ghi "cảnh báo thử" (preview), không tự cách ly pod. Đường cảnh báo vận hành qua Prometheus/Alertmanager/Grafana đang được thử song song (RCA mục 5.14).

## Đọc theo thứ tự nào

1. **[SENTINEL_PULSE_STATUS.md](SENTINEL_PULSE_STATUS.md), mục 1 "Tóm tắt":** kết quả mới nhất và cấu hình ML stable.
2. **Bốn báo cáo hiện hành.** Mỗi báo cáo có mục kết quả đánh số và nhật ký ở cuối:

   | Báo cáo | Nội dung | Cách đánh số |
   |---|---|---|
   | [SENTINEL_PULSE_STATUS.md](SENTINEL_PULSE_STATUS.md) | Phát hiện bằng ML: các lượt live, calibration, luật thời gian, baseline, gánh cảnh báo, overhead | `Pulse 5.x` (ví dụ 5.19 = chốt ML stable) |
   | [SYSCALL_FEATURE_EXPERIMENT_STATUS.md](SYSCALL_FEATURE_EXPERIMENT_STATUS.md) | Chọn syscall và nhóm feature, so ở cùng ngân sách cảnh báo | `syscall 5.x`, `5B` (nhóm feature), `5C` (dưới CUSUM) |
   | [RCA_RUNTIME_STATUS.md](RCA_RUNTIME_STATUS.md) | Cây bằng chứng sau cảnh báo: độ trễ, độ phủ, xếp hạng nghi phạm, ánh xạ IP, đường cảnh báo vận hành | `RCA 5.x` |
   | [RULE_INTEGRATION_STATUS.md](RULE_INTEGRATION_STATUS.md) | Phần rule (Falco, tripwire), **tách riêng** khỏi số liệu ML | `R1`–`R6` |

3. [TODO.md](TODO.md): việc đang chạy và việc tiếp theo. [RESEARCH_IDEAS.md](RESEARCH_IDEAS.md): đánh giá tổng thể, khoảng cách so với công trình liên quan, ý tưởng từ tài liệu. [references/](references/README.md): danh mục bài báo đã dùng; [references/KNOWLEDGE_SYNTHESIS.md](references/KNOWLEDGE_SYNTHESIS.md): tri thức tổng hợp từ tài liệu theo chủ đề luận văn.
4. [docs/](docs/): báo cáo và slide của từng buổi họp (bản chụp, không cập nhật). [DOCS_INDEX.md](DOCS_INDEX.md) liệt kê mọi tài liệu.

## Từ một con số trong báo cáo đến bằng chứng

Mỗi kết quả đi qua cùng một chuỗi:

1. **Báo cáo:** mục kết quả ghi số, giờ chạy, dòng "Biên nhận" (tên file) và luật chọn.
2. **Biên nhận trong repo:** `validation-evidence/results-<ngày>/…`. README của từng thư mục ghi file nào là kết quả của mục nào, script nào sinh ra, bản gốc nằm đâu trên cụm (ví dụ [results-20261022/README.md](validation-evidence/results-20261022/README.md)).
3. **Lệnh đã chạy:** `scripts/*.sh`. Mỗi job trên cụm là một script, dòng đầu ghi giao thức, đầu vào, máy chạy và cách gọi. Script gọi module trong `sentinel_pulse/` hoặc `scripts/analysis/*.py`. Code chạy là một snapshot git đóng băng, commit nằm trong tên thư mục (`runtime-<commit>-<ngày>/source`) hoặc trong biên nhận.
4. **Luật đăng ký trước:** `sentinel_pulse/protocol/*.json`. Luật được băm SHA-256 và đăng ký **trước khi có số**; báo cáo ghi giờ đăng ký và mọi bản bổ sung. Không đổi lựa chọn sau khi xem kết quả.
5. **Dữ liệu thô:** trên NFS của cụm `/mnt/sentinel-pulse-archive`, không có trong git (mục dưới).

Ví dụ cây RCA thật có hình vẽ: [validation-evidence/rca/examples-20261023/](validation-evidence/rca/examples-20261023/README.md).

## Cấu trúc repo

```
sentinel_pulse/        mã nguồn: collector, detector, pipeline, attack (campaign, replay), syscall_study,
                       rca (cây bằng chứng), ops (đường cảnh báo vận hành), protocol (luật đăng ký trước)
scripts/               *.sh: job đã chạy trên cụm (lệnh sinh ra kết quả); analysis/: phân tích trên biên nhận;
                       figures/: hình cho luận văn; ssh_lab.py, sync_cluster_checkouts.sh: tiện ích cụm
validation-evidence/   biên nhận, checksum, bảng kết quả, mẫu nhỏ (không sửa file đã niêm phong)
testbed/               tải, binary tấn công, microbenchmark, manifest K8s (Tetragon, monitoring)
tests/                 pytest
docs/                  báo cáo, slide buổi họp; figures/
references/            danh mục bài báo (PDF chỉ giữ ngoài git, xem references/README.md)
```

Bản đồ mã nguồn chi tiết: [sentinel_pulse/README.md](sentinel_pulse/README.md). Tài sản cụm thử nghiệm: [testbed/README.md](testbed/README.md).

## Những gì không nằm trong git và lý do

- **Dữ liệu thô** (`features.jsonl`, `decisions.jsonl`, score dump, bảng cửa sổ): một lượt 24 giờ chiếm vài chục GB, vượt giới hạn của GitHub. Dữ liệu nằm trên NFS, đường dẫn ghi trong biên nhận và báo cáo; `.gitignore` liệt kê các mẫu bị loại.
- **PDF bài báo:** repo công khai, nên không phát tán lại PDF có bản quyền. `references/` giữ danh mục, link, DOI và SHA-256 của bản đã tải; bản PDF nằm ở máy chủ đồ án và NFS.
- **Mật khẩu và khóa:** không bao giờ đưa vào repo. Script đọc chúng từ biến môi trường hoặc file chỉ người chạy đọc được.

## Chạy test và phân tích lại

```bash
python3 -m venv ~/.venvs/sentinel-pulse
~/.venvs/sentinel-pulse/bin/pip install -r sentinel_pulse/requirements-lock.txt pytest
~/.venvs/sentinel-pulse/bin/python -m pytest -q -p no:cacheprovider tests
```

Một số phân tích chạy lại được ngay trên biên nhận trong repo, ví dụ luật từng thành phần của nhóm feature:

```bash
F=validation-evidence/results-20261022/syscall/feature-groups-primary
python3 scripts/analysis/feature_group_verdict.py \
  --set pulse-attack-dev=$F/RESULTS-pulse-attack-dev.json,$F/BOOTSTRAP-pulse-attack-dev.json \
  --set pulse-live-recalibrated=$F/RESULTS-pulse-live-recalibrated.json,$F/BOOTSTRAP-pulse-live-recalibrated.json \
  --output /tmp/VERDICT.json
```

Các job cần dữ liệu thô (fit model, replay, lượt live) chỉ chạy được trên cụm.

## Cụm thử nghiệm

6 node Ubuntu x86-64, Kubernetes, CNI Cilium, mesh Istio:
- master `10.1.16.234` (k8s-master), `.235`, `.236`;
- worker `.237` (worker1), `.238` (worker4), `.239` (worker3).

NFS `10.1.16.233:/sentinel-pulse` mount tại `/mnt/sentinel-pulse-archive`. Monitoring là kube-prometheus-stack (Prometheus NodePort 32090, Grafana NodePort 32300); dashboard Pulse có uid `sentinel-pulse-alerts`. `scripts/ssh_lab.py` là helper SSH, đọc mật khẩu từ biến môi trường `LAB_SSH_PASSWORD`. `scripts/audit_cluster_runtime.py` kiểm kê tiến trình, service và tài nguyên trên các VM, chỉ đọc, không xuất argv hay biến môi trường. `scripts/sync_cluster_checkouts.sh` đưa checkout trên các VM về đúng `origin/main` sau mỗi lần push.

