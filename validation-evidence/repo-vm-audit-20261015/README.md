# Evidence của lượt rà soát repo và VM ngày 15/10/2026

Revision được review và chạy regression: `0e944eb5fafc70f9f13fc8d54dcab80e7e95a761`.
Runtime inventory khoảng 03:40 UTC; job status kiểm tra tiếp khoảng 03:48 UTC.
Các file này là snapshot, không phải cam kết trạng thái sẽ giữ nguyên.

| File | Nội dung/nguồn |
|---|---|
| `runtime-inventory.json.gz` | SSH read-only cả .233–.239: toàn bộ PID/PPID/comm, CPU/RSS, service/timer, nguồn project, filesystem, PSI, NTP, VMware balloon/swap, Git trạng thái |
| `cluster-readiness.json` | Kubernetes API đã lọc metadata/status, controller replica, Longhorn/CNPG và metrics; không lưu Pod spec/env |
| `latest-job-status.json` | Đọc STATUS của R4 và ba worker, compact summary và heartbeat age |
| `runtime-details.json` | Version Python packages, legacy detector flags; NFS exports, lsblk và df |
| `cgroup-memory.json` | memory.current/max/stat/events/pressure và cpu.stat/pressure của service live |
| `legacy-worktree-comparison.json` | SHA-256 và AST name comparison của 19 source/test dirty trong checkout VM cũ |
| `static-inventory.json` | Quét 2.078 tracked file tại revision trên; syntax/type counts và size inventory |
| `test-results.json` | Receipt observer ghi lại kết quả regression 1.258 passed và 20 subtests; hai Torch deprecation warnings |
| `reproduce_resume_binding.py` | Hai probe dùng thư mục tạm, readiness/context được mock để kiểm tra guard; không train hay thay live model |
| `resume-probes.json` | Output hai probe, kèm source SHA-256; không phải số đo chất lượng ML |
| `SHA256SUMS` | Hash của từng artifact trong thư mục này |

Tool: [audit_cluster_runtime.py](../../scripts/audit_cluster_runtime.py).
SSH dùng known-hosts verification và credential qua biến môi trường. Inventory
không xuất full argv/environ, password hoặc token. `ps` CPU là trung bình theo
tuổi process; `cpu_5s` và `top_cpu_5s` mới là mẫu CPU theo interval.

Các `memory.events max` là counter tích lũy chạm giới hạn, không phải số OOM;
phải đọc `oom/oom_kill` và PSI riêng. VMware balloon/swap giữ nguyên đơn vị
do VMware Tools xuất; không đồng nhất chúng với Linux guest swap.

Lệnh tái kiểm tra (không start/stop service):

```bash
export PULSE_SSH_PASSWORD='<credential>'
python3 scripts/audit_cluster_runtime.py --output /tmp/pulse-runtime-audit.json
```

Đọc inventory nén:

```bash
python3 -c 'import gzip,json; d=json.load(gzip.open("validation-evidence/repo-vm-audit-20261015/runtime-inventory.json.gz")); print(list(d["hosts"]))'
```

Các checksum xác minh file đã lưu, không phải chữ ký attestation từ hypervisor.
