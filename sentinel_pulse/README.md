# sentinel_pulse — bản đồ mã nguồn

README này chỉ hướng dẫn tìm code. Trạng thái thí nghiệm và số liệu nằm ở
[../docs/STATUS.md](../docs/STATUS.md).

## Luồng dữ liệu

```
eBPF đếm syscall theo container ──► collector/ ──► vector 249 số / 500 ms
                                                     │
                     detector/ (model đã đóng băng) ◄┘
                                                     │
                 pipeline/matched_worker: thu + chấm điểm trong 1 tiến trình
                                                     │
                  "cảnh báo thử" (preview) ──────────┼──► rca/: dựng đồ thị bằng chứng
                                                     │
        attack/: chạy tấn công/đối chứng để đo   ◄───┘
        syscall_study/: thí nghiệm chọn syscall (chạy offline, tách biệt)
```

## Các package

| Package | Làm gì | File chính |
|---|---|---|
| [collector/](collector/) | Ánh xạ pod → cgroup, đọc counter eBPF, tạo vector đặc trưng | `cgroup_resolver.py`, `capture.py`, `extended_capture.py`, `features.py`, `telemetry_recovery.py` |
| [detector/](detector/) | Model ExtraTrees + nhánh "vùng normal" (support), chấm điểm theo lô, chính sách preview | `idle_candidate.py`, `idle_batch.py`, `candidate_policy.py`, `support_model.py`, `model.py` |
| [pipeline/](pipeline/) | Worker 500 ms chạy trên từng node, sinh unit systemd, lập kế hoạch một lượt chạy, phát tải | `matched_worker.py`, `matched_services.py`, `plan_matched_run.py`, `matched_traffic.py` |
| [attack/](attack/) | Chạy cặp tấn công/đối chứng trên pod thật, chấm TP/FP/FN/TN, đo độ trễ | `preview_campaign.py`, `preview_evaluation.py`, `cluster.py`, `tetragon_evidence.py` |
| [syscall_study/](syscall_study/) | So sánh các bộ syscall (thêm/bớt kênh) trên cùng dữ liệu, chấm holdout | `matched_study.py`, `matched_holdout.py`, `audit_matched_fits.py` |
| [rca/](rca/) | Nhận preview, ghép sự kiện Tetragon (process/file/network) thành đồ thị điều tra | `service.py`, `tree.py`, `runtime_tree.py`, `connect.py` |

File dùng chung ở gốc package: `common.py` (ghi JSON an toàn, theo dõi file
JSONL, kiểm tra source sạch), `integrity.py` (SHA-256), `encoding.py` (nén vector).

Thư mục không phải Python: `ebpf/` (chương trình kernel + loader C),
`protocol/` (giao thức/ngưỡng đã đăng ký — **được băm SHA-256, không sửa**),
`systemd/` (unit cho collector, resolver, RCA), `k8s/` (TracingPolicy Tetragon
cho RCA). Tài sản của cụm thử nghiệm (script phát tải, binary tấn công,
policy exec-provenance) nằm ở [../testbed/](../testbed/).

## Chạy test

```bash
# venv có numpy/scikit-learn đúng phiên bản trong requirements-lock.txt
~/.venvs/sentinel-pulse/bin/python -m pytest -q -p no:cacheprovider tests
```

## Lưu ý khi deploy

- Service đang chạy trên cụm dùng **bản source đã đóng băng** (snapshot trên
  NFS hoặc `/opt/sentinel-pulse`), không chạy trực tiếp từ checkout này.
- `pipeline/matched_worker.py` từ chối chấm điểm nếu các file toán học của
  scorer khác bản đóng băng. Sau đợt tái cấu trúc 18/10/2026 các file này đã
  đổi dòng import, nên lượt chạy live mới cần đóng băng lại source và kiểm tra
  điểm số trùng khớp với bản cũ trước.
- Code của các thế hệ thí nghiệm trước (v8/AIMS, lifecycle 500 ms B1–B7,
  recovery coordinator, A/B overhead…) đã gỡ khỏi nhánh này; xem tag Git
  `archive/pre-refactor-20261018`.
