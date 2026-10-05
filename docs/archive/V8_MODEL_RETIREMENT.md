# Gỡ model V8 khỏi runtime — 02/10/2026

Theo yêu cầu người dùng, hai bundle V8 đã được xóa khỏi VM `dat@10.1.16.234`
lúc **11:08:28 ICT** sau khi sao lưu và đối chiếu SHA-256 **25/25 file**.
Đây là retirement artifact, không phải xóa lịch sử nghiên cứu hoặc kết quả fail.

## Phạm vi đã dọn

| Thư mục gốc trên VM | Nội dung | Dung lượng allocated trước xóa |
|---|---|---:|
| `/home/dat/ml-service/aims-v8-derived-v8-paired-replay-20260811/models-v8-candidate` | 8 bundle theo workload + 8 LSTM weight, vocab và metadata | 12.570.624 byte |
| `/home/dat/ml-service/aims-v8-derived-v8-paired-replay-20260811/models-v8-shared-workload` | Shared bundle + LSTM weight, vocab và metadata | 2.965.504 byte |

Tổng khoảng **14,82 MiB**, không phải hàng chục GB. Không tìm thấy trained V8
weight dưới `/home/dat` và `/opt` trên năm node còn lại trong lần kiểm kê SSH
root. Trong repo host hiện tại không có trained V8 bundle; source/test/report
V8 được giữ để giải thích lịch sử, không xóa lẫn với artifact đã train.

Đã stop/disable 12 unit liên quan capture/train/replay/finalization V8:

```text
aims-v8-post-capture.timer        aims-v8-post-capture.service
aims-v8-normal-ablation.timer    aims-v8-normal-ablation.service
aims-v8-overhead.timer           aims-v8-overhead.service
aims-v8-blind-attack.timer       aims-v8-blind-attack.service
aims-v8-overhead.path            aims-v8-capture.service
aims-v8-release-finalize.path    aims-v8-release-finalize.service
```

Unit finalizer có trạng thái enablement `static`; đã dừng cùng path kích hoạt.
Không claim mọi service có chữ V8 đều bị xóa: Falco baseline collector nằm
ngoài phần model retirement này. Không xóa Tetragon policy/DaemonSet.

## Giữ nguyên

- 21 model ExtraTrees Sentinel Pulse R10-C1, policy và run operational R10-C3.
- Bundle legacy riêng `/home/dat/ml-service/models` đang được
  `sentinel-detector.service` sử dụng; không nhầm bundle này với candidate V8.
- Normal datasets, capture/blind/ablation/overhead evidence và kết quả terminal.
- Longhorn/PV/PVC, workload AIMS, loadgen và observer hạ tầng đang chạy.

Các thư mục Pulse capture/decision trên worker có dung lượng lớn nhưng **không
phải model V8**. Dọn chúng cần kiểm tra archive/checksum riêng; lần này không xóa.

## Khôi phục

Bản sao từng nằm ngoài repo ở đường dẫn sau, nhưng **đã chuyển vào Trash lúc
11:25:40 ICT ngày 02/10 theo yêu cầu dọn V8 tiếp theo**. Không còn active backup
tại đường dẫn này:

```text
/home/tndat/.local/share/ebpf-recovery/v8-model-retirement-20261002T040700Z/
  models-v8-candidate/
  models-v8-shared-workload/
```

Bản sao hiện còn recoverable tại
`/home/tndat/.local/share/Trash/files/v8-model-retirement-20261002T040700Z/`;
metadata ở file cùng tên trong `Trash/info/` xác nhận đường dẫn gốc và ngày
chuyển. Chưa empty Trash, nên không claim đã xóa vĩnh viễn hoặc đã giải phóng
dung lượng backup trên host. Khôi phục qua Trash của desktop nếu cần, rồi kiểm
tra trước khi copy về VM:

```bash
cd /home/tndat/.local/share/ebpf-recovery/v8-model-retirement-20261002T040700Z
sha256sum -c /home/tndat/Downloads/eBPF-project/validation-evidence/v8-model-retirement-20261002/MODEL_BACKUP_SHA256SUMS
```

Sau đó copy đúng hai thư mục về đường dẫn gốc trên VM nếu muốn tái lập nghiên
cứu V8. Không tự re-enable timer hoặc promote model. Các checksum/report lịch sử
tham chiếu bundle gốc chỉ verify đầy đủ sau khi khôi phục; không sửa checksum
cũ để che việc retirement.
