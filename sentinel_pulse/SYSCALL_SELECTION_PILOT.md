# Pilot thu histogram syscall-ID chính xác

## Mục tiêu và ranh giới

Pilot này tạo **normal-selection data** có số lần gọi chính xác theo syscall ID và cgroup. Nó bổ sung bằng chứng tần suất để quyết định kênh syscall nào đáng giữ; nó **không** chứng minh khả năng phát hiện attack, không thay thế blind evaluation, không sửa model đang đóng băng và không thay collector sản xuất.

Probe riêng dùng `raw_tp/sys_enter`, chỉ xử lý cgroup trong allow-list `/run/sentinel-pulse/allowed-cgroups`, giới hạn ID `[0, 1023]`, map tối đa 65.536 cặp `(cgroup_id, syscall_id)`, snapshot mặc định 1 giây. Mỗi record có delta count giữa hai lần đọc cumulative và record integrity chứa map cardinality/drop counter. Cgroup identity được join bằng metadata resolver tại cùng node; không ghép chỉ bằng pod name.

`sys_enter` ghi nhận syscall entry nhìn thấy được, không chứng minh syscall thành công. ABI hiện tại phải được khóa là native x86-64; không gộp compat/x32 hoặc architecture khác vào cùng mapping. Syscall bị chặn trước tracepoint không được coi là count=0 evidence.

## Điều kiện trước khi attach

1. Xác nhận **không có formal normal soak, blind attack, hoặc capture evidence khác đang chạy trên node**. Không attach probe bổ sung vào một run đã đăng ký.
2. Lưu START bất biến: run ID, commit/object SHA-256, node/kernel/architecture, target allow-list và metadata SHA-256, thời gian bắt đầu/kết thúc, interval, workload/revision, traffic-orchestrator receipt và điều kiện dừng.
3. Chụp baseline tối thiểu 5 phút trước pilot: collector CPU/RSS, node CPU/memory, workload throughput và p95/p99 response time; dùng cùng công cụ/traffic ở giai đoạn sau attach.
4. Chạy pilot bounded tối đa 10 phút trên **một worker** trước. Không tự rollout sang sáu node. Giữ output raw immutable ngoài filesystem hệ điều hành; ghi lại attach/detach, map entries, dropped updates và khoảng thiếu metadata.
5. Dừng probe khi có dropped update, map gần đầy, node/workload health xấu đi đáng kể, hoặc p99/throughput lệch quá ngưỡng preregistered. Dừng probe không đồng nghĩa xóa/đánh fail soak khác.

Không được chạy pilot cho đến khi kiểm tra trạng thái soak/capture hiện hành và ghi kết quả kiểm tra vào START. Nếu không xác minh được trạng thái, chỉ build/test binary offline.

## Build và xác nhận offline

Build trên node Linux đích để dùng đúng kernel BTF/libbpf, trong thư mục tạm riêng:

```bash
install_dir=$(mktemp -d /var/tmp/pulse-syscall-histogram-build.XXXXXX)
make -C /path/to/eBPF-project/sentinel_pulse/ebpf syscall-histogram \
  HISTOGRAM_BUILD_DIR="$install_dir"
```

Target build chỉ biên dịch object/loader; nó không attach probe, không cài đè binary hiện hành, không tạo systemd service. Trước khi chạy, kiểm tra usage/đối số, SHA-256 artifacts, architecture, cgroup allow-list khác rỗng và snapshot metadata. Loader từ chối host không phải x86-64, bắt buộc duration hữu hạn (tối đa 24 giờ); pilot preregister chỉ dùng 600 giây. Guard này không tự phát hiện process compat/x32; cần loại/ghi riêng nhóm đó trước khi gộp.

## Cách diễn giải

- Kết quả pilot là **thử tính khả thi/overhead**, không phải phân tích tần suất đại diện cho AIMS.
- Tần suất selection có ý nghĩa sau khi capture độc lập qua đủ workload và traffic regime; phải ghi rõ thiếu workload/regime thay vì nội suy.
- Không chọn top-K từ test/attack. Xếp hạng chỉ từ normal development data; ablation train/calibration lại trên cùng split; final normal test và blind attack mới vẫn chưa được xem.
- Báo tần suất count/share/rate theo workload, regime, revision và thời lượng đủ điều kiện; kèm missing telemetry, map drops, CPU/RSS, throughput và p95/p99.
- Mọi alert trong normal capture được giữ lại và adjudicate sau run; không ép zero-alert gate.

Trạng thái hiện tại: code đã build thành công trên worker3 bằng kernel BTF của node, clang 18.1.3 và libbpf 1.4. Binary đã qua kiểm tra usage fail-closed; **chưa attach, chưa thu dữ liệu, chưa đo overhead và chưa có histogram kết quả**. Build SHA-256 và preflight cluster được ghi trong `../SYSCALL_FEATURE_EXPERIMENT_STATUS.md`. Chỉ chuyển sang live pilot sau khi START/metadata/traffic context được lưu và xác minh; nếu không có traffic receipt thì kết quả phải gắn `regime=unlabelled` và chỉ được dùng để kiểm tra instrumentation, không dùng chọn feature.
