# VM cho thực nghiệm syscall Sentinel Pulse

Cập nhật: 07/10/2026. Đây là **kế hoạch cấp VM**, chưa phải danh sách hệ điều hành đã được Pulse kiểm chứng. Soak hiện hành trên cụm Ubuntu giữ nguyên; các VM này là lab riêng, không join cụm đang soak.

## 1. Tạo những VM nào?

**Ưu tiên tạo ba VM đầu.** Khi có đủ tài nguyên, bổ sung hai VM tiếp theo để mở rộng bằng chứng về distro/kernel.

| Ưu tiên | Hostname đề xuất | OS / kiến trúc | Kernel mục tiêu | Vai trò thực nghiệm |
|---|---|---|---|---|
| 1 | `pulse-lab-ubuntu24` | Ubuntu Server 24.04 LTS, amd64 | GA 6.8, bản vá bảo mật hiện hành | Máy đối chứng cùng họ OS/kernel với cụm hiện tại, nhưng cùng cấu hình phần cứng với VM lab khác |
| 1 | `pulse-lab-rhel9` | RHEL 9.x, x86_64 | Kernel vendor 5.14, bản vá/backport hiện hành | Kiểm tra enterprise Linux, SELinux và collector trên kernel vendor |
| 1 | `pulse-lab-fedora44` | Fedora Server 44, x86_64 | Kernel stable của bản cài, ghi chính xác `uname -r` | Kiểm tra distro/toolchain và kernel mới hơn; không dùng Rawhide/beta |
| 2 | `pulse-lab-ubuntu22` | Ubuntu Server 22.04 LTS, amd64 | **GA 5.15**, không chọn HWE 6.8 | So sánh hai dòng kernel trong cùng họ Ubuntu |
| 2 | `pulse-lab-debian13` | Debian 13, amd64 | Dòng 6.12 LTS, bản vá hiện hành | Thêm distro và dòng kernel trung gian |

Ubuntu có cả GA và HWE: chỉ tên “Ubuntu 24.04/22.04” chưa đủ xác định kernel. Chọn nhánh GA theo bảng trên; sau cài phải xác nhận bằng `uname -r`. [Ubuntu kernel lifecycle](https://ubuntu.com/kernel/lifecycle).

RHEL 9 dùng dòng kernel 5.14 và yêu cầu CPU x86-64-v2 trên máy x86_64. Cần subscription/developer subscription hoặc quyền dùng bản đánh giá hợp lệ; không dùng ISO không rõ nguồn. Nếu thay bằng Rocky/AlmaLinux, ghi đúng tên distro đó trong kết quả, **không gọi là đã thử RHEL**. [Red Hat: kiến trúc RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/considerations_in_adopting_rhel_9/ref_architectures_considerations-in-adopting-rhel-9).

Fedora Server 44 có bản x86_64 chính thức; Debian 13 công bố dòng kernel 6.12 LTS. [Fedora Server download](https://fedoraproject.org/server/download/), [Debian 13 release](https://www.debian.org/News/2025/20250809).

Các lựa chọn này nhằm tạo độ đa dạng có kiểm soát, không phải danh sách bắt buộc từ một tiêu chuẩn. Ba VM đầu đủ **bắt đầu** thực nghiệm cross-distro, không tự động đủ chứng minh hỗ trợ mọi Linux. Kernel mới/cũ không bảo đảm collector chạy: phải kiểm tra khả năng thực tế trước khi thu dữ liệu.

## 2. Cấu hình mỗi VM Linux

| Thành phần | Đề xuất cho mỗi VM |
|---|---|
| CPU | 8 vCPU, cùng CPU model của hypervisor; hỗ trợ x86-64-v2 cho RHEL 9 |
| RAM | 16 GB, tránh ballooning trong lượt benchmark |
| Disk | 120 GB SSD; có thể thin provision nhưng phải theo dõi dung lượng vật lý |
| OS | Server/minimal, không cần desktop GUI |
| Network | SSH từ host quản trị; truy cập repo/registry và đồng bộ thời gian; IP riêng không trùng cụm |
| Tài khoản | `dat` có sudo; ưu tiên SSH key, không đưa password vào repo |

Đây là đề xuất cho **lab collector và workload đại diện**, không phải cam kết chạy toàn bộ stack AIMS/HA trên một VM 16 GB. Không cần cấp 32 vCPU/64 GB/600 GB như mỗi node production chỉ để thử syscall.

- Ba VM: tổng cấp 24 vCPU, 48 GB RAM, 360 GB disk ảo.
- Năm VM: tổng cấp 40 vCPU, 80 GB RAM, 600 GB disk ảo.
- Có thể chạy lần lượt từng VM nếu thiếu tài nguyên vật lý. Không giảm tài nguyên cụm đang soak để bật đồng thời cả lab; tránh CPU/RAM/storage contention khi so sánh latency.

Tạo VM Ubuntu đối chứng mới có cùng 8 vCPU/16 GB với VM RHEL/Fedora. Không so sánh trực tiếp latency của node production lớn với VM lab nhỏ rồi quy khác biệt cho OS.

## 3. Windows và ARM64

**Chưa cần tạo Windows cho vòng thực nghiệm này.** Windows không dùng Linux syscall ABI hay `raw_tp/sys_enter`; collector Pulse hiện tại không chạy nguyên trạng ở đó. Muốn hỗ trợ Windows cần track riêng: backend telemetry Windows, schema/định danh tương thích và thực nghiệm mới. eBPF for Windows cũng không bảo đảm các hook/helper đặc thù Linux dùng được trên Windows. [Microsoft eBPF for Windows: compatibility](https://github.com/microsoft/ebpf-for-windows#2-does-this-provide-app-compatibility-with-ebpf-programs-written-for-linux).

ARM64 là vòng mở rộng khác kiến trúc, không thay thế VM x86_64 ở bảng trên. Nếu cần claim ARM64, dùng VM trên host ARM thực hoặc phần cứng ARM; không dùng kết quả full-system emulation trên x86 để so sánh latency trực tiếp. Phải xây mapping syscall/schema phù hợp ABI trước, không nạp model hiện tại chỉ vì cũng là Ubuntu.

## 4. Cài xong cần giữ những điều kiện nào?

1. Cài OS từ nguồn chính thức, kiểm tra checksum ISO, cập nhật bảo mật trước lượt chạy, reboot và ghi OS/kernel/package versions. Giữ cấu hình cố định trong từng lượt; bản vá mới được ghi thành revision mới, không yêu cầu bỏ cập nhật bảo mật lâu dài.
2. Giữ SELinux enforcing trên RHEL/Fedora và AppArmor của Ubuntu; không tắt bảo vệ để làm benchmark “dễ pass”. Cấp quyền collector có kiểm soát và ghi lại cấu hình bảo mật.
3. Kiểm tra cgroup v2, BTF, raw tracepoint, quyền attach, bộ công cụ build và native x86_64 syscall ABI. Thiếu khả năng thì ghi unsupported/adaptation required, không sinh counter 0 để coi là bình thường.
4. Dùng cùng image digest, phiên bản ứng dụng, cấu hình, seed và traffic schedule trên các OS; không lấy container Ubuntu chạy trên kernel RHEL rồi coi đó là một thí nghiệm kernel Ubuntu.
5. Tách network/storage lab khỏi tài nguyên soak. Chưa cài Kubernetes/join node hoặc dùng Longhorn/NFS của production chỉ để chuẩn bị VM.

Lệnh kiểm tra ban đầu, chỉ đọc:

```bash
cat /etc/os-release
uname -r
uname -m
lscpu
free -h
df -h /
stat -fc %T /sys/fs/cgroup
test -r /sys/kernel/btf/vmlinux && echo 'BTF readable'
timedatectl status
```

Các lệnh này chỉ kiểm tra nền tảng, chưa chứng minh attach/đếm đúng hay độ chính xác ML. Sau khi tạo xong, cung cấp IP, OS và cách SSH của các VM; không cần chọn IP cụ thể trong tài liệu này.

## 5. Thực nghiệm sẽ dùng các VM ra sao?

- **Khả năng collector:** kiểm tra syscall ID theo kernel/ABI từng máy; so exact counters với chương trình có số lần gọi đã biết, báo mất dữ liệu/gap.
- **Tần suất syscall:** capture full-ID histogram độc lập trong lab để biết bên trong `other` gồm gì, tách workload và các chế độ steady/toolmix/peak/burst/recovery. Histogram đơn syscall không đủ dựng lại thứ tự adjacent transitions.
- **Chọn feature:** chọn top-K/nhóm trên phần training; calibration độc lập; ablation và importance trên tập đánh giá khác. Không loại syscall nhạy cảm chỉ vì ít xuất hiện ở normal.
- **Khả năng tổng quát ML:** báo riêng chuyển model Ubuntu đã khóa sang OS đích và model train/calibrate từ normal của OS đích. Mapping đúng không đồng nghĩa model vẫn đúng trên phân phối mới.
- **Chất lượng và tốc độ:** normal holdout/soak có adjudication, blind attack trials trong lab tách biệt, precision/recall/FPR, coverage, CI, overhead và kernel-to-alert. Không suy recall từ chỉ tần suất hoặc importance.

Thí nghiệm offline đang chạy trên host được mô tả trong [SYSCALL_FEATURE_EXPERIMENT_STATUS.md](SYSCALL_FEATURE_EXPERIMENT_STATUS.md). Nó chưa phải thực nghiệm full-ID/cross-OS trong bảng này và không thay đổi model hay soak production.
