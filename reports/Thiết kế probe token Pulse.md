# Thiết kế probe thu token cho `lidds-ml-v3`

Bản nháp 06/11/2026. Chưa có dòng code kernel nào; mọi con số dưới đây lấy từ biên nhận đã ghi trong `SENTINEL_PULSE_STATUS.md` (mục 5.32c) và `validation-evidence/results-20261105/ml-exploration/`.

## 1. Probe phải thu gì

Bảng chữ `select1f` (protocol `sentinel_pulse/protocol/lidds-ml-v3.json`) cho mỗi lần syscall trả về một token:

| Loại syscall | Token | Cần biết lúc trả về |
|---|---|---|
| 27 syscall trong danh sách errno (`stat`, `open`, `access`, `read`, `ioctl`, `connect`, `execve`, `futex`…) khi lỗi | tên + mã lỗi | giá trị trả về âm |
| `open`, `openat`, `openat2`, `creat` khi thành công | tên + chế độ mở + thư mục đầu | cờ mở và đường dẫn (tham số), kết quả thành công |
| nhóm đọc ghi (`read`, `pread`, `readv`, `recvfrom`, `recvmsg`, `write`, `writev`, `sendto`, `sendmsg`, `sendfile`…) khi thành công | tên + log2 số byte trả về | số byte trả về |
| mọi syscall khác | tên | không cần (đã có ở `sys_enter`) |

Trên development, bảng chữ này bằng bảng chữ đầy đủ (97,43%, 19/3.403 báo nhầm). Bỏ errno của `futex` thì còn 92,83% (CVE-2019-5418 11/36). Bỏ cỡ trả về, hoặc thay bằng cỡ yêu cầu lúc vào, thì mất 5–15 điểm.

## 2. Vì sao không móc mọi lần trả về

Ngày 31/10, probe exec-intent thêm `raw_tp/sys_exit` (thoát ngay khi không lỗi) cùng bộ đếm theo process ở `sys_enter`: thêm 197 ns ở `mmap` + `munmap`, vượt giới hạn 150 ns đã đăng ký; probe hiện tại đã tốn 179–271 ns mỗi syscall. Phép đo đó không tách được phần của `sys_exit` khỏi phần ở `sys_enter`. Giả thuyết (chưa đo): bật tracepoint `sys_exit` làm mọi syscall đi đường chậm khi thoát, nên tốn kể cả khi chương trình trả về ngay.

Phương án: gắn `fexit` vào đúng hàm của từng syscall cần (`__x64_sys_read`, `__x64_sys_futex`, `__x64_sys_openat`…; kernel 6.8 của worker có đủ 464 ký hiệu `__x64_sys_*` và BTF). Chỉ các syscall đó trả thêm chi phí trampoline; syscall khác không đổi.

## 3. Kiến trúc đề xuất

**Kernel:**

- **Mã token 16 bit:** 9 bit số syscall + 7 bit chi tiết (chỉ số errno, log2 cỡ, hoặc lớp open = chế độ × chỉ số thư mục). Thư mục đầu được ánh xạ qua bảng do user space nạp (các thư mục đã thấy khi học normal); thư mục chưa có trong bảng nhận một mã "khác" riêng, nên vẫn là token chưa từng thấy.
- **Trạng thái theo thread:** mở rộng `pulse_task_state` (map LRU sẵn có, khoá `pid_tgid`) thêm 3 mã token gần nhất. Không thêm lần tra map nào ở `sys_enter`.
- **Thứ tự token:** syscall có hook `fexit` phát token lúc trả về; syscall khác phát token lúc vào (như đếm hiện tại). Với syscall chặn lâu (`futex`, `read` trên socket), thứ tự có thể khác bản offline vốn phát mọi token lúc trả về. Phải kiểm bằng replay (mục 4).
- **4-gram gửi lên:** khoá u64 = 4 mã token 16 bit. Mỗi container có một map đếm (khoá: cgroup, 4-gram) theo cửa sổ 0,5 s, hai bản luân phiên để user space đọc bản cũ. Một lần cập nhật map mỗi syscall: đây là chi phí chính cần đo.

**User space (worker hiện tại):**

- Giữ bảng Witten-Bell học từ normal theo workload; với mỗi cửa sổ, tính −log P cho từng 4-gram, nhân theo số lần, lấy trung bình 10 giá trị lớn nhất. Không cần tên thread khi chấm, nên khoá gram đủ thông tin.
- Ngưỡng: trên cụm không có "bản ghi", nên đổi điểm cao nhất mỗi bản ghi validation thành điểm cao nhất mỗi khối thời gian của từng container (ví dụ 60 s), khớp Gumbel như v3, mỗi nhánh α/3. Báo nhầm khi đó tính theo khối, phải quy đổi sang gánh cảnh báo.

## 4. Kiểm offline trước khi viết code kernel

1. **Replay ngữ nghĩa probe trên LID-DS** (development): mã 16 bit, bảng thư mục, phát token lúc vào cho syscall không có hook; so với `select1f` trên cùng bản ghi. Chấp nhận nếu recall và báo nhầm ở α 0,0005 không kém quá 1 bản ghi mỗi kịch bản.
2. **Ngưỡng theo khối thời gian** trên bảng cửa sổ của các lượt live cũ (nhánh cây và support, vì token chưa có trên cụm): báo nhầm theo khối có khớp mức thiết kế không, và gánh cảnh báo ra sao.

## 5. Đo overhead

Theo cách đo 31/10 (`overhead_ab.sh`, benchmark syscall tĩnh, xoay vòng điều kiện, 5 vòng):

- A: probe hiện tại;
- B: + `fexit` của nhóm đọc ghi, open và 26 syscall errno, không `futex`;
- C: B + `futex`;
- D: C + map 4-gram.

Ghi thêm độ trễ request của ứng dụng thật (`app-overhead-v1`).

**Quyết định của chủ đồ án (06/11): nới giới hạn.** Probe dùng `select1f` (có `futex`) kể cả khi vượt 150 ns mỗi syscall; không đổi sang `select1`. Overhead vẫn được đo và báo đầy đủ cho từng điều kiện A–D, kể cả độ trễ request của ứng dụng thật, nhưng không còn là điều kiện đạt/không đạt.

## 6. Rủi ro đã biết

- `futex` là syscall rất thường gặp; hook trả về của nó có thể chiếm phần lớn chi phí.
- Đọc đường dẫn ở `fexit` của open cần đọc bộ nhớ user; với đường dẫn dài chỉ đọc tới thư mục đầu.
- Map LRU theo thread có thể đuổi thread ít hoạt động; mất lịch sử thì 3 token đầu sau đó có ngữ cảnh ngắn hơn.
- Bảng errno và độ phân giải cỡ được chọn trên development có nhãn tấn công; bằng chứng độc lập vẫn là lượt live và LID-DS 2019.
