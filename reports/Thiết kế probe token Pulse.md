# Thiết kế probe thu token cho `lidds-ml-v3`

Bản nháp 06/11/2026, cập nhật 07/11 khi đã viết probe (mục 7). Mọi con số dưới đây lấy từ biên nhận đã ghi trong `notes/STATE.md` (trước 07/11: `SENTINEL_PULSE_STATUS.md` mục 5.32c, git `8b1bc44`) và `validation-evidence/results-20261105/ml-exploration/`.

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

## 7. Bản đã viết (07/11)

Code: `sentinel_pulse/ebpf/pulse_token_ids.h` (bảng 39 syscall có hook, bố cục token), `pulse_tokens.bpf.h` (hook và map),
`pulse_counter.bpf.c` và `pulse_counter_loader.c` dưới `PULSE_TOKENS`, target `make tokens`. Phía user space:
`sentinel_pulse/collector/token_capture.py` (kiểm dòng `token_grams`, gắn workload), `sentinel_pulse/detector/token_model.py`
(mô hình đếm, bằng `TokenLM` offline tới 1e-12, `tests/test_token_model.py`), worker ghi `tokens.jsonl` mỗi segment khi
config có khoá `tokens`. Chưa chấm token trong worker.

Khác thiết kế ở mục 3:

- **Token 32 bit, không phải 16 bit.** errno tới 133 (EINPROGRESS 115, ECONNREFUSED 111 hay gặp ở `connect`), không vừa
  7 bit chi tiết. Bố cục: số syscall bit 23–31, loại chi tiết bit 21–22 (tên / errno / cỡ / open), chi tiết ở dưới. Khoá
  gram là (cgroup, cửa sổ, 4 token) = 32 byte.
- **Thư mục đầu lấy từ đường dẫn của file đã mở** (`fentry/security_file_open` + `bpf_d_path`, theo gốc của task nên là
  góc nhìn trong container), như `fd=N(<f>PATH)` mà LID-DS dùng; đọc tham số user sẽ ra "rel" cho mọi lần mở tương đối.
  Không có bảng thư mục: thư mục được băm FNV-1a 32 bit rồi giữ 20 bit (với khoảng 30 thư mục đầu, xác suất có một cặp
  trùng khoảng 0,04%). Thư mục chưa thấy khi học tự thành token chưa thấy.
- **Cửa sổ nằm trong khoá map**, không dùng hai bản luân phiên: loader thức dậy sau mỗi ranh giới 0,5 s của
  `CLOCK_MONOTONIC` 20 ms, đọc theo lô và xoá các cửa sổ đã đóng; không mất đếm ở ranh giới.
- **errno cho syscall bị seccomp chặn:** syscall bị bỏ qua không chạy nên không có `fexit`; nó phát tên lúc vào.

Kiểm chức năng trên k8s-worker1 (07/11, 1 s mỗi chế độ benchmark): token đúng như kỳ vọng (`openat:w:/tmp`, `read#12`,
`openat!2`, `openat:r:/etc`, `read` khi hết file, gram ngắn ở đầu thread), 1,97 triệu gram, không lần chèn nào thất bại.
Gắn 40 hook mất khoảng 10 s (mỗi liên kết `fexit` chờ `synchronize_rcu_tasks`), gỡ cũng vậy.

**Overhead lần 1 (07/11, `fexit` mỗi syscall, `results-20261107/token-probe-overhead/`).** Thêm so với probe hiện tại (A),
3 worker: getpid 32–39 ns, futex 277–316 ns (riêng hook futex 190–235 ns), read 4 KiB 226–349 ns, mmap + munmap không phân
biệt được với nhiễu, nhưng **open + close thêm 2,3–2,7 µs**, và process **không** được giám sát cũng chậm thêm 1,8–2,1 µs.
Chương trình BPF tự nó chỉ tốn 82–93 ns (bpf_stats). Nguyên nhân (chẩn đoán `hookcost*.jsonl`): Tetragon đã có kprobe trên
`__x64_sys_openat`, nên hàm này đi qua `arch_ftrace_ops_list_func`, duyệt mọi ftrace_ops; mỗi trampoline `fexit` là một
ops, 40 trampoline làm mọi lần mở file trên node chậm đi. Bỏ hết hook token thì chi phí về 0.

**Sửa:** mặc định `--token-exit sys_exit`: một chương trình `raw_tp/sys_exit` (tracepoint, không qua ftrace) phát token lúc
trả về, dùng số syscall mà `sys_enter` đã ghi trong `pulse_task_state` và cờ `tok_pending`; chỉ còn một ftrace_ops
(`security_file_open`). Proof cho cả hai chế độ: đúng một token mỗi syscall (403.884 và 399.788 lần gọi). Lần đo 2
(amendment 1) so hai chế độ trong cùng các vòng.
