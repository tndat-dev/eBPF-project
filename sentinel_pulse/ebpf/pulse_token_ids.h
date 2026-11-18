// SPDX-License-Identifier: GPL-2.0
/* ===================================================================================================================
 * pulse_token_ids.h — BẢNG CHỮ TOKEN (alphabet) VÀ CÁCH MÃ HOÁ MỘT TOKEN THÀNH 32 BIT
 * -------------------------------------------------------------------------------------------------------------------
 * Dùng chung bởi kernel (pulse_tokens.bpf.h) và loader user space (pulse_counter_loader.c).
 *
 * Ý tưởng: mỗi lần một container gọi syscall, probe tạo ra ĐÚNG MỘT "token". Token không chỉ là tên syscall mà mang
 * thêm một mẩu thông tin về KẾT QUẢ của lời gọi, vì nhiều exploit giữ nguyên tập syscall và chỉ đổi dữ liệu:
 *   - lời gọi thất bại      → tên + mã lỗi errno          (vd. openat!2 = openat trả ENOENT)
 *   - đọc/ghi thành công    → tên + nhóm cỡ log2(số byte) (vd. read#12 = đọc được 4096..8191 byte)
 *   - mở file thành công    → tên + chế độ r/w + thư mục đầu tiên của đường dẫn (vd. openat:r:/etc)
 *   - còn lại               → chỉ tên syscall
 * Bảng chữ này tên là "select1f" (chọn trên dữ liệu LID-DS 2021 development); "probe1f" là cùng bảng chữ nhưng theo
 * THỨ TỰ mà probe phát ra (syscall không có trong bảng dưới phát token lúc VÀO, syscall trong bảng phát lúc TRẢ VỀ).
 *
 * Lưu ý cập nhật: câu tiếng Anh ngay dưới còn nói "fexit of __x64_sys_<name>" — đó là thiết kế cũ. Hiện tại MỌI syscall
 * trong bảng phát token qua MỘT chương trình raw_tp/sys_exit chung (xem pulse_tokens.bpf.h, lý do là chi phí ftrace).
 * =================================================================================================================== */
#ifndef PULSE_TOKEN_IDS_H
#define PULSE_TOKEN_IDS_H

/* Token alphabet select1f of protocol lidds-ml-v3 (scripts/analysis/lidds_ml_token_alphabets.py), as the probe
 * emits it (alphabet probe1f): a syscall in this table gives its token at return (fexit of __x64_sys_<name>), every
 * other syscall at entry (raw_tp/sys_enter), name only.
 *
 * Flags: ERR  = errno token on failure (SELECT_ERR plus futex);
 *        RW   = log2 returned size on success (signals.READS / signals.WRITES), min(15, floor(log2(res))), res > 0;
 *        OPEN = mode + first directory on success; where the open flags are: SI (open), DX (openat), HOW (openat2,
 *               struct open_how in user memory), CREAT (always write).
 * x86_64 numbers. sysdig's "pread"/"pwrite" are pread64/pwrite64; "recv"/"send" are not x86_64 syscalls. */
/* Cờ cho từng syscall trong bảng (một syscall có thể có nhiều cờ, OR với nhau):
 *   PULSE_TF_ERR        : khi thất bại, token mang errno.
 *   PULSE_TF_RW         : khi thành công với n>0 byte, token mang min(15, floor(log2 n)).
 *   PULSE_TF_OPEN_SI/DX : mở file — cờ mở (O_WRONLY...) nằm ở thanh ghi tham số thứ 2 (rsi, open) hay thứ 3 (rdx,
 *                         openat). Cần cờ này để biết chế độ r hay w.
 *   PULSE_TF_OPEN_HOW   : openat2 — cờ nằm trong struct open_how ở bộ nhớ user (phải đọc qua con trỏ).
 *   PULSE_TF_OPEN_CREAT : creat — luôn là ghi. */
#define PULSE_TF_ERR 1u
#define PULSE_TF_RW 2u
#define PULSE_TF_OPEN_SI 4u
#define PULSE_TF_OPEN_DX 8u
#define PULSE_TF_OPEN_HOW 16u
#define PULSE_TF_OPEN_CREAT 32u
#define PULSE_TF_OPEN (PULSE_TF_OPEN_SI | PULSE_TF_OPEN_DX | PULSE_TF_OPEN_HOW | PULSE_TF_OPEN_CREAT)

/* 39 SYSCALL "CÓ HOOK" (X-macro: X(số syscall x86_64, tên, cờ)). Đây là các syscall mà token cần GIÁ TRỊ TRẢ VỀ
 * (mã lỗi, số byte, fd vừa mở), nên token chỉ phát được khi syscall trả về. Mọi syscall khác phát token "chỉ tên" ngay
 * lúc vào. Đồ án đo được (RQ2): trên LID-DS chỉ 5 trong 39 syscall này thực sự cần (open, read, recv/recvfrom, stat,
 * write) — tập 39 là đủ nhưng rộng hơn cần thiết. Lưu ý: 4,5,6 là stat/fstat/lstat (kernel gọi là newstat...). */
#define PULSE_HOOKED_ROWS(X) \
    X(0, read, PULSE_TF_ERR | PULSE_TF_RW) \
    X(1, write, PULSE_TF_ERR | PULSE_TF_RW) \
    X(2, open, PULSE_TF_ERR | PULSE_TF_OPEN_SI) \
    X(3, close, PULSE_TF_ERR) \
    X(4, newstat, PULSE_TF_ERR) \
    X(5, newfstat, PULSE_TF_ERR) \
    X(6, newlstat, PULSE_TF_ERR) \
    X(16, ioctl, PULSE_TF_ERR) \
    X(17, pread64, PULSE_TF_RW) \
    X(18, pwrite64, PULSE_TF_RW) \
    X(19, readv, PULSE_TF_RW) \
    X(20, writev, PULSE_TF_ERR | PULSE_TF_RW) \
    X(21, access, PULSE_TF_ERR) \
    X(40, sendfile64, PULSE_TF_ERR | PULSE_TF_RW) \
    X(42, connect, PULSE_TF_ERR) \
    X(44, sendto, PULSE_TF_RW) \
    X(45, recvfrom, PULSE_TF_ERR | PULSE_TF_RW) \
    X(46, sendmsg, PULSE_TF_RW) \
    X(47, recvmsg, PULSE_TF_RW) \
    X(48, shutdown, PULSE_TF_ERR) \
    X(59, execve, PULSE_TF_ERR) \
    X(62, kill, PULSE_TF_ERR) \
    X(72, fcntl, PULSE_TF_ERR) \
    X(82, rename, PULSE_TF_ERR) \
    X(83, mkdir, PULSE_TF_ERR) \
    X(85, creat, PULSE_TF_ERR | PULSE_TF_OPEN_CREAT) \
    X(87, unlink, PULSE_TF_ERR) \
    X(202, futex, PULSE_TF_ERR) \
    X(257, openat, PULSE_TF_ERR | PULSE_TF_OPEN_DX) \
    X(262, newfstatat, PULSE_TF_ERR) \
    X(263, unlinkat, PULSE_TF_ERR) \
    X(264, renameat, PULSE_TF_ERR) \
    X(269, faccessat, PULSE_TF_ERR) \
    X(275, splice, PULSE_TF_RW) \
    X(295, preadv, PULSE_TF_RW) \
    X(296, pwritev, PULSE_TF_RW) \
    X(299, recvmmsg, PULSE_TF_RW) \
    X(307, sendmmsg, PULSE_TF_RW) \
    X(437, openat2, PULSE_TF_OPEN_HOW)

/* futex được tách riêng: nó là syscall rất "nóng" (gọi liên tục khi các thread chờ nhau), nên loader có cờ
 * futex_at_exit để bật/tắt việc hook nó lúc trả về (dùng khi đo chi phí). Bản chạy thật: bật. */
#define PULSE_FUTEX_NR 202

/* Token = 32 bits: syscall number in bits 23..31 (x86_64 numbers are < 512; larger ones are clamped to 511), detail
 * kind in bits 21..22, detail below:
 *   kind 0: name only;
 *   kind 1: errno (1..4095) in bits 0..11;
 *   kind 2: size bucket (0..15) in bits 0..3;
 *   kind 3: open: bit 20 = write mode, bits 0..19 = first directory: FNV-1a 32 of the first path component under the
 *           task's root masked to 20 bits ('/' + component when the opened file's path has more than one component),
 *           or DIR_ROOT ('/'), DIR_REL (a file not under the task's root), DIR_UNKNOWN (fd or walk failed).
 * TOK_NONE marks an empty history slot: a gram whose leading slots are TOK_NONE is the shorter gram at thread start. */
/* BỐ CỤC 32 BIT CỦA MỘT TOKEN:
 *     bit 31..23 : số syscall (9 bit, tối đa 511)
 *     bit 22..21 : loại chi tiết — 0 chỉ tên | 1 errno | 2 nhóm cỡ | 3 mở file
 *     bit 20..0  : chi tiết — errno (bit 0..11) | nhóm cỡ 0..15 (bit 0..3) | mở file: bit 20 = ghi, bit 0..19 = băm
 *                  FNV-1a của thư mục đầu (cắt còn 20 bit), hoặc 3 mã đặc biệt ROOT / REL / UNKNOWN.
 * Ví dụ: read trả 4096 byte → (0 << 23) | (2 << 21) | 12.
 * PULSE_TOK_NONE (0xFFFFFFFF) đánh dấu ô lịch sử trống: ở đầu một thread, 4-gram có các ô đầu là NONE (gram ngắn hơn). */
#define PULSE_TOK_NR_SHIFT 23
#define PULSE_TOK_NR_MAX 511u
#define PULSE_TOK_KIND_SHIFT 21
#define PULSE_TOK_KIND_ERR (1u << PULSE_TOK_KIND_SHIFT)
#define PULSE_TOK_KIND_SIZE (2u << PULSE_TOK_KIND_SHIFT)
#define PULSE_TOK_KIND_OPEN (3u << PULSE_TOK_KIND_SHIFT)
#define PULSE_TOK_OPEN_WRITE (1u << 20)
#define PULSE_TOK_DIR_MASK 0xFFFFFu
#define PULSE_TOK_DIR_REL 0xFFFFEu      /* file không nằm dưới gốc của task (vd. file giả /proc, gốc khác) */
#define PULSE_TOK_DIR_UNKNOWN 0xFFFFFu  /* không đọc được fd hoặc đi cây thư mục thất bại */
#define PULSE_TOK_FNV_BASIS 2166136261u /* hằng số khởi đầu và hệ số nhân chuẩn của băm FNV-1a 32 bit */
#define PULSE_TOK_FNV_PRIME 16777619u
#define PULSE_TOK_DIR_ROOT (PULSE_TOK_FNV_BASIS & PULSE_TOK_DIR_MASK)   /* file nằm ngay ở gốc "/" */
#define PULSE_TOK_NONE 0xFFFFFFFFu
#define PULSE_TOK_WINDOW_NS 500000000ULL   /* cửa sổ 0,5 s: mỗi gram được đếm vào cửa sổ chứa thời điểm của nó */
#define PULSE_TOK_DIR_CHARS 64             /* đọc tối đa 64 ký tự tên thư mục để băm */
#define PULSE_TOK_DIR_DEPTH 64   /* dentry levels walked up for the first directory, mount crossings included */
/* O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND (signals.WRITE_FLAGS) */
/* Có bất kỳ cờ nào trong số này → coi là mở để GHI (chữ "w" trong token), ngược lại là "r". */
#define PULSE_TOK_WRITE_FLAGS (01u | 02u | 0100u | 01000u | 02000u)

/* KHOÁ CỦA MAP ĐẾM 4-GRAM (pulse_grams). Kernel đếm số lần mỗi khoá xuất hiện:
 *   (container nào, cửa sổ 0,5 s nào, 4 token liên tiếp của cùng một thread, dòng dõi của thread).
 * Đây là lý do "mỗi sự kiện tạo đúng một 4-gram": ở mỗi syscall, gram = 3 token trước của CHÍNH thread đó + token mới.
 * Một cửa sổ 0,5 s có thể có hàng nghìn sự kiện, nhưng các gram giống nhau chỉ chiếm MỘT khoá với số đếm tăng dần. */
struct pulse_gram_key {
    __u64 cgroup_id;
    __u32 window;   /* CLOCK_MONOTONIC / 0.5 s at emission */
    __u32 tok[4];   /* oldest first; tok[3] is the token just emitted */
    __u32 pad;      /* the thread's lineage (PULSE_LINEAGE_*); 0 in builds before the lineage tag */
};

/* ml-final-study-v1 amendment 2: telemetry only. Native = the workload's own process tree; session = a process that
 * entered the container through a runtime exec (kubectl exec, an exec probe), and its descendants. */
/* THẺ DÒNG DÕI: native = cây process của chính workload (từ entrypoint pid 1); session = process vào container qua
 * runtime exec (kubectl exec, exec probe của kubelet) và mọi con cháu của nó. Hiện chỉ để đo (telemetry): đường cảnh
 * báo vẫn chấm cả cửa sổ. Lượt live v6 kiểm giả thuyết "chỉ chấm phần native thì không còn báo nhầm lệnh quản trị". */
#define PULSE_LINEAGE_NATIVE 0u
#define PULSE_LINEAGE_SESSION 1u

/* Set by the loader before load (.rodata.tokcfg), so the verifier prunes the disabled paths. Conditions of the
 * overhead A/B: exit-nofutex = B, exit = C, grams = D. */
/* Cấu hình do loader ghi vào vùng .rodata TRƯỚC khi nạp chương trình: verifier của kernel thấy giá trị hằng nên
 * cắt bỏ hẳn nhánh bị tắt (không tốn chi phí lúc chạy). Ba chế độ dùng khi đo chi phí: B (hook trả về, không futex),
 * C (hook trả về, có futex), D (đếm gram — chế độ chạy thật). */
struct pulse_tok_config {
    __u32 futex_at_exit;   /* futex is a hooked (exit) syscall; otherwise it gives its name at entry */
    __u32 count_grams;     /* update the per-window 4-gram map; otherwise tokens only move the thread history */
};

#endif
