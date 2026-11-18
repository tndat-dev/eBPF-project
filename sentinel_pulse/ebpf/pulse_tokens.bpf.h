// SPDX-License-Identifier: GPL-2.0
/* Token probe of lidds-ml-v3 (reports/Thiết kế probe token Pulse.md): per-thread select1f tokens and a per-cgroup,
 * per-0.5 s window count of token 4-grams. Included by pulse_counter.bpf.c under PULSE_TOKENS, after the maps; the
 * thread history lives in pulse_task_state (pulse_last_syscall), which sys_enter already looks up. */
/* ===================================================================================================================
 * pulse_tokens.bpf.h — PROBE TOKEN (phần kernel của mô hình ML hiện tại)
 * -------------------------------------------------------------------------------------------------------------------
 * Được #include vào pulse_counter.bpf.c khi biên dịch với -DPULSE_TOKENS. Ba việc:
 *   1) Dựng token cho mỗi syscall (xem bố cục 32 bit trong pulse_token_ids.h):
 *        - syscall không có hook: token = tên, phát ngay ở sys_enter (pulse_counter.bpf.c gọi pulse_tok_emit);
 *        - 39 syscall có hook: phát ở pulse_tok_sys_exit (raw_tp/sys_exit) với mã lỗi / nhóm cỡ / thư mục đầu.
 *   2) Đếm 4-gram theo thread: mỗi thread giữ 3 token gần nhất (pulse_task_state.tok[]); token mới + 3 token đó = một
 *      4-gram, cộng 1 vào map pulse_grams với khoá (cgroup, cửa sổ 0,5 s, 4 token, dòng dõi).
 *   3) Gắn thẻ dòng dõi native/session cho từng thread (pulse_tok_lineage lúc gặp lần đầu, pulse_tok_fork lúc fork).
 * Loader cứ 0,5 s đọc map, lấy các cửa sổ đã đóng, in JSON và xoá chúng (drain_grams trong pulse_counter_loader.c).
 * Không sự kiện đơn lẻ nào được chuyển lên user space — chỉ số đếm theo gram — nên chi phí thấp.
 * =================================================================================================================== */
#ifndef PULSE_TOKENS_BPF_H
#define PULSE_TOKENS_BPF_H

#include "pulse_token_ids.h"

/* Cấu hình mặc định; loader ghi đè trước khi nạp (xem struct pulse_tok_config). "const volatile" để verifier coi là
 * hằng số tại thời điểm nạp mà compiler không tối ưu mất. */
const volatile struct pulse_tok_config pulse_tok_config SEC(".rodata.tokcfg") = {
    .futex_at_exit = 1,
    .count_grams = 1,
};

/* 2^18 (cgroup, window, gram) entries: user space drains closed windows every 0.5 s, so about two windows live. */
/* MAP 4-GRAM: 262.144 mục = 2^18. Mỗi mục = một (cgroup, cửa sổ, 4 token, dòng dõi) khác nhau → số lần. Loader xoá cửa sổ
 * đã đóng mỗi 0,5 s nên lúc nào cũng chỉ khoảng 2 cửa sổ sống. Đo được (map-capacity-v1): map bắt đầu đầy và bỏ gram ở
 * 400.000 syscall/s mà mọi syscall là gram mới; cửa sổ thật nặng nhất của lượt v5 chỉ 6.901 gram. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, struct pulse_gram_key);
    __type(value, __u64);
} pulse_grams SEC(".maps");

/* 0: gram insert failed (map full), 1: first directory walk deeper than PULSE_TOK_DIR_DEPTH, 2: grams counted */
/* Ba bộ đếm sức khoẻ (per-CPU): [0] số lần chèn gram thất bại vì map đầy (insert_fail — phải luôn bằng 0 trong lượt
 * chạy hợp lệ), [1] số lần đi cây thư mục quá 64 bậc, [2] tổng số gram đã đếm. Loader in ra trong dòng "token_drain". */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} pulse_tok_stats SEC(".maps");


/* Tăng một bộ đếm sức khoẻ (bản per-CPU nên không cần nguyên tử). */
static __always_inline void pulse_tok_stat(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&pulse_tok_stats, &index);
    if (value)
        (*value)++;
}

/* Khi một luồng vừa mới khởi động hoặc khi lịch sử bị reset: 3 ô = NONE. Gram đầu tiên sau đó sẽ là (NONE, NONE, NONE, token) — "gram ngắn". */
static __always_inline void pulse_tok_reset(struct pulse_task_state *state)
{
    state->tok[0] = PULSE_TOK_NONE;
    state->tok[1] = PULSE_TOK_NONE;
    state->tok[2] = PULSE_TOK_NONE;
}

/* The task's pid in its own pid namespace; 0 in the host's namespace. A container's entrypoint is pid 1 there. */
/* Lấy pid của task TRONG pid namespace của nó (không phải pid nhìn từ host). Trong container, process khởi động
 * (entrypoint) có pid 1. Cách đọc: task->thread_pid->numbers[level].nr với level = độ sâu namespace của task. Phải dùng
 * bpf_core_type_size vì kích thước struct upid có thể khác giữa các kernel (CO-RE). Trả 0 nếu ở namespace của host. */
static __always_inline __u32 pulse_tok_ns_pid(struct task_struct *task)
{
    struct pid *pid = BPF_CORE_READ(task, thread_pid);
    unsigned int level = BPF_CORE_READ(pid, level);
    struct upid upid = {};
    if (!pid || level == 0) //Nếu level == 0, có nghĩa là tiến trình đang nằm ở Host (root namespace), không bị đóng gói trong container nào cả -> hàm trả về 0
        return 0;
    const struct upid *first = __builtin_preserve_access_index(&pid->numbers[0]); //Định vị dữ liệu PID trong Namespace cụ thể
    if (bpf_probe_read_kernel(&upid, sizeof(upid), (const void *)first + (level & 0xff) * bpf_core_type_size(struct upid)) < 0)
        return 0;
    return (__u32)upid.nr; //upid.nr chính là số hiệu PID thực tế mà tiến trình nhìn thấy khi nó chạy bên trong container của mình (ví dụ: PID = 1)
}
//lấy số hiệu tiến trình (PID) bên trong một Namespace

/* Lineage of a task first seen without a state (amendment 2). Children of a watched task get theirs at fork
 * (pulse_tok_fork), so this covers tasks older than the probe and tasks that moved into the cgroup: the lineage of the
 * thread-group leader; else of the parent when the parent is in this cgroup; else native when the process is pid 1 of
 * its pid namespace (the container's entrypoint) and session otherwise (a runtime exec joins an existing pid namespace
 * from a parent outside the cgroup). */
/* DÒNG DÕI CỦA MỘT THREAD GẶP LẦN ĐẦU (chưa có trạng thái). Thứ tự quyết định:
 *   1) Nếu là thread phụ của một process → lấy dòng dõi của thread chính (leader) nếu leader đã có trạng thái.
 *   2) Nếu process cha cùng container → lấy dòng dõi của cha (cha chưa có trạng thái thì coi native).
 *   3) Còn lại (cha ở NGOÀI container): là pid 1 của container → native (chính entrypoint); khác → session. Lý do: khi
 *      chạy `kubectl exec`, runtime (containerd/runc) tạo process từ BÊN NGOÀI container rồi cho nó nhập vào namespace
 *      đã có, nên cha của nó nằm ngoài cgroup và nó không phải pid 1.
 * Thread con của một thread đã theo dõi thì nhận dòng dõi ngay lúc fork (pulse_tok_fork), không qua hàm này. */
static __always_inline __u32 pulse_tok_lineage(__u64 cgroup_id)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    struct pulse_task_state *other;
    if ((__u32)pid_tgid != tgid) {                       /* pid != tgid → đây là thread phụ, không phải leader */
        __u64 leader = ((__u64)tgid << 32) | tgid;
        other = bpf_map_lookup_elem(&pulse_last_syscall, &leader);
        if (other && other->cgroup_id == cgroup_id)
            return other->lineage;
    }
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    /* id cgroup (cgroup v2) của process cha: parent->cgroups->dfl_cgrp->kn->id. */
    if (BPF_CORE_READ(parent, cgroups, dfl_cgrp, kn, id) == cgroup_id) {
        __u64 key = ((__u64)BPF_CORE_READ(parent, tgid) << 32) | (__u32)BPF_CORE_READ(parent, pid);
        other = bpf_map_lookup_elem(&pulse_last_syscall, &key);
        return other && other->cgroup_id == cgroup_id ? other->lineage : PULSE_LINEAGE_NATIVE;
    }
    return pulse_tok_ns_pid(BPF_CORE_READ(task, group_leader)) == 1 ? PULSE_LINEAGE_NATIVE : PULSE_LINEAGE_SESSION;
}

/* Token "chỉ tên": số syscall dịch lên bit 23 (loại = 0, không chi tiết). */
static __always_inline __u32 pulse_tok_plain(__u32 nr)
{
    return (nr > PULSE_TOK_NR_MAX ? PULSE_TOK_NR_MAX : nr) << PULSE_TOK_NR_SHIFT;
}

/* syscalls that give their token at return; all others give it at entry */
/* 1 nếu syscall thuộc 39 syscall có hook (phát token lúc trả về). Macro sinh ra một switch với 39 nhánh case. */
static __always_inline int pulse_tok_hooked(__u32 nr)
{
#ifndef PULSE_HOOK_SMALL
    if (nr == PULSE_FUTEX_NR)
        return pulse_tok_config.futex_at_exit;
#endif
    switch (nr) {
#define PULSE_CASE(number, name, flags) case number: return 1;
        PULSE_HOOKED_ROWS(PULSE_CASE)
#undef PULSE_CASE
    default: return 0;
    }
}

/* the gram ending in tok, then the history moves on by one */
/* PHÁT MỘT TOKEN: (1) đếm 4-gram (3 token trước + token mới) vào cửa sổ hiện tại; (2) dịch lịch sử thread đi một ô.
 * Đây là chỗ "mỗi sự kiện tạo đúng một 4-gram". Cửa sổ = thời điểm / 0,5 s (đồng hồ monotonic của kernel). */
static __always_inline void pulse_tok_emit(struct pulse_task_state *state, __u64 cgroup_id, __u64 now_ns, __u32 tok)
{
    if (pulse_tok_config.count_grams) {
        struct pulse_gram_key key = {
            .cgroup_id = cgroup_id,
            .window = (__u32)(now_ns / PULSE_TOK_WINDOW_NS),
            .tok = { state->tok[0], state->tok[1], state->tok[2], tok },
            .pad = state->lineage,
        };
        /* Gram đã có trong map → cộng 1 (nguyên tử vì nhiều CPU có thể cộng cùng khoá). Chưa có → chèn với giá trị 1.
         * Nếu chèn thất bại do CPU khác vừa chèn cùng khoá → tra lại và cộng; nếu vẫn không có → map đầy, đếm insert_fail. */
        __u64 *count = bpf_map_lookup_elem(&pulse_grams, &key);
        if (count) {
            __sync_fetch_and_add(count, 1); //// (1) Gram đã có trong map -> Tăng thêm 1
        } else {
            __u64 one = 1; //(2) Gram chưa có -> Khởi tạo giá trị bằng 1
            if (bpf_map_update_elem(&pulse_grams, &key, &one, BPF_NOEXIST) < 0) {
                count = bpf_map_lookup_elem(&pulse_grams, &key);   /* lost a race with another CPU */
                if (count)
                    __sync_fetch_and_add(count, 1); //// (3) Bị tranh chấp với CPU khác -> Tra lại và tăng thêm 1
                else
                    pulse_tok_stat(0);
            }
        }
        pulse_tok_stat(2);
    }
    /* Dịch lịch sử: bỏ token cũ nhất, thêm token mới vào cuối. */
    state->tok[0] = state->tok[1];
    state->tok[1] = state->tok[2];
    state->tok[2] = tok;
}

/* floor(log2(value)) bằng tìm kiếm nhị phân trên bit (không có vòng lặp, verifier dễ chấp nhận), chặn trên ở 15.
 * Ví dụ 4096 → 12, 5000 → 12, 1 → 0. */
static __always_inline __u32 pulse_tok_log2(__u64 value)
{
    __u32 bits = 0;
    if (value >> 32) { value >>= 32; bits += 32; }
    if (value >> 16) { value >>= 16; bits += 16; }
    if (value >> 8) { value >>= 8; bits += 8; }
    if (value >> 4) { value >>= 4; bits += 4; }
    if (value >> 2) { value >>= 2; bits += 2; }
    if (value >> 1) { bits += 1; }
    return bits > 15 ? 15 : bits;
}

/* Cờ (ERR/RW/OPEN...) của một syscall có hook, lấy từ bảng X-macro. */
static __always_inline __u32 pulse_tok_flags(__u32 nr)
{
    switch (nr) {
#define PULSE_CASE(number, name, flags) case number: return flags;
        PULSE_HOOKED_ROWS(PULSE_CASE)
#undef PULSE_CASE
    default: return 0;
    }
}

/* First directory of the file an open just returned as fd, as LID-DS takes it from sysdig's resolved fd=N(<f>PATH):
 * '/' + the first component under the task's root (inside a container, the container's root), DIR_ROOT for a file
 * directly in the root, DIR_REL for a file not under the task's root (pseudo files, another root), DIR_UNKNOWN when
 * the walk fails. The dentry chain is walked upwards, crossing mount points, without d_path: d_path is allowed only
 * in a few fentry hooks, and every fentry trampoline is one more ftrace_ops (07/11: fentry/security_file_open cost
 * about 380 ns on every open of every process of the node, monitored or not). */
/* Băm FNV-1a tên MỘT thành phần đường dẫn (vd. "etc") thành 20 bit. Hai giá trị cao nhất được dành cho mã đặc biệt
 * REL/UNKNOWN nên băm trùng chúng thì lùi xuống 2. */
static __always_inline __u32 pulse_tok_dir_hash(const unsigned char *name)
{
    char buffer[PULSE_TOK_DIR_CHARS];
    if (bpf_probe_read_kernel_str(buffer, sizeof(buffer), name) <= 0)//để sao chép chuỗi tên thư mục từ vùng nhớ kernel vào bộ đệm cục bộ (buffer)
        return PULSE_TOK_DIR_UNKNOWN;
    __u32 hash = PULSE_TOK_FNV_BASIS;
    for (int index = 0; index < PULSE_TOK_DIR_CHARS - 1; index++) {
        char c = buffer[index];
        if (c == 0) break;
        hash = (hash ^ (__u8)c) * PULSE_TOK_FNV_PRIME; //Fowler–Noll–Vo
    }
    hash &= PULSE_TOK_DIR_MASK;//ép kết quả băm nằm trong giới hạn bit cho phép (20-bit)
    return hash >= PULSE_TOK_DIR_REL ? hash - 2 : hash;   /* keep the two reserved codes */
}

/* Trạng thái của vòng đi ngược cây thư mục (dentry = một nút tên trong cây file của kernel; vfsmount/mount = điểm
 * gắn kết của một filesystem). Mục tiêu: từ file vừa mở đi NGƯỢC lên gốc của task (gốc container), nhớ nút ngay dưới
 * gốc ("top") — đó là thư mục đầu tiên, vd. /etc/passwd → top = etc. */
struct pulse_tok_walk {
    struct dentry *dentry, *root_dentry, *top;
    struct vfsmount *vfsmnt, *root_mnt;
    struct mount *mnt;
    __u64 mount_offset;
    __u32 components, result, done;
};

/* one step up; bpf_loop keeps the verifier to one pass over this body (an unrolled 64-step walk is too complex) */
/* MỘT BƯỚC đi lên. bpf_loop gọi hàm này tối đa 64 lần; trả 1 để dừng sớm. Ba trường hợp mỗi bước:
 *   a) đã tới gốc của task → kết quả = thư mục "top" (hoặc ROOT nếu file nằm ngay ở gốc);
 *   b) đang ở gốc của một filesystem được mount → nhảy sang điểm mount ở filesystem cha (đi tiếp lên trên);
 *      nếu filesystem không có cha (không nằm dưới gốc task, vd. /proc của host) → REL;
 *   c) bình thường → nhớ nút hiện tại làm "top", đi lên thư mục cha. */
static long pulse_tok_walk_step(__u32 index, void *context)
{
    struct pulse_tok_walk *walk = context;
    /* plain locals: BPF_CORE_READ on walk->field would relocate the field of this local struct against the kernel */
    struct dentry *dentry = walk->dentry, *top = walk->top;
    struct vfsmount *vfsmnt = walk->vfsmnt;
    struct mount *mnt = walk->mnt;
    (void)index;
    if (dentry == walk->root_dentry && vfsmnt == walk->root_mnt) {
        walk->result = (!top || walk->components == 1) ? PULSE_TOK_DIR_ROOT
                       : pulse_tok_dir_hash(BPF_CORE_READ(top, d_name.name));
        walk->done = 1;
        return 1;
    }
    if (dentry == BPF_CORE_READ(vfsmnt, mnt_root)) //mnt_root: mount point
    {
        struct mount *parent = BPF_CORE_READ(mnt, mnt_parent);
        if (parent == mnt) {            /* a filesystem root that is not the task's root */
            walk->result = PULSE_TOK_DIR_REL;
            walk->done = 1;
            return 1;
        }
        walk->dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        walk->mnt = parent;
        walk->vfsmnt = (struct vfsmount *)((void *)parent + walk->mount_offset);
        return 0;
    }
    walk->top = dentry;
    walk->components++;
    walk->dentry = BPF_CORE_READ(dentry, d_parent);
    return 0;
}

/* Thư mục đầu của file mà syscall mở vừa trả về dưới dạng fd: tra fd trong bảng file của task → struct file →
 * (dentry, mount); lấy gốc của task (task->fs->root, chính là gốc container); rồi đi ngược tối đa 64 bước. */
static __always_inline __u32 pulse_tok_dir_of_fd(long fd)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fdtable *table = BPF_CORE_READ(task, files, fdt);//Truy cập vào bảng quản lý file (files) và lấy bảng mô tả file (fdtable) của tiến trình đó
    if (!table || fd < 0 || fd >= BPF_CORE_READ(table, max_fds))
        return PULSE_TOK_DIR_UNKNOWN;
    struct file **files = BPF_CORE_READ(table, fd);
    struct file *file = NULL;
    if (bpf_probe_read_kernel(&file, sizeof(file), &files[fd]) < 0 || !file)
        return PULSE_TOK_DIR_UNKNOWN;
    struct pulse_tok_walk walk = {
        .dentry = BPF_CORE_READ(file, f_path.dentry),
        .vfsmnt = BPF_CORE_READ(file, f_path.mnt),
        .root_dentry = BPF_CORE_READ(task, fs, root.dentry),
        .root_mnt = BPF_CORE_READ(task, fs, root.mnt),
        .mount_offset = bpf_core_field_offset(struct mount, mnt),
        .result = PULSE_TOK_DIR_UNKNOWN,
    };
    /* struct vfsmount nằm BÊN TRONG struct mount (trường mnt): lùi con trỏ đi mount_offset để có struct mount. */
    walk.mnt = (struct mount *)((void *)walk.vfsmnt - walk.mount_offset);
    bpf_loop(PULSE_TOK_DIR_DEPTH, pulse_tok_walk_step, &walk, 0);
    if (!walk.done)
        pulse_tok_stat(1);              /* deeper than PULSE_TOK_DIR_DEPTH */
    return walk.result;
}

/* DỰNG TOKEN LÚC TRẢ VỀ cho một syscall có hook, rồi phát nó. `ret` là giá trị trả về của syscall:
 *   - ret âm trong [-4095, -1] là mã lỗi → nếu syscall có cờ ERR: token = tên + errno (= -ret);
 *   - ret > 0 với syscall đọc/ghi (RW) → token = tên + nhóm cỡ log2(ret);
 *   - ret >= 0 với syscall mở file (OPEN) → ret là fd: token = tên + w/r + thư mục đầu. Cờ mở (để biết r hay w) lấy
 *     từ thanh ghi tham số đã lưu (regs->si cho open, regs->dx cho openat) hoặc từ struct open_how (openat2);
 *   - còn lại → chỉ tên. */
static __always_inline int pulse_tok_return(struct pulse_task_state *state, __u64 cgroup_id, __u32 nr, __u32 flags,
                                            const struct pt_regs *regs, long ret)
{
    __u32 tok = pulse_tok_plain(nr);
    if (ret < 0 && ret >= -4095) {
        if (flags & PULSE_TF_ERR)
            tok |= PULSE_TOK_KIND_ERR | (__u32)(-ret);
    } else if ((flags & PULSE_TF_RW) && ret > 0) {
        tok |= PULSE_TOK_KIND_SIZE | pulse_tok_log2((__u64)ret);
    } else if ((flags & PULSE_TF_OPEN) && ret >= 0) {
        __u64 open_flags = 0;
        if (flags & PULSE_TF_OPEN_CREAT) {
            open_flags = PULSE_TOK_WRITE_FLAGS;
        } else if (flags & PULSE_TF_OPEN_SI) {
            open_flags = BPF_CORE_READ(regs, si);
        } else if (flags & PULSE_TF_OPEN_DX) {
            open_flags = BPF_CORE_READ(regs, dx);
        } else {
            const void *how = (const void *)BPF_CORE_READ(regs, dx);   /* struct open_how: flags is its first u64 */
            if (bpf_probe_read_user(&open_flags, sizeof(open_flags), how) < 0)
                open_flags = 0;
        }
        tok |= PULSE_TOK_KIND_OPEN | (pulse_tok_dir_of_fd(ret) & PULSE_TOK_DIR_MASK) |
               ((open_flags & PULSE_TOK_WRITE_FLAGS) ? PULSE_TOK_OPEN_WRITE : 0);
    }
    pulse_tok_emit(state, cgroup_id, bpf_ktime_get_ns(), tok);
    return 0;
}

/* Hooked calls give their token at return through this one raw tracepoint, not through one fexit trampoline per
 * syscall: every trampoline is one more ftrace_ops, and a function that another ftrace user also hooks (Tetragon's
 * kprobes on __x64_sys_openat, measured 07/11) goes through arch_ftrace_ops_list_func, which walks every ops; 40
 * trampolines made open + close of every process on the node about 1-2 us slower (the fexit variant is at tag
 * archive/pre-audit-20261110). sys_enter already marks the call it saw (tok_pending), so a call skipped by seccomp,
 * which reaches sys_exit without running, gives no second token. */
/* HOOK 3: raw tracepoint sys_exit — chạy sau MỌI syscall của node. Chỉ làm việc khi thread này có tok_pending = 1
 * (tức sys_enter đã thấy một syscall có hook của container được theo dõi). args[0] = thanh ghi tham số (pt_regs),
 * args[1] = giá trị trả về. Một chương trình chung cho cả 39 syscall thay vì 39 chương trình fexit, vì mỗi fexit là một
 * trampoline ftrace và khi Tetragon cũng hook openat thì mọi lần mở file của cả node chậm thêm 1–2 µs (đo 07/11). */
SEC("raw_tp/sys_exit")
int pulse_tok_sys_exit(struct bpf_raw_tracepoint_args *context)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pulse_task_state *state = bpf_map_lookup_elem(&pulse_last_syscall, &pid_tgid);
    if (!state || !state->tok_pending)
        return 0;
    state->tok_pending = 0;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (state->cgroup_id != cgroup_id)
        return 0;
    __u32 nr = state->syscall_id;
    return pulse_tok_return(state, cgroup_id, nr, pulse_tok_flags(nr), (const struct pt_regs *)context->args[0],
                            (long)context->args[1]);
}

/* A child takes its parent's lineage at fork, before it runs: a child that waits for its parent to exit before its
 * first syscall would otherwise be re-parented to the container's pid 1 and read as native. Runs in the parent. The
 * child starts with an empty token history, as a thread first seen at its first syscall does. */
/* HOOK 4: raw tracepoint sched_process_fork — chạy trong process CHA mỗi lần fork/clone. Nếu cha đang được theo dõi
 * (có trạng thái, cùng cgroup), tạo sẵn trạng thái cho CON với dòng dõi của cha và lịch sử token rỗng. Lý do phải làm
 * lúc fork: một process con của phiên `kubectl exec` có thể đợi cha thoát rồi mới gọi syscall đầu tiên; lúc đó nó đã bị
 * "nhận nuôi" bởi pid 1 của container và pulse_tok_lineage sẽ đọc nhầm thành native. args[1] = task_struct của con. */
SEC("raw_tp/sched_process_fork")
int pulse_tok_fork(struct bpf_raw_tracepoint_args *context)
{
    __u64 parent_key = bpf_get_current_pid_tgid();
    struct pulse_task_state *parent = bpf_map_lookup_elem(&pulse_last_syscall, &parent_key);
    if (!parent)
        return 0;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (parent->cgroup_id != cgroup_id)
        return 0;
    struct task_struct *child = (struct task_struct *)context->args[1];
    struct pulse_task_state state = {
        .cgroup_id = cgroup_id,
        .lineage = parent->lineage,
    };
    pulse_tok_reset(&state);
    __u64 child_key = ((__u64)BPF_CORE_READ(child, tgid) << 32) | (__u32)BPF_CORE_READ(child, pid);
    bpf_map_update_elem(&pulse_last_syscall, &child_key, &state, BPF_ANY);
    return 0;
}

#endif