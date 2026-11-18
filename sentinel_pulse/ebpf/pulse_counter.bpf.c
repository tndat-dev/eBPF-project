// SPDX-License-Identifier: GPL-2.0
/* Per-CPU, per-cgroup syscall distribution and transition sketch. */
/* ===================================================================================================================
 * pulse_counter.bpf.c — CHƯƠNG TRÌNH eBPF CHẠY TRONG KERNEL (điểm vào của probe)
 * -------------------------------------------------------------------------------------------------------------------
 * Biên dịch bằng clang thành pulse_counter.bpf.o (Makefile, `make tokens` bật -DPULSE_TOKENS để thêm probe token).
 * Loader (pulse_counter_loader.c) nạp object này vào kernel, gắn các chương trình vào hook, và đọc các map.
 *
 * Hai việc diễn ra ở MỖI syscall của node (mọi process, mọi container):
 *   1) `raw_tp/sys_enter` (pulse_sys_enter) chạy TRƯỚC syscall. Nó tra cgroup của task hiện tại trong map
 *      pulse_cgroups — map này đồng thời là allow-list: chỉ container được theo dõi mới có khoá trong map. Task không
 *      được theo dõi thoát ngay sau MỘT lần tra map (vì vậy container không theo dõi vẫn trả ~0,2–0,3 µs mỗi syscall).
 *   2) Với task được theo dõi: tăng bộ đếm syscall (mô hình đếm cũ) và — nếu build có PULSE_TOKENS — phát token
 *      (mô hình hiện tại), xem pulse_tokens.bpf.h.
 *   Ngoài ra `fexit/__seccomp_filter` bắt các syscall bị seccomp chặn/giả lập: chúng không đi qua đường bình thường
 *   nên nếu không bắt ở đây thì sẽ thiếu token, mà đồ án cần "mỗi syscall đúng một token".
 *
 * Ba map khai báo ở file này:
 *   - pulse_cgroups      : allow-list + bộ đếm syscall theo cgroup (PERCPU_HASH, tối đa 1024 cgroup/node).
 *   - pulse_last_syscall : trạng thái của từng thread (LRU_HASH, khoá = pid_tgid): cgroup, thời điểm và syscall trước,
 *                          và (bản token) 3 token gần nhất, cờ chờ sys_exit, thẻ dòng dõi.
 *   - pulse_stats        : đếm số lần không chèn được trạng thái thread (map đầy) — để phát hiện mất dữ liệu.
 * =================================================================================================================== */

#include "vmlinux.h"              /* mọi kiểu dữ liệu của kernel (sinh bằng bpftool từ BTF), dùng cho CO-RE */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "pulse_counter_ids.h"
#ifdef PULSE_TOKENS
#include <bpf/bpf_core_read.h>    /* BPF_CORE_READ: đọc trường struct kernel, tự chỉnh offset theo kernel đang chạy */
#endif

#define PULSE_MAX_SYSCALL_ID 1024
#define PULSE_SYSCALL_BINS 64
#define PULSE_TRANSITION_BINS 64
#define PULSE_TRACKED 29
#define PULSE_TRANSITION_MAX_GAP_NS 5000000000ULL   /* hai syscall cách nhau > 5 s thì không tính là "chuyển tiếp" */

/* Phải trùng byte-cho-byte với struct cùng tên trong pulse_counter_projection.h (phía user space). */
struct pulse_counters {
    __u64 full_counts[PULSE_MAX_SYSCALL_ID];
    __u64 transition_bins[PULSE_TRANSITION_BINS];
    __u64 seccomp_skipped_or_emulated;
};

/* Trạng thái của MỘT thread (giá trị của map pulse_last_syscall, khoá = pid_tgid = (tgid << 32) | pid).
 * Lưu ý: kernel gọi thread là "task"; pid ở đây là id của thread, tgid là id của process. */
struct pulse_task_state {
    __u64 cgroup_id;      /* container của thread ở lần syscall trước (đổi cgroup → bắt đầu lịch sử mới) */
    __u64 seen_ns;        /* thời điểm syscall trước (ns, đồng hồ monotonic của kernel) */
    __u32 syscall_id;     /* số syscall trước; với bản token cũng là syscall đang chờ sys_exit */
#ifdef PULSE_TOKENS
    __u32 tok[3];       /* the thread's last three tokens, oldest first; PULSE_TOK_NONE when empty */
    __u32 tok_pending;  /* this call entered and gives its token at return (raw_tp/sys_exit mode) */
    __u32 lineage;      /* PULSE_LINEAGE_NATIVE: the workload's own process tree; PULSE_LINEAGE_SESSION: entered by a runtime exec */
#else
    __u32 padding;
#endif
};

/* The map itself is the allow-list. Preallocate a deliberately bounded map so
 * target insertion cannot fail intermittently in the syscall collector's
 * startup path. 1024 leaf cgroups per node is over 20x the current production
 * high-water mark while keeping worst-case per-CPU memory below the service's
 * 1 GiB cgroup limit on a 24-vCPU worker. */
/* Allow-list kiêm bộ đếm. Loader thêm/xoá khoá theo file allow-list do resolver ghi (cgroup của các container cần
 * theo dõi). Kernel không bao giờ tự thêm khoá: cgroup nào không có trong map thì không bị theo dõi. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct pulse_counters);
} pulse_cgroups SEC(".maps");

/* Trạng thái từng thread. LRU: khi đầy (131.072 thread), thread lâu không gọi syscall bị đẩy ra trước. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u64);
    __type(value, struct pulse_task_state);
} pulse_last_syscall SEC(".maps");

/* Một ô duy nhất: số lần chèn trạng thái thread thất bại (loader in ra thành stat "task_state_update_fail"). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pulse_stats SEC(".maps");

/* Probe token được "dán" vào đây (sau khi các map trên đã khai báo, vì nó dùng pulse_last_syscall). */
#ifdef PULSE_TOKENS
#include "pulse_tokens.bpf.h"
#endif



/* Băm Fibonacci số syscall vào 1 trong 64 ô (giống hệt phía user space trong pulse_counter_projection.h). */
static __always_inline __u32 syscall_bin(__u32 id)
{
    return (id * 2654435761U) >> 26;
}

/* Băm cặp (syscall trước, syscall hiện tại) của cùng thread vào 1 trong 64 ô chuyển tiếp. */
static __always_inline __u32 transition_bin(__u32 previous, __u32 current)
{
    return ((previous * 31U + current) * 2654435761U) >> 26;
}

/* HÀM CHÍNH, chạy ở mỗi syscall của mọi task trên node.
 *   syscall_id : số syscall x86_64 vừa được gọi.
 *   skipped    : 1 nếu gọi từ hook seccomp (syscall bị seccomp chặn/giả lập, không chạy thật), 0 nếu từ sys_enter. */
static __always_inline int pulse_record_call(__u32 syscall_id, int skipped)
{
    /* Bước 1 — lọc theo cgroup: task không thuộc container được theo dõi thì thoát ngay. */
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct pulse_counters *counters = bpf_map_lookup_elem(&pulse_cgroups, &cgroup_id);
    if (!counters)
        return 0;

    if (syscall_id >= PULSE_MAX_SYSCALL_ID)
        return 0;

    /* Bước 2 — bộ đếm của mô hình đếm cũ (bản per-CPU nên không cần thao tác nguyên tử). */
    counters->full_counts[syscall_id]++;

    if (skipped) counters->seccomp_skipped_or_emulated++;

    /* Bước 3 — tra trạng thái của thread hiện tại (lần syscall trước của nó). */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 now_ns = bpf_ktime_get_ns();
    struct pulse_task_state *previous = bpf_map_lookup_elem(&pulse_last_syscall, &pid_tgid);
    /* Đếm "chuyển tiếp" (syscall trước → syscall này) nếu cùng container và cách nhau không quá 5 s. */
    if (previous && previous->cgroup_id == cgroup_id &&
        now_ns >= previous->seen_ns &&
        now_ns - previous->seen_ns <= PULSE_TRANSITION_MAX_GAP_NS) {
        __u32 tr_bin = transition_bin(previous->syscall_id, syscall_id);
        if (tr_bin < PULSE_TRANSITION_BINS)
            counters->transition_bins[tr_bin]++;
    }

#ifdef PULSE_TOKENS
    /* A hooked syscall gives its token at return (pulse_tok_sys_exit); one skipped by seccomp never runs, so it gives
     * its name here like an unhooked one. A thread that moved cgroup starts a new history. */
    /* Bước 4 (probe token) — quyết định token của lời gọi này phát Ở ĐÂY (lúc vào) hay ở sys_exit (lúc trả về):
     *   - syscall KHÔNG nằm trong 39 syscall có hook → phát token "chỉ tên" ngay bây giờ;
     *   - syscall bị seccomp bỏ qua → cũng phát ngay (nó sẽ không bao giờ trả về một kết quả thật);
     *   - còn lại → đánh dấu tok_pending = 1, chương trình sys_exit sẽ phát token kèm kết quả.
     * Thread vừa chuyển sang cgroup khác (hiếm) → xoá lịch sử token và tính lại dòng dõi. */
    int token_here = skipped || !pulse_tok_hooked(syscall_id);
    if (previous) {
        if (previous->cgroup_id != cgroup_id) {
            pulse_tok_reset(previous);
            previous->lineage = pulse_tok_lineage(cgroup_id);
        }
        if (token_here)
            pulse_tok_emit(previous, cgroup_id, now_ns, pulse_tok_plain(syscall_id));
        previous->tok_pending = !token_here;
    }
#endif
    if (previous) {
        /* A task cannot execute two syscalls concurrently. Updating the map
         * value in place avoids an LRU update helper and global map work on
         * every hot-path syscall. */
        /* Một thread không thể gọi hai syscall cùng lúc, nên sửa thẳng giá trị trong map (không cần khoá). */
        previous->cgroup_id = cgroup_id;
        previous->seen_ns = now_ns;
        previous->syscall_id = syscall_id;
        return 0;
    }

    /* Thread lần đầu gặp (chưa có trạng thái): tạo trạng thái mới, lịch sử token rỗng, tính dòng dõi một lần. */
    struct pulse_task_state current = {
        .cgroup_id = cgroup_id,
        .seen_ns = now_ns,
        .syscall_id = syscall_id,
    };
#ifdef PULSE_TOKENS
    pulse_tok_reset(&current);
    current.lineage = pulse_tok_lineage(cgroup_id);
    if (token_here)
        pulse_tok_emit(&current, cgroup_id, now_ns, pulse_tok_plain(syscall_id));
    current.tok_pending = !token_here;
#endif
    /* BPF_NOEXIST: chỉ chèn nếu chưa có khoá. Thất bại (map đầy...) được đếm vào pulse_stats để loader báo. */
    if (bpf_map_update_elem(&pulse_last_syscall, &pid_tgid, &current, BPF_NOEXIST) < 0) {
        __u32 zero = 0;
        __u64 *failures = bpf_map_lookup_elem(&pulse_stats, &zero);
        if (failures)
            __sync_fetch_and_add(failures, 1);
    }
    return 0;
}

/* HOOK 1: raw tracepoint sys_enter — chạy trước MỌI syscall của node. args[1] là số syscall. Dùng raw tracepoint
 * (không phải tracepoint thường hay kprobe) vì đây là đường rẻ nhất: không chuẩn bị tham số, không qua ftrace. */
SEC("raw_tp/sys_enter")
int pulse_sys_enter(struct bpf_raw_tracepoint_args *context)
{
    return pulse_record_call((__u32)context->args[1], 0);
}

/* HOOK 2: fexit của hàm kernel __seccomp_filter — chạy SAU khi seccomp quyết định cho một syscall. Nếu kết quả là -1
 * (syscall bị bỏ qua/giả lập), syscall đó không đi tiếp tới sys_enter trên kernel 6.8 đã kiểm, nên ta ghi nó ở đây với
 * skipped = 1. Bỏ qua lần kiểm lại lồng nhau (recheck_after_trace) để không đếm hai lần. */
SEC("fexit/__seccomp_filter")
int BPF_PROG(pulse_seccomp_skip, int nr, const struct seccomp_data *sd,
             bool recheck_after_trace, int result)
{
    /* Skip does not reach sys_enter on the validated Linux 6.8 entry path.
     * Avoid counting the nested TRACE recheck. KILL need not return here;
     * -1 can include emulation, so this is NOT labelled universally denied. */
    if (result == -1 && !recheck_after_trace && nr >= 0)
        return pulse_record_call((__u32)nr, 1);
    return 0;
}


/* Giấy phép GPL là bắt buộc để dùng một số helper của kernel (bpf_probe_read_kernel...). */
char LICENSE[] SEC("license") = "GPL";
