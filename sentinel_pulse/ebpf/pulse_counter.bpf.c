// SPDX-License-Identifier: GPL-2.0
/* Per-CPU, per-cgroup syscall distribution and transition sketch. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "pulse_counter_ids.h"
#ifdef PULSE_TOKENS
#include <bpf/bpf_core_read.h>
#endif

#define PULSE_MAX_SYSCALL_ID 1024
#define PULSE_SYSCALL_BINS 64
#define PULSE_TRANSITION_BINS 64
#define PULSE_TRACKED 29
#define PULSE_TRANSITION_MAX_GAP_NS 5000000000ULL

struct pulse_counters {
    __u64 full_counts[PULSE_MAX_SYSCALL_ID];
    __u64 transition_bins[PULSE_TRANSITION_BINS];
    __u64 seccomp_skipped_or_emulated;
};

struct pulse_task_state {
    __u64 cgroup_id;
    __u64 seen_ns;
    __u32 syscall_id;
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
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct pulse_counters);
} pulse_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u64);
    __type(value, struct pulse_task_state);
} pulse_last_syscall SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pulse_stats SEC(".maps");

#ifdef PULSE_TOKENS
#include "pulse_tokens.bpf.h"
#endif



static __always_inline __u32 syscall_bin(__u32 id)
{
    return (id * 2654435761U) >> 26;
}

static __always_inline __u32 transition_bin(__u32 previous, __u32 current)
{
    return ((previous * 31U + current) * 2654435761U) >> 26;
}

static __always_inline int pulse_record_call(__u32 syscall_id, int skipped)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct pulse_counters *counters = bpf_map_lookup_elem(&pulse_cgroups, &cgroup_id);
    if (!counters)
        return 0;

    if (syscall_id >= PULSE_MAX_SYSCALL_ID)
        return 0;

    counters->full_counts[syscall_id]++;

    if (skipped) counters->seccomp_skipped_or_emulated++;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 now_ns = bpf_ktime_get_ns();
    struct pulse_task_state *previous = bpf_map_lookup_elem(&pulse_last_syscall, &pid_tgid);
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
        previous->cgroup_id = cgroup_id;
        previous->seen_ns = now_ns;
        previous->syscall_id = syscall_id;
        return 0;
    }

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
    if (bpf_map_update_elem(&pulse_last_syscall, &pid_tgid, &current, BPF_NOEXIST) < 0) {
        __u32 zero = 0;
        __u64 *failures = bpf_map_lookup_elem(&pulse_stats, &zero);
        if (failures)
            __sync_fetch_and_add(failures, 1);
    }
    return 0;
}

SEC("raw_tp/sys_enter")
int pulse_sys_enter(struct bpf_raw_tracepoint_args *context)
{
    return pulse_record_call((__u32)context->args[1], 0);
}

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


char LICENSE[] SEC("license") = "GPL";
