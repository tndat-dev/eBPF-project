// SPDX-License-Identifier: GPL-2.0
/* Per-CPU, per-cgroup syscall distribution and transition sketch. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#ifdef PULSE_SECCOMP_EXTENDED
#include <bpf/bpf_tracing.h>
#ifndef PULSE_PROJECTED_COUNTERS
#error extended seccomp requires the projected counter ABI
#endif
#endif
#include "pulse_counter_ids.h"
#ifdef PULSE_EXEC_INTENT
#if !defined(PULSE_FULL_IDS) || !defined(PULSE_SECCOMP_EXTENDED)
#error exec-intent counters extend the matched full-ID ABI
#endif
#include <bpf/bpf_core_read.h>
/* protocol exec-intent-v1 fixed values: a process is "young" for 30 s after its exec; its first 512 syscalls
 * (or its first 2 s, whichever ends first) are its startup phase, the rest its steady phase. */
#define PULSE_YOUNG_NS 30000000000ULL
#define PULSE_STARTUP_CALLS 512ULL
#define PULSE_STARTUP_NS 2000000000ULL
#endif

#define PULSE_MAX_SYSCALL_ID 1024
#define PULSE_SYSCALL_BINS 64
#define PULSE_TRANSITION_BINS 64
#define PULSE_TRACKED 29
#define PULSE_TRANSITION_MAX_GAP_NS 5000000000ULL

struct pulse_counters {
#ifdef PULSE_PROJECTED_COUNTERS
#ifdef PULSE_FULL_IDS
    __u64 full_counts[PULSE_MAX_SYSCALL_ID];
#else
    __u64 tracked[PULSE_TRACKED];
    __u64 other_syscall_bins[PULSE_SYSCALL_BINS];
#endif
    __u64 transition_bins[PULSE_TRANSITION_BINS];
#ifdef PULSE_SECCOMP_EXTENDED
    __u64 seccomp_skipped_or_emulated;
#endif
#ifdef PULSE_EXEC_INTENT
    __u64 execs;                                /* sched_process_exec in this cgroup */
    __u64 young_startup_calls;                  /* syscalls of young processes in their startup phase */
    __u64 young_steady_calls;                   /* ... in their steady phase */
    __u64 young_steady_tracked[PULSE_TRACKED];  /* tracked syscalls of young processes in their steady phase */
    __u64 failed_tracked[PULSE_TRACKED];        /* tracked syscalls returning -errno, any process */
#endif
#else
    __u64 syscall_bins[PULSE_SYSCALL_BINS];
    __u64 transition_bins[PULSE_TRANSITION_BINS];
    __u64 tracked[PULSE_TRACKED];
    __u64 total;
#endif
};

struct pulse_task_state {
    __u64 cgroup_id;
    __u64 seen_ns;
    __u32 syscall_id;
    __u32 padding;
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

#ifdef PULSE_EXEC_INTENT
struct pulse_exec_state {
    __u64 exec_ns;
    __u64 calls;
};

/* One entry per process (tgid) exec'd in a monitored cgroup; LRU so old processes age out. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct pulse_exec_state);
} pulse_exec_states SEC(".maps");

static __always_inline void increment_young_steady(struct pulse_counters *counters, __u32 id)
{
    switch (id) {
#define PULSE_CASE(number, slot) case number: counters->young_steady_tracked[slot]++; return;
        PULSE_TRACKED_ROWS(PULSE_CASE)
#undef PULSE_CASE
    default: return;
    }
}

static __always_inline void increment_failed(struct pulse_counters *counters, __u64 id)
{
    switch (id) {
#define PULSE_CASE(number, slot) case number: counters->failed_tracked[slot]++; return;
        PULSE_TRACKED_ROWS(PULSE_CASE)
#undef PULSE_CASE
    default: return;
    }
}
#endif

#ifndef PULSE_PROJECTED_COUNTERS
static __always_inline void increment_tracked(
    struct pulse_counters *counters, __u32 id)
{
    /* Use constant offsets in every branch.  Linux 6.8's verifier does not
     * retain a useful upper bound for a slot returned from a large inlined
     * switch, despite a subsequent slot < PULSE_TRACKED guard. */
    switch (id) {
    case 0: counters->tracked[0]++; break;
    case 1: counters->tracked[1]++; break;
    case 2: counters->tracked[2]++; break;
    case 3: counters->tracked[3]++; break;
    case 9: counters->tracked[4]++; break;
    case 10: counters->tracked[5]++; break;
    case 41: counters->tracked[6]++; break;
    case 42: counters->tracked[7]++; break;
    case 43: counters->tracked[8]++; break;
    case 44: counters->tracked[9]++; break;
    case 45: counters->tracked[10]++; break;
    case 56: counters->tracked[11]++; break;
    case 59: counters->tracked[12]++; break;
    case 90: counters->tracked[13]++; break;
    case 101: counters->tracked[14]++; break;
    case 105: counters->tracked[15]++; break;
    case 106: counters->tracked[16]++; break;
    case 126: counters->tracked[17]++; break;
    case 155: counters->tracked[18]++; break;
    case 165: counters->tracked[19]++; break;
    case 257: counters->tracked[20]++; break;
    case 272: counters->tracked[21]++; break;
    case 288: counters->tracked[22]++; break;
    case 299: counters->tracked[23]++; break;
    case 307: counters->tracked[24]++; break;
    case 308: counters->tracked[25]++; break;
    case 317: counters->tracked[26]++; break;
    case 322: counters->tracked[27]++; break;
    case 435: counters->tracked[28]++; break;
    default: break;
    }
}
#elif !defined(PULSE_FULL_IDS)
static __always_inline int increment_projected_tracked(
    struct pulse_counters *counters, __u32 id)
{
    switch (id) {
#define PULSE_CASE(number, slot) case number: counters->tracked[slot]++; return 1;
        PULSE_TRACKED_ROWS(PULSE_CASE)
#undef PULSE_CASE
    default: return 0;
    }
}
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

#ifdef PULSE_PROJECTED_COUNTERS
#ifdef PULSE_FULL_IDS
    counters->full_counts[syscall_id]++;
#else
    if (!increment_projected_tracked(counters, syscall_id)) {
        __u32 sc_bin = syscall_bin(syscall_id);
        if (sc_bin < PULSE_SYSCALL_BINS)
            counters->other_syscall_bins[sc_bin]++;
    }
#endif
#else
    counters->total++;
    __u32 sc_bin = syscall_bin(syscall_id);
    if (sc_bin < PULSE_SYSCALL_BINS)
        counters->syscall_bins[sc_bin]++;
    increment_tracked(counters, syscall_id);
#endif

#ifdef PULSE_SECCOMP_EXTENDED
    if (skipped) counters->seccomp_skipped_or_emulated++;
#else
    (void)skipped;
#endif

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 now_ns = bpf_ktime_get_ns();
#ifdef PULSE_EXEC_INTENT
    __u32 tgid = pid_tgid >> 32;
    struct pulse_exec_state *young = bpf_map_lookup_elem(&pulse_exec_states, &tgid);
    if (young && now_ns >= young->exec_ns && now_ns - young->exec_ns <= PULSE_YOUNG_NS) {
        __u64 index = __sync_fetch_and_add(&young->calls, 1);
        if (index < PULSE_STARTUP_CALLS && now_ns - young->exec_ns < PULSE_STARTUP_NS) {
            counters->young_startup_calls++;
        } else {
            counters->young_steady_calls++;
            increment_young_steady(counters, syscall_id);
        }
    }
#endif
    struct pulse_task_state *previous = bpf_map_lookup_elem(&pulse_last_syscall, &pid_tgid);
    if (previous && previous->cgroup_id == cgroup_id &&
        now_ns >= previous->seen_ns &&
        now_ns - previous->seen_ns <= PULSE_TRANSITION_MAX_GAP_NS) {
        __u32 tr_bin = transition_bin(previous->syscall_id, syscall_id);
        if (tr_bin < PULSE_TRANSITION_BINS)
            counters->transition_bins[tr_bin]++;
    }

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

#ifdef PULSE_SECCOMP_EXTENDED
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
#endif

#ifdef PULSE_EXEC_INTENT
SEC("tp/sched/sched_process_exec")
int pulse_process_exec(void *context)
{
    (void)context;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct pulse_counters *counters = bpf_map_lookup_elem(&pulse_cgroups, &cgroup_id);
    if (!counters)
        return 0;
    counters->execs++;
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct pulse_exec_state state = { .exec_ns = bpf_ktime_get_ns(), .calls = 0 };
    bpf_map_update_elem(&pulse_exec_states, &tgid, &state, BPF_ANY);   /* a re-exec restarts the phases */
    return 0;
}

SEC("raw_tp/sys_exit")
int pulse_sys_exit(struct bpf_raw_tracepoint_args *context)
{
    long ret = (long)context->args[1];
    if (ret >= 0 || ret < -4095)
        return 0;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct pulse_counters *counters = bpf_map_lookup_elem(&pulse_cgroups, &cgroup_id);
    if (!counters)
        return 0;
    struct pt_regs *regs = (struct pt_regs *)context->args[0];
    increment_failed(counters, BPF_CORE_READ(regs, orig_ax));
    return 0;
}
#endif

char LICENSE[] SEC("license") = "GPL";
