// SPDX-License-Identifier: GPL-2.0
/* Per-CPU, per-cgroup syscall distribution and transition sketch. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define PULSE_MAX_SYSCALL_ID 1024
#define PULSE_SYSCALL_BINS 64
#define PULSE_TRANSITION_BINS 64
#define PULSE_TRACKED 29
#define PULSE_TRANSITION_MAX_GAP_NS 5000000000ULL

struct pulse_counters {
    __u64 syscall_bins[PULSE_SYSCALL_BINS];
    __u64 transition_bins[PULSE_TRANSITION_BINS];
    __u64 tracked[PULSE_TRACKED];
    __u64 total;
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

static __always_inline __u32 syscall_bin(__u32 id)
{
    return (id * 2654435761U) >> 26;
}

static __always_inline __u32 transition_bin(__u32 previous, __u32 current)
{
    return ((previous * 31U + current) * 2654435761U) >> 26;
}

SEC("raw_tp/sys_enter")
int pulse_sys_enter(struct bpf_raw_tracepoint_args *context)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct pulse_counters *counters = bpf_map_lookup_elem(&pulse_cgroups, &cgroup_id);
    if (!counters)
        return 0;

    __u32 syscall_id = (__u32)context->args[1];
    if (syscall_id >= PULSE_MAX_SYSCALL_ID)
        return 0;

    counters->total++;
    __u32 sc_bin = syscall_bin(syscall_id);
    if (sc_bin < PULSE_SYSCALL_BINS)
        counters->syscall_bins[sc_bin]++;
    increment_tracked(counters, syscall_id);

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

char LICENSE[] SEC("license") = "GPL";
