// SPDX-License-Identifier: GPL-2.0
/* Isolated exact syscall-ID histogram for syscall-selection experiments.
 * This is deliberately a separate object from the frozen Pulse feature ABI.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define SYSCALL_ID_LIMIT 1024
#define HISTOGRAM_MAX_ENTRIES 65536
#define TARGET_MAX_ENTRIES 2048

struct histogram_key {
    __u64 cgroup_id;
    __u32 syscall_id;
    __u32 padding;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TARGET_MAX_ENTRIES);
    __type(key, __u64);
    __type(value, __u8);
} histogram_targets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, HISTOGRAM_MAX_ENTRIES);
    __type(key, struct histogram_key);
    __type(value, __u64);
} syscall_histogram SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} histogram_stats SEC(".maps");

SEC("raw_tp/sys_enter")
int histogram_sys_enter(struct bpf_raw_tracepoint_args *context)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&histogram_targets, &cgroup_id))
        return 0;

    __u32 syscall_id = (__u32)context->args[1];
    if (syscall_id >= SYSCALL_ID_LIMIT)
        return 0;

    struct histogram_key key = {
        .cgroup_id = cgroup_id,
        .syscall_id = syscall_id,
    };
    __u64 *count = bpf_map_lookup_elem(&syscall_histogram, &key);
    if (!count) {
        __u64 zero = 0;
        if (bpf_map_update_elem(&syscall_histogram, &key, &zero, BPF_NOEXIST) < 0) {
            /* Another CPU may have inserted this key at the same time. That
             * is normal first-use contention, not a lost counter update. */
            count = bpf_map_lookup_elem(&syscall_histogram, &key);
            if (!count) {
                __u32 stat_key = 0;
                __u64 *drops = bpf_map_lookup_elem(&histogram_stats, &stat_key);
                if (drops)
                    __sync_fetch_and_add(drops, 1);
                return 0;
            }
        } else {
            count = bpf_map_lookup_elem(&syscall_histogram, &key);
        }
    }
    if (count)
        __sync_fetch_and_add(count, 1);
    else {
        __u32 stat_key = 0;
        __u64 *drops = bpf_map_lookup_elem(&histogram_stats, &stat_key);
        if (drops)
            __sync_fetch_and_add(drops, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
