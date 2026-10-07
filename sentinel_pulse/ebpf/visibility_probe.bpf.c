// SPDX-License-Identifier: GPL-2.0
/* Private diagnostic maps: never merged into a frozen Pulse collector. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} visibility_target SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} visibility_counts SEC(".maps");

static __always_inline int slot(int nr)
{
    switch (nr) {
    case 10: return 0;  /* mprotect, x86_64 only */
    case 308: return 1; /* setns */
    case 317: return 2; /* seccomp */
    default: return -1;
    }
}

static __always_inline int owned(void)
{
    __u32 zero = 0;
    __u64 *cg = bpf_map_lookup_elem(&visibility_target, &zero);
    return cg && *cg && bpf_get_current_cgroup_id() == *cg;
}

static __always_inline void increment(int nr, __u32 offset)
{
    int index = slot(nr);
    if (index < 0 || !owned()) return;
    __u32 key = (__u32)index + offset;
    __u64 *value = bpf_map_lookup_elem(&visibility_counts, &key);
    if (value) (*value)++;
}

SEC("raw_tp/sys_enter")
int visibility_enter(struct bpf_raw_tracepoint_args *ctx)
{
    increment((int)ctx->args[1], 0);
    return 0;
}

SEC("fexit/__seccomp_filter")
int BPF_PROG(visibility_seccomp_exit, int nr, const struct seccomp_data *sd,
             bool recheck_after_trace, int result)
{
    /* -1 means skipped/emulated, not universally "denied". KILL need not
     * return here. Ignore the inner TRACE recheck to avoid double counting. */
    if (result == -1 && !recheck_after_trace) increment(nr, 3);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
