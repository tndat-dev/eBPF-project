// SPDX-License-Identifier: GPL-2.0
/* Token probe of lidds-ml-v3 (reports/Thiết kế probe token Pulse.md): per-thread select1f tokens and a per-cgroup,
 * per-0.5 s window count of token 4-grams. Included by pulse_counter.bpf.c under PULSE_TOKENS, after the maps; the
 * thread history lives in pulse_task_state (pulse_last_syscall), which sys_enter already looks up. */
#ifndef PULSE_TOKENS_BPF_H
#define PULSE_TOKENS_BPF_H

#include "pulse_token_ids.h"

const volatile struct pulse_tok_config pulse_tok_config SEC(".rodata.tokcfg") = {
    .futex_at_exit = 1,
    .count_grams = 1,
};

/* 2^18 (cgroup, window, gram) entries: user space drains closed windows every 0.5 s, so about two windows live. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, struct pulse_gram_key);
    __type(value, __u64);
} pulse_grams SEC(".maps");

/* 0: gram insert failed (map full), 1: d_path failed, 2: grams counted */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} pulse_tok_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[PULSE_TOK_PATH_MAX]);
} pulse_tok_path SEC(".maps");

static __always_inline void pulse_tok_stat(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&pulse_tok_stats, &index);
    if (value)
        (*value)++;
}

static __always_inline void pulse_tok_reset(struct pulse_task_state *state)
{
    state->tok[0] = PULSE_TOK_NONE;
    state->tok[1] = PULSE_TOK_NONE;
    state->tok[2] = PULSE_TOK_NONE;
    state->open_dir = PULSE_TOK_DIR_UNKNOWN;
}

static __always_inline __u32 pulse_tok_plain(__u32 nr)
{
    return (nr > PULSE_TOK_NR_MAX ? PULSE_TOK_NR_MAX : nr) << PULSE_TOK_NR_SHIFT;
}

/* syscalls that give their token at return; all others give it at entry */
static __always_inline int pulse_tok_hooked(__u32 nr)
{
    if (nr == PULSE_FUTEX_NR)
        return pulse_tok_config.futex_at_exit;
    switch (nr) {
#define PULSE_CASE(number, name, flags) case number: return 1;
        PULSE_HOOKED_ROWS(PULSE_CASE)
#undef PULSE_CASE
    default: return 0;
    }
}

/* the gram ending in tok, then the history moves on by one */
static __always_inline void pulse_tok_emit(struct pulse_task_state *state, __u64 cgroup_id, __u64 now_ns, __u32 tok)
{
    if (pulse_tok_config.count_grams) {
        struct pulse_gram_key key = {
            .cgroup_id = cgroup_id,
            .window = (__u32)(now_ns / PULSE_TOK_WINDOW_NS),
            .tok = { state->tok[0], state->tok[1], state->tok[2], tok },
            .pad = 0,
        };
        __u64 *count = bpf_map_lookup_elem(&pulse_grams, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            __u64 one = 1;
            if (bpf_map_update_elem(&pulse_grams, &key, &one, BPF_NOEXIST) < 0) {
                count = bpf_map_lookup_elem(&pulse_grams, &key);   /* lost a race with another CPU */
                if (count)
                    __sync_fetch_and_add(count, 1);
                else
                    pulse_tok_stat(0);
            }
        }
        pulse_tok_stat(2);
    }
    state->tok[0] = state->tok[1];
    state->tok[1] = state->tok[2];
    state->tok[2] = tok;
}

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

static __always_inline __u32 pulse_tok_flags(__u32 nr)
{
    switch (nr) {
#define PULSE_CASE(number, name, flags) case number: return flags;
        PULSE_HOOKED_ROWS(PULSE_CASE)
#undef PULSE_CASE
    default: return 0;
    }
}

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
        tok |= PULSE_TOK_KIND_OPEN | (state->open_dir & PULSE_TOK_DIR_MASK) |
               ((open_flags & PULSE_TOK_WRITE_FLAGS) ? PULSE_TOK_OPEN_WRITE : 0);
    }
    pulse_tok_emit(state, cgroup_id, bpf_ktime_get_ns(), tok);
    return 0;
}

static __always_inline int pulse_tok_exit(__u32 nr, __u32 flags, const struct pt_regs *regs, long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pulse_task_state *state = bpf_map_lookup_elem(&pulse_last_syscall, &pid_tgid);
    if (!state)
        return 0;   /* thread never entered a syscall in a monitored cgroup */
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (state->cgroup_id != cgroup_id)
        return 0;   /* sys_enter of this very call updated cgroup_id; a mismatch means it was not monitored */
    return pulse_tok_return(state, cgroup_id, nr, flags, regs, ret);
}

/* The same tokens from one raw tracepoint instead of 39 fexit trampolines (loader --token-exit sys_exit). Every
 * fexit trampoline is one more ftrace_ops, and a function that another ftrace user also hooks (Tetragon's kprobes on
 * __x64_sys_openat, measured 07/11) goes through arch_ftrace_ops_list_func, which walks every ops: 40 trampolines
 * made open + close of every process on the node about 1-2 us slower. sys_enter already marks the call it saw
 * (tok_pending), so a call skipped by seccomp, which reaches sys_exit without running, gives no second token. */
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

#define PULSE_TOK_EXIT_PROG(number, name, flags)                                     \
    SEC("fexit/__x64_sys_" #name)                                                     \
    int BPF_PROG(pulse_tok_x_##name, const struct pt_regs *regs, long ret)            \
    {                                                                                 \
        return pulse_tok_exit(number, flags, regs, ret);                              \
    }
PULSE_HOOKED_ROWS(PULSE_TOK_EXIT_PROG)
#undef PULSE_TOK_EXIT_PROG

/* First directory of the file being opened, from its resolved path (as sysdig's fd=N(<f>PATH) in LID-DS), kept for
 * the open's fexit. d_path is relative to the task's root, so inside a container it is the container's view. */
SEC("fentry/security_file_open")
int BPF_PROG(pulse_tok_open_dir, struct file *file)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pulse_task_state *state = bpf_map_lookup_elem(&pulse_last_syscall, &pid_tgid);
    if (!state || state->cgroup_id != bpf_get_current_cgroup_id())
        return 0;
    __u32 zero = 0;
    char *path = bpf_map_lookup_elem(&pulse_tok_path, &zero);
    if (!path)
        return 0;
    long length = bpf_d_path(&file->f_path, path, PULSE_TOK_PATH_MAX);
    if (length < 0) {
        state->open_dir = PULSE_TOK_DIR_UNKNOWN;
        pulse_tok_stat(1);
        return 0;
    }
    if (path[0] != '/') {
        state->open_dir = PULSE_TOK_DIR_REL;
        return 0;
    }
    __u32 hash = PULSE_TOK_FNV_BASIS;
    int ended = 0;
    for (int index = 1; index < PULSE_TOK_DIR_CHARS; index++) {
        char c = path[index];
        if (c == '/') break;
        if (c == 0) { ended = 1; break; }
        hash = (hash ^ (__u8)c) * PULSE_TOK_FNV_PRIME;
    }
    if (ended) {
        state->open_dir = PULSE_TOK_DIR_ROOT;   /* '/' or '/name': a file in the root, top '/' */
        return 0;
    }
    /* a first component of 63+ chars is hashed on its first 63, as a directory */
    hash &= PULSE_TOK_DIR_MASK;
    if (hash >= PULSE_TOK_DIR_REL)
        hash -= 2;   /* keep the two reserved codes */
    state->open_dir = hash;
    return 0;
}

#endif
