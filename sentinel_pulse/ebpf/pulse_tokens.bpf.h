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

/* 0: gram insert failed (map full), 1: first directory walk deeper than PULSE_TOK_DIR_DEPTH, 2: grams counted */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} pulse_tok_stats SEC(".maps");


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

/* First directory of the file an open just returned as fd, as LID-DS takes it from sysdig's resolved fd=N(<f>PATH):
 * '/' + the first component under the task's root (inside a container, the container's root), DIR_ROOT for a file
 * directly in the root, DIR_REL for a file not under the task's root (pseudo files, another root), DIR_UNKNOWN when
 * the walk fails. The dentry chain is walked upwards, crossing mount points, without d_path: d_path is allowed only
 * in a few fentry hooks, and every fentry trampoline is one more ftrace_ops (07/11: fentry/security_file_open cost
 * about 380 ns on every open of every process of the node, monitored or not). */
static __always_inline __u32 pulse_tok_dir_hash(const unsigned char *name)
{
    char buffer[PULSE_TOK_DIR_CHARS];
    if (bpf_probe_read_kernel_str(buffer, sizeof(buffer), name) <= 0)
        return PULSE_TOK_DIR_UNKNOWN;
    __u32 hash = PULSE_TOK_FNV_BASIS;
    for (int index = 0; index < PULSE_TOK_DIR_CHARS - 1; index++) {
        char c = buffer[index];
        if (c == 0) break;
        hash = (hash ^ (__u8)c) * PULSE_TOK_FNV_PRIME;
    }
    hash &= PULSE_TOK_DIR_MASK;
    return hash >= PULSE_TOK_DIR_REL ? hash - 2 : hash;   /* keep the two reserved codes */
}

struct pulse_tok_walk {
    struct dentry *dentry, *root_dentry, *top;
    struct vfsmount *vfsmnt, *root_mnt;
    struct mount *mnt;
    __u64 mount_offset;
    __u32 components, result, done;
};

/* one step up; bpf_loop keeps the verifier to one pass over this body (an unrolled 64-step walk is too complex) */
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
    if (dentry == BPF_CORE_READ(vfsmnt, mnt_root)) {
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

static __always_inline __u32 pulse_tok_dir_of_fd(long fd)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fdtable *table = BPF_CORE_READ(task, files, fdt);
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
    walk.mnt = (struct mount *)((void *)walk.vfsmnt - walk.mount_offset);
    bpf_loop(PULSE_TOK_DIR_DEPTH, pulse_tok_walk_step, &walk, 0);
    if (!walk.done)
        pulse_tok_stat(1);              /* deeper than PULSE_TOK_DIR_DEPTH */
    return walk.result;
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
        tok |= PULSE_TOK_KIND_OPEN | (pulse_tok_dir_of_fd(ret) & PULSE_TOK_DIR_MASK) |
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

#endif
