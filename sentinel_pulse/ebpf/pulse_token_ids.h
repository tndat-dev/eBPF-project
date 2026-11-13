// SPDX-License-Identifier: GPL-2.0
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
#define PULSE_TF_ERR 1u
#define PULSE_TF_RW 2u
#define PULSE_TF_OPEN_SI 4u
#define PULSE_TF_OPEN_DX 8u
#define PULSE_TF_OPEN_HOW 16u
#define PULSE_TF_OPEN_CREAT 32u
#define PULSE_TF_OPEN (PULSE_TF_OPEN_SI | PULSE_TF_OPEN_DX | PULSE_TF_OPEN_HOW | PULSE_TF_OPEN_CREAT)

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
#define PULSE_TOK_NR_SHIFT 23
#define PULSE_TOK_NR_MAX 511u
#define PULSE_TOK_KIND_SHIFT 21
#define PULSE_TOK_KIND_ERR (1u << PULSE_TOK_KIND_SHIFT)
#define PULSE_TOK_KIND_SIZE (2u << PULSE_TOK_KIND_SHIFT)
#define PULSE_TOK_KIND_OPEN (3u << PULSE_TOK_KIND_SHIFT)
#define PULSE_TOK_OPEN_WRITE (1u << 20)
#define PULSE_TOK_DIR_MASK 0xFFFFFu
#define PULSE_TOK_DIR_REL 0xFFFFEu
#define PULSE_TOK_DIR_UNKNOWN 0xFFFFFu
#define PULSE_TOK_FNV_BASIS 2166136261u
#define PULSE_TOK_FNV_PRIME 16777619u
#define PULSE_TOK_DIR_ROOT (PULSE_TOK_FNV_BASIS & PULSE_TOK_DIR_MASK)
#define PULSE_TOK_NONE 0xFFFFFFFFu
#define PULSE_TOK_WINDOW_NS 500000000ULL
#define PULSE_TOK_DIR_CHARS 64
#define PULSE_TOK_DIR_DEPTH 64   /* dentry levels walked up for the first directory, mount crossings included */
/* O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND (signals.WRITE_FLAGS) */
#define PULSE_TOK_WRITE_FLAGS (01u | 02u | 0100u | 01000u | 02000u)

struct pulse_gram_key {
    __u64 cgroup_id;
    __u32 window;   /* CLOCK_MONOTONIC / 0.5 s at emission */
    __u32 tok[4];   /* oldest first; tok[3] is the token just emitted */
    __u32 pad;      /* the thread's lineage (PULSE_LINEAGE_*); 0 in builds before the lineage tag */
};

/* ml-final-study-v1 amendment 2: telemetry only. Native = the workload's own process tree; session = a process that
 * entered the container through a runtime exec (kubectl exec, an exec probe), and its descendants. */
#define PULSE_LINEAGE_NATIVE 0u
#define PULSE_LINEAGE_SESSION 1u

/* Set by the loader before load (.rodata.tokcfg), so the verifier prunes the disabled paths. Conditions of the
 * overhead A/B: exit-nofutex = B, exit = C, grams = D. */
struct pulse_tok_config {
    __u32 futex_at_exit;   /* futex is a hooked (exit) syscall; otherwise it gives its name at entry */
    __u32 count_grams;     /* update the per-window 4-gram map; otherwise tokens only move the thread history */
};

#endif
