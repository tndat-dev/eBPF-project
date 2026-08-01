// SPDX-License-Identifier: GPL-2.0
/*
 * Prototype only: MCP TLS uprobe collector for Agent Runtime Sentinel V2.
 *
 * Intended hook points:
 *   - uprobe/libssl:SSL_write(ctx, ssl, buf, num)
 *   - uretprobe/libssl:SSL_read(ctx) paired with saved buf pointer
 *
 * The eBPF program must not parse JSON-RPC. It should copy a bounded byte slice
 * to the ring buffer and let userspace parse MCP semantics.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MCP_MAX_CAPTURE 512

struct mcp_tls_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u32 len;
    __u8 direction; /* 1 = write, 2 = read */
    char comm[16];
    char payload[MCP_MAX_CAPTURE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} mcp_events SEC(".maps");

static __always_inline int submit_tls_buf(const void *buf, __u32 len, __u8 direction)
{
    __u32 copy_len = len;
    if (copy_len > MCP_MAX_CAPTURE) {
        copy_len = MCP_MAX_CAPTURE;
    }

    struct mcp_tls_event *event = bpf_ringbuf_reserve(&mcp_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->ts_ns = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->len = copy_len;
    event->direction = direction;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user(event->payload, copy_len, buf);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("uprobe/SSL_write")
int BPF_KPROBE(probe_ssl_write, void *ssl, const void *buf, int num)
{
    if (!buf || num <= 0) {
        return 0;
    }
    return submit_tls_buf(buf, (__u32)num, 1);
}

/* OpenSSL 3 callers commonly use SSL_write_ex rather than SSL_write. */
SEC("uprobe/SSL_write_ex")
int BPF_KPROBE(probe_ssl_write_ex, void *ssl, const void *buf, __u64 num,
               __u64 *written)
{
    if (!buf || num == 0) {
        return 0;
    }
    return submit_tls_buf(buf, (__u32)num, 1);
}

char LICENSE[] SEC("license") = "GPL";
