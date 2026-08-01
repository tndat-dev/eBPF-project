// SPDX-License-Identifier: GPL-2.0
/* Explicit-PID libbpf loader: never attaches to every host TLS process. */
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MCP_MAX_CAPTURE 512
struct mcp_tls_event { uint64_t ts_ns; uint32_t pid, tid, len; uint8_t direction; char comm[16]; char payload[MCP_MAX_CAPTURE]; };
static volatile sig_atomic_t exiting;
static int emit_payload;
static void stop(int signal_number) { (void)signal_number; exiting = 1; }
static void hex_encode(const char *input, size_t length, char *output) {
    static const char hex[] = "0123456789abcdef";
    for (size_t index = 0; index < length; index++) {
        unsigned char value = (unsigned char)input[index];
        output[index * 2] = hex[value >> 4];
        output[index * 2 + 1] = hex[value & 15];
    }
    output[length * 2] = '\0';
}
static int event(void *context, void *data, size_t size) {
    const struct mcp_tls_event *item = data;
    (void)context;
    if (size < sizeof(*item)) return 0;
    if (!emit_payload) {
        /* Metadata only: plaintext is never written to logs by default. */
        printf("ts_ns=%llu pid=%u direction=%s bytes=%u comm=%.*s\n",
        (unsigned long long)item->ts_ns, item->pid,
        item->direction == 1 ? "write" : "read", item->len, 16, item->comm);
    } else {
        char payload_hex[MCP_MAX_CAPTURE * 2 + 1];
        size_t capture_len = item->len > MCP_MAX_CAPTURE ? MCP_MAX_CAPTURE : item->len;
        hex_encode(item->payload, capture_len, payload_hex);
        /* Explicit controlled-PID mode only; pipe directly to ring_reader.py. */
        printf("{\"ts_ns\":%llu,\"pid\":%u,\"direction\":\"%s\",\"payload_hex\":\"%s\"}\n",
            (unsigned long long)item->ts_ns, item->pid,
            item->direction == 1 ? "write" : "read", payload_hex);
    }
    fflush(stdout);
    return 0;
}
int main(int argc, char **argv) {
    const char *object_path = NULL, *libssl_path = NULL;
    pid_t pid = 0; struct bpf_object *object; struct bpf_program *program;
    struct bpf_link *links[2] = {NULL, NULL}; struct ring_buffer *buffer = NULL; int error = 0;
    struct bpf_uprobe_opts uprobe_opts = {
        .sz = sizeof(uprobe_opts),
        .func_name = "SSL_write",
    };
    for (int index = 1; index < argc; index++) {
        if (!strcmp(argv[index], "--object") && index + 1 < argc) object_path = argv[++index];
        else if (!strcmp(argv[index], "--libssl") && index + 1 < argc) libssl_path = argv[++index];
        else if (!strcmp(argv[index], "--pid") && index + 1 < argc) pid = (pid_t)strtol(argv[++index], NULL, 10);
        else if (!strcmp(argv[index], "--emit-payload")) emit_payload = 1;
        else { fprintf(stderr, "usage: %s --object PATH --libssl PATH --pid PID [--emit-payload]\n", argv[0]); return 2; }
    }
    if (!object_path || !libssl_path || pid <= 0) return 2;
    signal(SIGINT, stop); signal(SIGTERM, stop);
    object = bpf_object__open_file(object_path, NULL); error = libbpf_get_error(object);
    if (error) { fprintf(stderr, "open: %s\n", strerror(-error)); return 1; }
    if ((error = bpf_object__load(object))) goto cleanup;
    program = bpf_object__find_program_by_name(object, "probe_ssl_write");
    if (!program) { error = -ENOENT; goto cleanup; }
    links[0] = bpf_program__attach_uprobe_opts(program, pid, libssl_path, 0, &uprobe_opts);
    error = libbpf_get_error(links[0]); if (error) { links[0] = NULL; goto cleanup; }
    uprobe_opts.func_name = "SSL_write_ex";
    program = bpf_object__find_program_by_name(object, "probe_ssl_write_ex");
    if (!program) { error = -ENOENT; goto cleanup; }
    links[1] = bpf_program__attach_uprobe_opts(program, pid, libssl_path, 0, &uprobe_opts);
    error = libbpf_get_error(links[1]); if (error) { links[1] = NULL; goto cleanup; }
    buffer = ring_buffer__new(bpf_object__find_map_fd_by_name(object, "mcp_events"), event, NULL, NULL);
    error = libbpf_get_error(buffer); if (error) { buffer = NULL; goto cleanup; }
    fprintf(stderr, "attached to controlled pid=%d; Ctrl-C to stop\n", pid);
    while (!exiting && (error = ring_buffer__poll(buffer, 250)) >= 0) {}
    if (error == -EINTR) error = 0;
cleanup:
    ring_buffer__free(buffer); bpf_link__destroy(links[1]); bpf_link__destroy(links[0]); bpf_object__close(object);
    if (error) fprintf(stderr, "probe: %s\n", strerror(-error));
    return error ? 1 : 0;
}
