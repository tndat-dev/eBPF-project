// Frozen blind-set syscall generator for AIMS evaluation.
//
// This is intentionally a different implementation and scenario set from
// runtime_attack.c. It is safe by construction: no external destination,
// successful mount, privilege change, payload exfiltration, or persistent
// write is performed. Seed changes ordering/ports, not safety boundaries.
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;
static uint64_t rng_state = 1;

static void stop_handler(int signo) {
    (void)signo;
    running = 0;
}

static uint32_t next_random(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)rng_state;
}

static void loopback_probe(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return;
    struct sockaddr_in destination = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    (void)connect(fd, (struct sockaddr *)&destination, sizeof(destination));
    close(fd);
}

static void child_fanout(unsigned count) {
    for (unsigned i = 0; i < count; ++i) {
        pid_t pid = fork();
        if (pid == 0) {
            volatile uint64_t value = next_random();
            for (unsigned j = 0; j < 2000; ++j)
                value = (value << 5) ^ (value >> 3) ^ j;
            _exit((int)(value & 0U));
        }
        if (pid > 0) (void)waitpid(pid, NULL, 0);
    }
}

static void local_socket_beacon(void) {
    // IANA discard-range style local ports only; no packet leaves the pod.
    loopback_probe((uint16_t)(9 + (next_random() % 8U)));
    if ((next_random() & 3U) == 0U) child_fanout(1);
}

static void namespace_probe(void) {
    (void)syscall(SYS_unshare, ~0UL);  // invalid bits: guaranteed failure
    (void)mount("sentinel-absent-source", "/sentinel-absent-target",
                "sentinel-invalid-fs", MS_RDONLY, NULL);
    (void)ptrace(PTRACE_ATTACH, (pid_t)-1, NULL, NULL);
}

static void process_fanout(void) {
    child_fanout(1U + (next_random() % 3U));
}

static void identity_transition_probe(void) {
    // Current IDs are no-ops; invalid capability ABI cannot change caps.
    volatile int result = setresuid(getuid(), getuid(), getuid());
    result |= setresgid(getgid(), getgid(), getgid());
    struct __user_cap_header_struct header = {.version = 0, .pid = 0};
    struct __user_cap_data_struct data[2] = {{0}};
    result |= (int)syscall(SYS_capset, &header, &data);
    (void)result;
}

static void read_path(const char *path) {
    char buffer[257];
    int fd = openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    while (read(fd, buffer, sizeof(buffer)) > 0) { }
    close(fd);
}

static void credential_read_burst(void) {
    // Public local metadata only; bytes are discarded and never transmitted.
    read_path("/etc/passwd");
    read_path("/proc/self/status");
    loopback_probe((uint16_t)(19 + (next_random() % 8U)));
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s MODE [SECONDS] [RATE] [SEED]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    int seconds = argc > 2 ? atoi(argv[2]) : 45;
    int rate = argc > 3 ? atoi(argv[3]) : 12;
    unsigned long seed = argc > 4 ? strtoul(argv[4], NULL, 10) : 1UL;
    if (seconds < 1 || seconds > 600 || rate < 1 || rate > 100) return 2;
    rng_state = seed ? seed : 1UL;

    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);
    long interval_ns = 1000000000L / rate;
    struct timespec pause = {
        .tv_sec = interval_ns / 1000000000L,
        .tv_nsec = interval_ns % 1000000000L,
    };
    time_t deadline = time(NULL) + seconds;
    unsigned long iterations = 0;
    fprintf(stderr,
            "sentinel-runtime-attack start mode=%s seconds=%d rate=%d seed=%lu\n",
            mode, seconds, rate, seed);

    while (running && time(NULL) < deadline) {
        if (strcmp(mode, "local_socket_beacon") == 0)
            local_socket_beacon();
        else if (strcmp(mode, "namespace_probe") == 0)
            namespace_probe();
        else if (strcmp(mode, "process_fanout") == 0)
            process_fanout();
        else if (strcmp(mode, "identity_transition_probe") == 0)
            identity_transition_probe();
        else if (strcmp(mode, "credential_read_burst") == 0)
            credential_read_burst();
        else {
            fprintf(stderr, "unknown mode: %s\n", mode);
            return 2;
        }
        ++iterations;
        nanosleep(&pause, NULL);
    }
    fprintf(stderr, "sentinel-runtime-attack done mode=%s iterations=%lu\n",
            mode, iterations);
    return 0;
}
