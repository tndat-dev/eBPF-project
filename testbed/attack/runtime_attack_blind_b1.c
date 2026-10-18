// Frozen successor blind-set syscall generator for Sentinel Pulse B1.
//
// This source intentionally excludes every A2 scenario and implementation.
// Each operation is process-local or guaranteed to fail before changing host,
// namespace, credential, filesystem, or network state. It must never be used
// for training, calibration, threshold selection, or post-hoc policy tuning.
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
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

static void anonymous_mprotect_churn(void) {
    const size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    void *page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return;
    ((volatile unsigned char *)page)[0] = (unsigned char)next_random();
    (void)mprotect(page, page_size, PROT_READ);
    (void)mprotect(page, page_size, PROT_READ | PROT_WRITE);
    (void)munmap(page, page_size);
}

static void child_ptrace_handshake(void) {
    pid_t child = fork();
    if (child == 0) {
        // PTRACE_TRACEME affects this short-lived child only; no other process
        // is inspected and no payload is read or persisted.
        (void)ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        _exit(0);
    }
    if (child > 0) (void)waitpid(child, NULL, 0);
}

static void invalid_setns_burst(void) {
    // EBADF is guaranteed: no namespace transition can succeed.
    (void)syscall(SYS_setns, -1, 0);
    (void)syscall(SYS_setns, -1, CLONE_NEWNET);
}

static void seccomp_api_probe(void) {
    // An unsupported operation is rejected with EINVAL before state changes.
    (void)syscall(SYS_seccomp, UINT32_MAX, 0U, NULL);
    (void)syscall(SYS_seccomp, UINT32_MAX - 1U, 0U, NULL);
}

static void execveat_resolution_probe(void) {
    char *const argv[] = {(char *)"sentinel-absent", NULL};
    char *const envp[] = {NULL};
    // Invalid dirfd plus a relative absent path guarantees no image change.
    (void)syscall(SYS_execveat, -1, "sentinel-absent", argv, envp, 0);
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
    const long interval_ns = 1000000000L / rate;
    const struct timespec pause = {
        .tv_sec = interval_ns / 1000000000L,
        .tv_nsec = interval_ns % 1000000000L,
    };
    const time_t deadline = time(NULL) + seconds;
    unsigned long iterations = 0;
    fprintf(stderr,
            "sentinel-runtime-attack start mode=%s seconds=%d rate=%d seed=%lu\n",
            mode, seconds, rate, seed);

    while (running && time(NULL) < deadline) {
        if (strcmp(mode, "anonymous_mprotect_churn") == 0)
            anonymous_mprotect_churn();
        else if (strcmp(mode, "child_ptrace_handshake") == 0)
            child_ptrace_handshake();
        else if (strcmp(mode, "invalid_setns_burst") == 0)
            invalid_setns_burst();
        else if (strcmp(mode, "seccomp_api_probe") == 0)
            seccomp_api_probe();
        else if (strcmp(mode, "execveat_resolution_probe") == 0)
            execveat_resolution_probe();
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
