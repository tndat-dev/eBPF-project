// Syscall cost microbenchmark for the Pulse overhead A/B (protocol overhead-ab-v1).
// One mode per run, a fixed number of seconds; prints one JSON line:
//   {"mode": "...", "ops": N, "seconds": S, "ns_per_op": X}
// Modes exercise the raw_tp/sys_enter path with different kernel work behind it:
//   getpid      - near-null syscall: the probe's cost is the largest share here
//   read4k      - read 4 KiB from /dev/zero
//   openclose   - open + close of a file in /tmp (two syscalls per op)
//   mmapunmap   - anonymous 4 KiB mmap + munmap (two syscalls per op)
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);   // vDSO: not a syscall, so it does not perturb the count
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s MODE SECONDS\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    double seconds = atof(argv[2]);
    if (seconds <= 0 || seconds > 600) return 2;
    char buffer[4096];
    char path[64];
    snprintf(path, sizeof path, "/tmp/pulse-bench-%d", (int)getpid());
    int zero = open("/dev/zero", O_RDONLY);
    if (zero < 0) return 1;
    unsigned long long ops = 0;
    double start = now(), stop = start + seconds, t = start;
    while (t < stop) {
        for (int i = 0; i < 1024; i++) {
            if (!strcmp(mode, "getpid")) {
                (void)syscall(SYS_getpid);
            } else if (!strcmp(mode, "read4k")) {
                if (read(zero, buffer, sizeof buffer) != (ssize_t)sizeof buffer) return 1;
            } else if (!strcmp(mode, "openclose")) {
                int fd = open(path, O_CREAT | O_RDWR, 0600);
                if (fd < 0) return 1;
                close(fd);
            } else if (!strcmp(mode, "mmapunmap")) {
                void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (p == MAP_FAILED) return 1;
                munmap(p, 4096);
            } else {
                return 2;
            }
        }
        ops += 1024;
        t = now();
    }
    unlink(path);
    double elapsed = t - start;
    printf("{\"mode\": \"%s\", \"ops\": %llu, \"seconds\": %.6f, \"ns_per_op\": %.3f}\n", mode, ops, elapsed, elapsed * 1e9 / ops);
    return 0;
}
