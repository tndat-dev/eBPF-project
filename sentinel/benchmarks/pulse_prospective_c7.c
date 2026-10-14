/* Bounded, process-local research surrogates. No external network, payload
 * recording, persistent writes, mount, credential change or ptrace. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static double now(clockid_t clock) {
    struct timespec t;
    if (clock_gettime(clock, &t)) exit(3);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static void pause_seconds(double seconds) {
    if (seconds <= 0) return;
    struct timespec t = {(time_t)seconds, (long)((seconds - (time_t)seconds) * 1e9)};
    while (nanosleep(&t, &t) && errno == EINTR) {}
}
static void operation(int mode, uint32_t value) {
    int fd[2]; char byte = (char)value; char data[128];
    switch (mode) {
    case 0: /* Local UNIX socket pair; never opens an IP socket. */
        if (!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, fd)) {
            if (send(fd[0], &byte, 1, MSG_DONTWAIT) == 1) (void)recv(fd[1], data, 1, MSG_DONTWAIT);
            close(fd[0]); close(fd[1]);
        }
        break;
    case 1:
        if (!pipe2(fd, O_NONBLOCK | O_CLOEXEC)) {
            struct pollfd p = {fd[0], POLLIN, 0};
            ssize_t write_result = write(fd[1], &byte, 1);
            int poll_result = poll(&p, 1, 0);
            ssize_t read_result = read(fd[0], data, 1);
            (void)write_result; (void)poll_result; (void)read_result;
            close(fd[0]); close(fd[1]);
        }
        break;
    case 2: {
        int file = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
        if (file >= 0) {
            struct stat st;
            int stat_result = fstat(file, &st);
            ssize_t read_result = read(file, data, sizeof(data));
            (void)stat_result; (void)read_result;
            close(file);
        }
        break;
    }
    case 3: {
        void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page != MAP_FAILED) {
            ((volatile unsigned char *)page)[0] = (unsigned char)value;
            (void)mprotect(page, 4096, PROT_READ); (void)mprotect(page, 4096, PROT_READ | PROT_WRITE);
            (void)munmap(page, 4096);
        }
        break;
    }
    case 4:
        /* Invalid fd guarantees no namespace transition succeeds. */
        (void)syscall(SYS_setns, -1, CLONE_NEWNS);
        break;
    }
}
int main(int argc, char **argv) {
    const char *modes[] = {"local_datagram_turnover", "pipe_poll_churn", "readonly_metadata_walk",
                          "anon_page_protection", "invalid_namespace_handle", "control_sleep"};
    if (argc != 5) return 2;
    int mode = -1;
    for (int i = 0; i < 6; ++i) if (!strcmp(argv[1], modes[i])) mode = i;
    int seconds = atoi(argv[2]); int rate = atoi(argv[3]);
    uint32_t seed = (uint32_t)strtoul(argv[4], NULL, 10);
    if (mode < 0 || seconds < 1 || seconds > 30 || rate < 1 || rate > 24 || !seed) return 2;
    double started = now(CLOCK_MONOTONIC), deadline = started + seconds;
    double next_operation = started;
    unsigned long operations = 0;
    fprintf(stderr, "pulse-c7 start scenario=%s wall=%.9f seed=%u\n", argv[1], now(CLOCK_REALTIME), seed);
    while (now(CLOCK_MONOTONIC) < deadline) {
        if (mode == 5) { pause_seconds(.05); continue; }
        seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
        operation(mode, seed);
        ++operations;
        /* One scenario operation per period; slow calls never trigger catch-up bursts. */
        next_operation += 1.0 / rate;
        double current = now(CLOCK_MONOTONIC);
        if (next_operation < current) next_operation = current;
        pause_seconds(next_operation - current);
    }
    fprintf(stderr, "pulse-c7 done wall=%.9f operations=%lu\n", now(CLOCK_REALTIME), operations);
    return 0;
}
