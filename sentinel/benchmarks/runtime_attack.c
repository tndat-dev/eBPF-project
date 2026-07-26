// Safe, in-container syscall workload generator for end-to-end validation.
//
// It emits the kernel behavior associated with each evaluation scenario but
// never opens a remote shell, mounts a filesystem, changes privileges, mines,
// or transmits data. Potentially destructive syscalls use deliberately invalid
// arguments; Tetragon still observes the attempted syscall at entry.
#define _GNU_SOURCE

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
#include <arpa/inet.h>

static volatile sig_atomic_t keep_running = 1;

static void stop_handler(int signo) {
    (void)signo;
    keep_running = 0;
}

static void local_failed_connect(void) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return;
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(9), // discard port; normally closed in the pod
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    (void)connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
}

static void short_child(void) {
    pid_t pid = fork();
    if (pid == 0) {
        char *const argv[] = {"/bin/true", NULL};
        char *const envp[] = {NULL};
        execve(argv[0], argv, envp);
        _exit(127);
    }
    if (pid > 0) (void)waitpid(pid, NULL, 0);
}

static void reverse_shell_signals(unsigned long iteration) {
    local_failed_connect();
    if ((iteration % 4UL) == 0) short_child();
}

static void escape_signals(unsigned long iteration) {
    // Invalid flag bits and missing paths guarantee these attempts do not
    // create a namespace or mount anything.
    (void)syscall(SYS_unshare, ~0UL);
    (void)mount("sentinel-missing", "/sentinel-missing", "sentinel-none",
                MS_RDONLY, NULL);
    (void)ptrace(PTRACE_ATTACH, (pid_t)-1, NULL, NULL);
    if ((iteration % 4UL) == 0) short_child();
}

static void cryptomining_signals(unsigned long iteration) {
    volatile uint64_t x = iteration + 0x9e3779b97f4a7c15ULL;
    for (int i = 0; i < 50000; ++i) x = (x ^ (x >> 12)) * 0x2545f4914f6cdd1dULL;
    (void)x;
    short_child();
}

static void privilege_signals(void) {
    // Setting the current IDs is a no-op. An invalid capability ABI version
    // makes capset fail without changing this process' capability set.
    volatile int rc = setuid(getuid());
    rc |= setgid(getgid());
    struct __user_cap_header_struct hdr = {.version = 0, .pid = 0};
    struct __user_cap_data_struct data[2] = {{0}};
    (void)syscall(SYS_capset, &hdr, &data);
    (void)rc;
}

static void exfiltration_signals(void) {
    char buffer[512];
    int in = openat(AT_FDCWD, "/etc/passwd", O_RDONLY | O_CLOEXEC);
    if (in >= 0) {
        while (read(in, buffer, sizeof(buffer)) > 0) { }
        close(in);
    }
    local_failed_connect();
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s MODE [SECONDS] [RATE_PER_SECOND]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    int seconds = argc > 2 ? atoi(argv[2]) : 70;
    int rate = argc > 3 ? atoi(argv[3]) : 20;
    if (seconds < 1 || seconds > 600 || rate < 1 || rate > 100) return 2;

    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000000L / rate};
    time_t deadline = time(NULL) + seconds;
    unsigned long iteration = 0;
    fprintf(stderr, "sentinel-runtime-attack start mode=%s seconds=%d rate=%d\n",
            mode, seconds, rate);

    while (keep_running && time(NULL) < deadline) {
        if (strcmp(mode, "reverse_shell") == 0) {
            reverse_shell_signals(iteration);
        } else if (strcmp(mode, "container_escape") == 0) {
            escape_signals(iteration);
        } else if (strcmp(mode, "cryptomining") == 0) {
            cryptomining_signals(iteration);
        } else if (strcmp(mode, "privilege_escalation") == 0) {
            privilege_signals();
        } else if (strcmp(mode, "data_exfiltration") == 0) {
            exfiltration_signals();
        } else {
            fprintf(stderr, "unknown mode: %s\n", mode);
            return 2;
        }
        ++iteration;
        nanosleep(&pause, NULL);
    }

    fprintf(stderr, "sentinel-runtime-attack done mode=%s iterations=%lu\n",
            mode, iteration);
    return 0;
}
