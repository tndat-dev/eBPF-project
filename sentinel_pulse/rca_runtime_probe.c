/* Isolated observability fixture: never run inside an AIMS workload. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void receipt(const char *operation, long result, int error) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    printf("{\"operation\":\"%s\",\"kernel_return\":%ld,\"at\":%lld.%09ld}\n",
           operation, result < 0 ? -(long)error : result,
           (long long)now.tv_sec, now.tv_nsec);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        receipt("child_exec", 0, 0);
        return 3;
    }
    if (geteuid() == 0) {
        fputs("fixture requires a non-root isolated validation pod\n", stderr);
        return 64;
    }
    long result = syscall(SYS_openat, AT_FDCWD, "/proof/sentinel-rca-proof.txt",
                          O_CREAT | O_EXCL | O_WRONLY, 0600);
    int error = errno;
    receipt("open_file", result, error);
    if (result < 0) return 65;
    int fd = (int)result;
    usleep(650000);
    result = write(fd, "RCA-proof\n", 10); error = errno;
    receipt("write_file", result, error);
    close(fd);
    usleep(650000);
    result = syscall(SYS_openat, AT_FDCWD, "/proof/not-existing", O_RDONLY, 0); error = errno;
    receipt("open_missing", result, error);
    if (result >= 0) close((int)result);
    result = syscall(SYS_setuid, getuid()); error = errno;
    receipt("setuid_same", result, error);
    result = syscall(SYS_setgid, getgid()); error = errno;
    receipt("setgid_same", result, error);
    result = syscall(SYS_setuid, 0); error = errno;
    receipt("setuid_denied", result, error);
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    result = syscall(SYS_capset, &header, caps); error = errno;
    receipt("capset_empty", result, error);
    result = syscall(SYS_unshare, 0); error = errno;
    receipt("unshare_zero", result, error);
    result = syscall(SYS_unshare, CLONE_NEWNET); error = errno;
    receipt("unshare_denied", result, error);
    result = syscall(SYS_setns, -1, CLONE_NEWNET); error = errno;
    receipt("setns_invalid", result, error);
    result = syscall(SYS_mount, "none", "/proof/not-a-mount", "tmpfs", 0, NULL); error = errno;
    receipt("mount_denied", result, error);
    result = syscall(SYS_ptrace, PTRACE_ATTACH, 2147483647, NULL, NULL); error = errno;
    receipt("ptrace_missing", result, error);
    pid_t child = fork();
    if (child == 0) {
        execl("/proc/self/exe", "rca-runtime-probe", "--child", (char *)NULL);
        _exit(66);
    }
    if (child < 0) return 67;
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 68;
    receipt("child_wait_status", WIFEXITED(status) ? WEXITSTATUS(status) : 255, 0);
    result = syscall(SYS_unlinkat, AT_FDCWD, "/proof/sentinel-rca-proof.txt", 0); error = errno;
    receipt("unlink_file", result, error);
    return WIFEXITED(status) && WEXITSTATUS(status) == 3 ? 0 : 69;
}
