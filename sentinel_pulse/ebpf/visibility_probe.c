// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int self_cgroup(uint64_t *id)
{
    char line[4096], path[4200];
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f) return -1;
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "0::/", 4)) continue;
        line[strcspn(line, "\n")] = 0;
        snprintf(path, sizeof(path), "/sys/fs/cgroup%s", line + 3);
        struct stat st;
        if (stat(path, &st) == 0) { *id = st.st_ino; found = 1; }
        break;
    }
    fclose(f);
    return found ? 0 : -1;
}

static int snapshot(int fd, int cpus, uint64_t counts[6])
{
    uint64_t *per_cpu = calloc((size_t)cpus, sizeof(uint64_t));
    if (!per_cpu) return -1;
    for (uint32_t key = 0; key < 6; key++) {
        if (bpf_map_lookup_elem(fd, &key, per_cpu)) { free(per_cpu); return -1; }
        counts[key] = 0;
        for (int cpu = 0; cpu < cpus; cpu++) counts[key] += per_cpu[cpu];
    }
    free(per_cpu);
    return 0;
}

static int fixture(void)
{
    /* Filter only this child. Never weaken a pod/node security profile. */
    struct sock_filter insns[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xc000003eU, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_setns, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_seccomp, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    };
    struct sock_fprog program = {.len = sizeof(insns)/sizeof(insns[0]), .filter = insns};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) return 2;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return 3;
    void *page = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (page == MAP_FAILED) return 3;
    int setns_denied = 0, seccomp_denied = 0, mprotect_ok = 0;
    for (int i = 0; i < 20; i++) {
        errno = 0;
        if (syscall(SYS_setns, -1, 0) == -1 && errno == EPERM) setns_denied++;
        errno = 0;
        if (syscall(SYS_seccomp, UINT32_MAX, 0U, NULL) == -1 && errno == EPERM) seccomp_denied++;
        if (mprotect(page, (size_t)page_size, PROT_READ) == 0) mprotect_ok++;
        if (mprotect(page, (size_t)page_size, PROT_READ | PROT_WRITE) == 0) mprotect_ok++;
    }
    munmap(page, (size_t)page_size);
    printf("{\"schema\":\"pulse-visibility-fixture-v1\",\"setns_errno_eperm\":%d,\"seccomp_errno_eperm\":%d,\"mprotect_success\":%d}\n",
           setns_denied, seccomp_denied, mprotect_ok);
    fflush(stdout);
    return setns_denied == 20 && seccomp_denied == 20 && mprotect_ok == 40 ? 0 : 4;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    uint64_t cgroup;
    if (self_cgroup(&cgroup)) return 2;
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    struct bpf_object *object = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(object)) return 5;
    int rc = 5;
    struct bpf_link *enter = NULL, *exit = NULL;
    if (bpf_object__load(object)) goto done;
    int target = bpf_object__find_map_fd_by_name(object, "visibility_target");
    int counters = bpf_object__find_map_fd_by_name(object, "visibility_counts");
    uint32_t zero = 0;
    if (target < 0 || counters < 0 || bpf_map_update_elem(target, &zero, &cgroup, BPF_ANY)) goto done;
    struct bpf_program *p = bpf_object__find_program_by_name(object, "visibility_enter");
    enter = p ? bpf_program__attach_raw_tracepoint(p, "sys_enter") : NULL;
    if (!enter || libbpf_get_error(enter)) { enter = NULL; goto done; }
    p = bpf_object__find_program_by_name(object, "visibility_seccomp_exit");
    exit = p ? bpf_program__attach_trace(p) : NULL;
    if (!exit || libbpf_get_error(exit)) { exit = NULL; goto done; }
    int cpus = libbpf_num_possible_cpus();
    uint64_t before[6], after[6];
    if (cpus < 1 || snapshot(counters, cpus, before)) goto done;
    pid_t child = fork();
    if (child < 0) goto done;
    if (child == 0) _exit(fixture());
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) goto done;
    if (snapshot(counters, cpus, after)) goto done;
    for (int i = 0; i < 6; i++) after[i] -= before[i];
    printf("{\"schema\":\"pulse-visibility-probe-v1\",\"cgroup_id\":%llu,\"raw_sys_enter\":{\"mprotect\":%llu,\"setns\":%llu,\"seccomp\":%llu},\"seccomp_skipped_or_emulated\":{\"mprotect\":%llu,\"setns\":%llu,\"seccomp\":%llu},\"not_frozen_candidate_input\":true}\n",
           (unsigned long long)cgroup, (unsigned long long)after[0], (unsigned long long)after[1],
           (unsigned long long)after[2], (unsigned long long)after[3], (unsigned long long)after[4],
           (unsigned long long)after[5]);
    rc = after[0] == 40 && after[1] == 0 && after[2] == 0 && after[3] == 0 && after[4] == 20 && after[5] == 20 ? 0 : 6;
done:
    bpf_link__destroy(exit); bpf_link__destroy(enter); bpf_object__close(object);
    return rc;
}
