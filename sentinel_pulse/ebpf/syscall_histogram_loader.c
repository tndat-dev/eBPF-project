// SPDX-License-Identifier: GPL-2.0
/* Bounded userspace sampler for syscall_histogram.bpf.c. */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define MAX_TARGETS 2048
#define MAX_SYSCALL_ID 1024
#define SNAPSHOT_RETRIES 8

struct histogram_key {
    uint64_t cgroup_id;
    uint32_t syscall_id;
    uint32_t padding;
};

static volatile sig_atomic_t exiting;
static void stop(int signal_number) { (void)signal_number; exiting = 1; }

static double wall_time(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_REALTIME, &value) != 0) return 0.0;
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

static int read_targets(const char *path, uint64_t *ids, size_t *count)
{
    FILE *file = fopen(path, "r");
    if (!file) return -errno;
    *count = 0;
    char line[128];
    while (fgets(line, sizeof(line), file)) {
        char *end = NULL;
        errno = 0;
        unsigned long long parsed = strtoull(line, &end, 10);
        if (errno || end == line || parsed == 0) continue;
        uint64_t id = (uint64_t)parsed;
        size_t index;
        for (index = 0; index < *count; index++)
            if (ids[index] == id) break;
        if (index != *count) continue;
        if (*count == MAX_TARGETS) { fclose(file); return -E2BIG; }
        ids[(*count)++] = id;
    }
    fclose(file);
    return 0;
}

static int update_targets(int fd, const uint64_t *ids, size_t count)
{
    uint8_t present = 1;
    for (size_t i = 0; i < count; i++)
        if (bpf_map_update_elem(fd, &ids[i], &present, BPF_ANY) != 0)
            return -errno;
    uint64_t stale[MAX_TARGETS];
    size_t stale_count = 0;
    uint64_t key = 0, next = 0;
    int has_key = 0;
    while (bpf_map_get_next_key(fd, has_key ? &key : NULL, &next) == 0) {
        int keep = 0;
        for (size_t i = 0; i < count; i++)
            if (ids[i] == next) { keep = 1; break; }
        if (!keep && stale_count < MAX_TARGETS) stale[stale_count++] = next;
        key = next;
        has_key = 1;
    }
    for (size_t i = 0; i < stale_count; i++)
        if (bpf_map_delete_elem(fd, &stale[i]) != 0 && errno != ENOENT)
            return -errno;
    return (int)count;
}

static int target_index(const uint64_t *ids, size_t count, uint64_t id)
{
    for (size_t i = 0; i < count; i++)
        if (ids[i] == id) return (int)i;
    return -1;
}

static int previous_target_index(const uint64_t *ids, size_t count, uint64_t id)
{
    return target_index(ids, count, id);
}

static int snapshot(int map_fd, int cpu_count, const uint64_t *ids,
                    size_t target_count, uint64_t *previous,
                    const uint64_t *previous_ids, size_t previous_count,
                    double window_start,
                    uint64_t *entry_count, uint64_t *next_previous)
{
    size_t cells = target_count * MAX_SYSCALL_ID;
    uint64_t *current = calloc(cells, sizeof(*current));
    uint64_t *per_cpu = calloc((size_t)cpu_count, sizeof(*per_cpu));
    if (!current || !per_cpu) { free(current); free(per_cpu); return -ENOMEM; }

    uint64_t key_storage[2] = {0, 0};
    struct histogram_key *key = (struct histogram_key *)key_storage;
    struct histogram_key next_key;
    int has_key = 0;
    *entry_count = 0;
    double snapshot_started_at = wall_time();
    while (bpf_map_get_next_key(map_fd, has_key ? key : NULL, &next_key) == 0) {
        key_storage[0] = next_key.cgroup_id;
        key_storage[1] = ((uint64_t)next_key.syscall_id) |
                         ((uint64_t)next_key.padding << 32);
        has_key = 1;
        int index = target_index(ids, target_count, next_key.cgroup_id);
        if (index < 0 || next_key.syscall_id >= MAX_SYSCALL_ID) continue;
        int found = 0;
        for (int attempt = 0; attempt < SNAPSHOT_RETRIES; attempt++) {
            memset(per_cpu, 0, (size_t)cpu_count * sizeof(*per_cpu));
            if (bpf_map_lookup_elem(map_fd, &next_key, per_cpu) == 0) {
                found = 1;
                break;
            }
            if (errno != ENOENT) { free(current); free(per_cpu); return -errno; }
        }
        if (!found) continue;
        uint64_t sum = 0;
        for (int cpu = 0; cpu < cpu_count; cpu++) sum += per_cpu[cpu];
        current[(size_t)index * MAX_SYSCALL_ID + next_key.syscall_id] = sum;
        (*entry_count)++;
    }
    double window_end = wall_time();
    double snapshot_scan_seconds = window_end - snapshot_started_at;

    for (size_t target = 0; target < target_count; target++) {
        int first = 1;
        int old_target = previous_target_index(previous_ids, previous_count, ids[target]);
        printf("{\"schema\":\"sentinel-pulse-syscall-id-histogram-v1\","
               "\"type\":\"interval\",\"window_start\":%.9f,"
               "\"window_end\":%.9f,\"snapshot_scan_seconds\":%.9f,"
               "\"cgroup_id\":%llu,\"counts\":{",
               window_start, window_end, snapshot_scan_seconds,
               (unsigned long long)ids[target]);
        for (uint32_t syscall_id = 0; syscall_id < MAX_SYSCALL_ID; syscall_id++) {
            size_t cell = target * MAX_SYSCALL_ID + syscall_id;
            size_t old_cell = old_target < 0 ? 0 :
                (size_t)old_target * MAX_SYSCALL_ID + syscall_id;
            uint64_t old_value = old_target < 0 ? 0 : previous[old_cell];
            uint64_t delta = current[cell] >= old_value ?
                             current[cell] - old_value : current[cell];
            if (delta) {
                printf("%s\"%u\":%llu", first ? "" : ",", syscall_id,
                       (unsigned long long)delta);
                first = 0;
            }
            next_previous[cell] = current[cell];
        }
        printf("},\"map_entries\":%llu}\n", (unsigned long long)*entry_count);
    }
    free(current);
    free(per_cpu);
    return 0;
}

int main(int argc, char **argv)
{
    const char *object_path = NULL, *allow_file = NULL;
    unsigned interval_ms = 1000;
    unsigned duration_seconds = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--object") && i + 1 < argc) object_path = argv[++i];
        else if (!strcmp(argv[i], "--allow-cgroup-file") && i + 1 < argc) allow_file = argv[++i];
        else if (!strcmp(argv[i], "--interval-ms") && i + 1 < argc) interval_ms = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--duration-seconds") && i + 1 < argc) duration_seconds = (unsigned)strtoul(argv[++i], NULL, 10);
        else { fprintf(stderr, "usage: %s --object PATH --allow-cgroup-file PATH [--interval-ms 1000]\n", argv[0]); return 2; }
    }
    if (!object_path || !allow_file || interval_ms < 500 || interval_ms > 60000 ||
        duration_seconds == 0 || duration_seconds > 86400) return 2;
    struct utsname platform;
    if (uname(&platform) != 0 || strcmp(platform.machine, "x86_64") != 0) {
        fprintf(stderr, "refusing non-x86_64 host; syscall ID mapping is native x86-64 only\n");
        return 2;
    }
    signal(SIGINT, stop); signal(SIGTERM, stop); libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    int cpu_count = libbpf_num_possible_cpus();
    if (cpu_count <= 0) return 1;

    struct bpf_object *object = bpf_object__open_file(object_path, NULL);
    int error = libbpf_get_error(object);
    if (error) { fprintf(stderr, "open BPF object: %s\n", strerror(-error)); return 1; }
    if ((error = bpf_object__load(object))) { fprintf(stderr, "load BPF object: %s\n", strerror(-error)); bpf_object__close(object); return 1; }
    int targets_fd = bpf_object__find_map_fd_by_name(object, "histogram_targets");
    int histogram_fd = bpf_object__find_map_fd_by_name(object, "syscall_histogram");
    int stats_fd = bpf_object__find_map_fd_by_name(object, "histogram_stats");
    if (targets_fd < 0 || histogram_fd < 0 || stats_fd < 0) { bpf_object__close(object); return 1; }

    uint64_t ids[MAX_TARGETS];
    size_t target_count = 0;
    if ((error = read_targets(allow_file, ids, &target_count)) != 0 || target_count == 0) {
        fprintf(stderr, "invalid/empty target list: %s\n", error ? strerror(-error) : "empty");
        bpf_object__close(object); return 1;
    }
    if ((error = update_targets(targets_fd, ids, target_count)) < 0) {
        fprintf(stderr, "populate targets: %s\n", strerror(-error)); bpf_object__close(object); return 1;
    }
    struct bpf_program *program = bpf_object__find_program_by_name(object, "histogram_sys_enter");
    struct bpf_link *link = program ? bpf_program__attach_raw_tracepoint(program, "sys_enter") : NULL;
    error = libbpf_get_error(link);
    if (!program || error) {
        fprintf(stderr, "attach syscall histogram: %s\n", program ? strerror(-error) : "missing program");
        bpf_object__close(object); return 1;
    }
    fprintf(stderr, "isolated syscall-ID histogram attached; interval=%ums duration=%us targets=%zu cpus=%d map_cap=%u\n",
            interval_ms, duration_seconds, target_count, cpu_count, 65536U);

    uint64_t *previous = calloc((size_t)MAX_TARGETS * MAX_SYSCALL_ID, sizeof(*previous));
    uint64_t *next_previous = calloc((size_t)MAX_TARGETS * MAX_SYSCALL_ID, sizeof(*next_previous));
    uint64_t *per_cpu_drops = calloc((size_t)cpu_count, sizeof(*per_cpu_drops));
    uint64_t previous_ids[MAX_TARGETS];
    size_t previous_count = 0;
    if (!previous || !next_previous || !per_cpu_drops) { free(previous); free(next_previous); free(per_cpu_drops); bpf_link__destroy(link); bpf_object__close(object); return 1; }
    double previous_at = wall_time();
    time_t monotonic_start = time(NULL);
    while (!exiting && time(NULL) - monotonic_start < (time_t)duration_seconds) {
        usleep(interval_ms * 1000U);
        if (exiting) break;
        if ((error = read_targets(allow_file, ids, &target_count)) != 0 || target_count == 0) {
            fprintf(stderr, "target refresh failed; stopping: %s\n", error ? strerror(-error) : "empty");
            break;
        }
        if ((error = update_targets(targets_fd, ids, target_count)) < 0) {
            fprintf(stderr, "target map refresh failed: %s\n", strerror(-error)); break;
        }
        double now = wall_time();
        uint64_t entries = 0;
        memset(next_previous, 0, (size_t)MAX_TARGETS * MAX_SYSCALL_ID * sizeof(*next_previous));
        error = snapshot(histogram_fd, cpu_count, ids, target_count, previous,
                         previous_ids, previous_count, previous_at,
                         &entries, next_previous);
        if (error) { fprintf(stderr, "histogram snapshot failed: %s\n", strerror(-error)); break; }
        now = wall_time();
        memcpy(previous, next_previous,
               (size_t)MAX_TARGETS * MAX_SYSCALL_ID * sizeof(*previous));
        memcpy(previous_ids, ids, target_count * sizeof(*ids));
        previous_count = target_count;
        memset(per_cpu_drops, 0, (size_t)cpu_count * sizeof(*per_cpu_drops));
        uint32_t zero = 0;
        if (bpf_map_lookup_elem(stats_fd, &zero, per_cpu_drops) != 0) { fprintf(stderr, "drop counter lookup failed\n"); break; }
        uint64_t drops = 0;
        for (int cpu = 0; cpu < cpu_count; cpu++) drops += per_cpu_drops[cpu];
        printf("{\"schema\":\"sentinel-pulse-syscall-id-histogram-v1\",\"type\":\"integrity\",\"observed_at\":%.9f,\"window_start\":%.9f,\"interval_seconds\":%.9f,\"target_count\":%zu,\"map_entries\":%llu,\"dropped_updates\":%llu}\n",
               now, previous_at, now - previous_at, target_count,
               (unsigned long long)entries, (unsigned long long)drops);
        fflush(stdout);
        previous_at = now;
    }
    free(previous); free(next_previous); free(per_cpu_drops); bpf_link__destroy(link); bpf_object__close(object);
    return 0;
}
