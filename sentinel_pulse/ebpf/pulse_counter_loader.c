// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PULSE_SYSCALL_BINS 64
#define PULSE_TRANSITION_BINS 64
#define PULSE_TRACKED 29
#define PULSE_SNAPSHOT_RETRIES 8

struct pulse_counters {
    uint64_t syscall_bins[PULSE_SYSCALL_BINS];
    uint64_t transition_bins[PULSE_TRANSITION_BINS];
    uint64_t tracked[PULSE_TRACKED];
    uint64_t total;
};

static const uint32_t tracked_ids[PULSE_TRACKED] = {
    0, 1, 2, 3, 9, 10, 41, 42, 43, 44, 45, 56, 59, 90, 101,
    105, 106, 126, 155, 165, 257, 272, 288, 299, 307, 308, 317, 322, 435
};
static volatile sig_atomic_t exiting;
static void stop(int signal_number) { (void)signal_number; exiting = 1; }

static double wall_time(void)
{
    struct timespec value;
    clock_gettime(CLOCK_REALTIME, &value);
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

static int contains(const uint64_t *values, size_t count, uint64_t candidate)
{
    for (size_t index = 0; index < count; index++)
        if (values[index] == candidate) return 1;
    return 0;
}

static int refresh_targets(int map_fd, const char *path, int cpu_count)
{
    FILE *handle = fopen(path, "r");
    if (!handle) return -errno;
    size_t count = 0, capacity = 128;
    uint64_t *desired = calloc(capacity, sizeof(*desired));
    size_t stride = (sizeof(struct pulse_counters) + 7U) & ~7U;
    void *per_cpu = calloc((size_t)cpu_count, stride);
    if (!desired || !per_cpu) { fclose(handle); free(desired); free(per_cpu); return -ENOMEM; }
    char line[128];
    while (fgets(line, sizeof(line), handle)) {
        char *end = NULL;
        errno = 0;
        uint64_t id = strtoull(line, &end, 10);
        if (errno || end == line || id == 0 || contains(desired, count, id)) continue;
        if (count == capacity) {
            capacity *= 2;
            uint64_t *expanded = realloc(desired, capacity * sizeof(*desired));
            if (!expanded) { fclose(handle); free(desired); free(per_cpu); return -ENOMEM; }
            desired = expanded;
        }
        desired[count++] = id;
    }
    fclose(handle);
    if (count == 0) { free(desired); free(per_cpu); return 0; }

    for (size_t index = 0; index < count; index++) {
        if (bpf_map_lookup_elem(map_fd, &desired[index], per_cpu) < 0 &&
            bpf_map_update_elem(map_fd, &desired[index], per_cpu, BPF_NOEXIST) < 0) {
            int error = -errno; free(desired); free(per_cpu); return error;
        }
    }

    size_t existing_count = 0, existing_capacity = count + 64;
    uint64_t *existing = calloc(existing_capacity, sizeof(*existing));
    uint64_t key = 0, next = 0;
    int has_key = 0;
    if (!existing) { free(desired); free(per_cpu); return -ENOMEM; }
    while (bpf_map_get_next_key(map_fd, has_key ? &key : NULL, &next) == 0) {
        if (existing_count == existing_capacity) {
            existing_capacity *= 2;
            uint64_t *expanded = realloc(existing, existing_capacity * sizeof(*existing));
            if (!expanded) { free(existing); free(desired); free(per_cpu); return -ENOMEM; }
            existing = expanded;
        }
        existing[existing_count++] = next;
        key = next; has_key = 1;
    }
    for (size_t index = 0; index < existing_count; index++)
        if (!contains(desired, count, existing[index]))
            bpf_map_delete_elem(map_fd, &existing[index]);
    free(existing); free(desired); free(per_cpu);
    return (int)count;
}

static int per_cpu_snapshot_consistent(
    const unsigned char *per_cpu, int cpu_count, size_t stride)
{
    for (int cpu = 0; cpu < cpu_count; cpu++) {
        const struct pulse_counters *value =
            (const struct pulse_counters *)(per_cpu + (size_t)cpu * stride);
        uint64_t binned = 0;
        for (int bin = 0; bin < PULSE_SYSCALL_BINS; bin++)
            binned += value->syscall_bins[bin];
        if (binned != value->total)
            return 0;
    }
    return 1;
}

static int lookup_consistent_snapshot(
    int map_fd, const uint64_t *key, unsigned char *per_cpu,
    int cpu_count, size_t stride)
{
    for (int attempt = 0; attempt < PULSE_SNAPSHOT_RETRIES; attempt++) {
        memset(per_cpu, 0, (size_t)cpu_count * stride);
        if (bpf_map_lookup_elem(map_fd, key, per_cpu) < 0)
            return -errno;
        /* A map copy can land between the adjacent total and bin writes.
         * Retry that boundary read rather than accepting a distribution that
         * never existed or weakening the integrity gate. */
        if (per_cpu_snapshot_consistent(per_cpu, cpu_count, stride))
            return 0;
    }
    return -EAGAIN;
}

static int print_snapshots(
    int map_fd, int cpu_count, double observed_at,
    uint64_t *consistency_retry_exhausted)
{
    size_t stride = (sizeof(struct pulse_counters) + 7U) & ~7U;
    unsigned char *per_cpu = calloc((size_t)cpu_count, stride);
    if (!per_cpu) return -ENOMEM;
    uint64_t key = 0, next = 0;
    int has_key = 0, printed = 0;
    while (bpf_map_get_next_key(map_fd, has_key ? &key : NULL, &next) == 0) {
        int lookup = lookup_consistent_snapshot(
            map_fd, &next, per_cpu, cpu_count, stride);
        if (lookup == -EAGAIN) {
            (*consistency_retry_exhausted)++;
        } else if (lookup == 0) {
            struct pulse_counters sum = {0};
            for (int cpu = 0; cpu < cpu_count; cpu++) {
                struct pulse_counters *value = (struct pulse_counters *)(per_cpu + (size_t)cpu * stride);
                sum.total += value->total;
                for (int bin = 0; bin < PULSE_SYSCALL_BINS; bin++) sum.syscall_bins[bin] += value->syscall_bins[bin];
                for (int bin = 0; bin < PULSE_TRANSITION_BINS; bin++) sum.transition_bins[bin] += value->transition_bins[bin];
                for (int slot = 0; slot < PULSE_TRACKED; slot++) sum.tracked[slot] += value->tracked[slot];
            }
            printf("{\"type\":\"cgroup_snapshot\",\"observed_at\":%.9f,\"cgroup_id\":%llu,\"total\":%llu,\"counts\":{",
                   observed_at, (unsigned long long)next, (unsigned long long)sum.total);
            for (int slot = 0; slot < PULSE_TRACKED; slot++)
                printf("%s\"%u\":%llu", slot ? "," : "", tracked_ids[slot], (unsigned long long)sum.tracked[slot]);
            printf("},\"syscall_bins\":[");
            for (int bin = 0; bin < PULSE_SYSCALL_BINS; bin++)
                printf("%s%llu", bin ? "," : "", (unsigned long long)sum.syscall_bins[bin]);
            printf("],\"transition_bins\":[");
            for (int bin = 0; bin < PULSE_TRANSITION_BINS; bin++)
                printf("%s%llu", bin ? "," : "", (unsigned long long)sum.transition_bins[bin]);
            printf("]}\n");
            printed++;
        }
        key = next; has_key = 1;
    }
    free(per_cpu);
    return printed;
}

int main(int argc, char **argv)
{
    const char *object_path = NULL, *allow_file = NULL;
    unsigned interval_ms = 1000;
    for (int index = 1; index < argc; index++) {
        if (!strcmp(argv[index], "--object") && index + 1 < argc) object_path = argv[++index];
        else if (!strcmp(argv[index], "--allow-cgroup-file") && index + 1 < argc) allow_file = argv[++index];
        else if (!strcmp(argv[index], "--interval-ms") && index + 1 < argc) interval_ms = (unsigned)strtoul(argv[++index], NULL, 10);
        else { fprintf(stderr, "usage: %s --object PATH --allow-cgroup-file PATH [--interval-ms 1000]\n", argv[0]); return 2; }
    }
    if (!object_path || !allow_file || interval_ms < 100 || interval_ms > 60000) return 2;
    signal(SIGINT, stop); signal(SIGTERM, stop); libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    int cpu_count = libbpf_num_possible_cpus();
    if (cpu_count <= 0) { fprintf(stderr, "cannot determine possible CPUs\n"); return 1; }
    struct bpf_object *object = bpf_object__open_file(object_path, NULL);
    int error = libbpf_get_error(object);
    if (error) { fprintf(stderr, "open BPF object: %s\n", strerror(-error)); return 1; }
    if ((error = bpf_object__load(object))) { fprintf(stderr, "load BPF object: %s\n", strerror(-error)); bpf_object__close(object); return 1; }
    int cgroups_fd = bpf_object__find_map_fd_by_name(object, "pulse_cgroups");
    int stats_fd = bpf_object__find_map_fd_by_name(object, "pulse_stats");
    if (cgroups_fd < 0 || stats_fd < 0) { fprintf(stderr, "required BPF map missing\n"); bpf_object__close(object); return 1; }
    int targets = refresh_targets(cgroups_fd, allow_file, cpu_count);
    if (targets <= 0) { fprintf(stderr, "no valid target cgroup in %s; refusing host-wide collection\n", allow_file); bpf_object__close(object); return 1; }
    struct bpf_program *program = bpf_object__find_program_by_name(object, "pulse_sys_enter");
    struct bpf_link *link = program ? bpf_program__attach_raw_tracepoint(program, "sys_enter") : NULL;
    error = libbpf_get_error(link);
    if (!program || error) { fprintf(stderr, "attach raw tracepoint: %s\n", program ? strerror(-error) : "program missing"); if (error) link = NULL; bpf_object__close(object); return 1; }
    fprintf(stderr, "sentinel-pulse attached; interval=%ums targets=%d cpus=%d\n", interval_ms, targets, cpu_count);
    uint64_t consistency_retry_exhausted = 0;
    while (!exiting) {
        usleep(interval_ms * 1000U);
        targets = refresh_targets(cgroups_fd, allow_file, cpu_count);
        if (targets < 0) { fprintf(stderr, "target refresh failed: %s\n", strerror(-targets)); break; }
        if (targets == 0) { fprintf(stderr, "target allow-list became empty; stopping fail-closed\n"); break; }
        double snapshot_started_at = wall_time();
        int snapshots = print_snapshots(
            cgroups_fd, cpu_count, snapshot_started_at,
            &consistency_retry_exhausted);
        /* The boundary is after all map lookups, so no included count can be
         * timestamped later than the window end used for latency evidence. */
        double observed_at = wall_time();
        double snapshot_read_seconds = observed_at - snapshot_started_at;
        uint32_t zero = 0; uint64_t task_failures = 0;
        bpf_map_lookup_elem(stats_fd, &zero, &task_failures);
        printf("{\"type\":\"stat\",\"observed_at\":%.9f,\"name\":\"task_state_update_fail\",\"cumulative\":%llu}\n", observed_at, (unsigned long long)task_failures);
        printf("{\"type\":\"stat\",\"observed_at\":%.9f,\"name\":\"snapshot_consistency_retry_exhausted\",\"cumulative\":%llu}\n", observed_at, (unsigned long long)consistency_retry_exhausted);
        printf("{\"type\":\"snapshot_end\",\"observed_at\":%.9f,\"targets\":%d,\"snapshots\":%d,\"snapshot_read_seconds\":%.9f}\n",
               observed_at, targets, snapshots, snapshot_read_seconds);
        fflush(stdout);
    }
    bpf_link__destroy(link); bpf_object__close(object);
    return targets <= 0 ? 1 : 0;
}
