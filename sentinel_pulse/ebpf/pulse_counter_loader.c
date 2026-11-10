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
#define PULSE_SNAPSHOT_RETRIES 32
#define PULSE_SNAPSHOT_RETRY_DELAY_US 50
#define PULSE_TARGET_REFRESH_RETRIES 5

#ifdef PULSE_TOKENS
#include <linux/types.h>
#include "pulse_token_ids.h"
#endif
#include "pulse_counter_projection.h"

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

#ifdef PULSE_TOKENS
static uint64_t *token_targets;
static size_t token_target_count;

static void remember_targets(const uint64_t *ids, size_t count)
{
    uint64_t *copy = malloc(count * sizeof(*copy));
    if (!copy) return;   /* keep the previous list */
    memcpy(copy, ids, count * sizeof(*copy));
    free(token_targets);
    token_targets = copy;
    token_target_count = count;
}
#endif

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
#ifdef PULSE_TOKENS
    remember_targets(desired, count);
#endif

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

static int refresh_targets_bounded(int map_fd, const char *path, int cpu_count)
{
    int result = 0;
    for (int attempt = 0; attempt < PULSE_TARGET_REFRESH_RETRIES; attempt++) {
        result = refresh_targets(map_fd, path, cpu_count);
        if (result >= 0)
            return result;
        if (result != -ENOMEM && result != -EAGAIN)
            return result;
        if (attempt + 1 < PULSE_TARGET_REFRESH_RETRIES) {
            unsigned delay_us = 50000U << attempt;
            fprintf(stderr,
                    "target refresh attempt %d failed: %s; retrying in %uus\n",
                    attempt + 1, strerror(-result), delay_us);
            usleep(delay_us);
        }
    }
    return result;
}


static int print_snapshots(
    int map_fd, int cpu_count, double observed_at,
    uint64_t *consistency_retries,
    uint64_t *consistency_retry_exhausted,
    uint64_t *projection_failures)
{
    (void)consistency_retries;
    (void)consistency_retry_exhausted;
    size_t stride = (sizeof(struct pulse_counters) + 7U) & ~7U;
    unsigned char *per_cpu = calloc((size_t)cpu_count, stride);
    if (!per_cpu) return -ENOMEM;
    uint64_t key = 0, next = 0;
    int has_key = 0, printed = 0;
    while (bpf_map_get_next_key(map_fd, has_key ? &key : NULL, &next) == 0) {
        memset(per_cpu, 0, (size_t)cpu_count * stride);
        int lookup = bpf_map_lookup_elem(map_fd, &next, per_cpu) < 0 ? -errno : 0;
        if (lookup == -EAGAIN) {
            (*consistency_retry_exhausted)++;
        } else if (lookup == 0) {
            struct pulse_snapshot sum = {0};
            int projection_ok = 1;
            for (int cpu = 0; cpu < cpu_count; cpu++) {
                struct pulse_counters *value = (struct pulse_counters *)(per_cpu + (size_t)cpu * stride);
                if (pulse_project_cpu(value, &sum) != 0) {
                    projection_ok = 0;
                    (*projection_failures)++;
                    break;
                }
            }
            if (!projection_ok) {
                key = next; has_key = 1;
                continue;
            }
            printf("{\"type\":\"cgroup_snapshot_extended\",\"telemetry_contract\":\"pulse-entered-plus-seccomp-skip-v1\",\"seccomp_skipped_or_emulated\":%llu,\"observed_at\":%.9f,\"cgroup_id\":%llu,\"total\":%llu,\"counts\":{",
                   (unsigned long long)sum.seccomp_skipped_or_emulated,
                   observed_at, (unsigned long long)next, (unsigned long long)sum.total);
            for (int slot = 0; slot < PULSE_TRACKED; slot++)
                printf("%s\"%u\":%llu", slot ? "," : "", tracked_ids[slot], (unsigned long long)sum.tracked[slot]);
            printf("},\"syscall_bins\":[");
            for (int bin = 0; bin < PULSE_SYSCALL_BINS; bin++)
                printf("%s%llu", bin ? "," : "", (unsigned long long)sum.syscall_bins[bin]);
            printf("],\"transition_bins\":[");
            for (int bin = 0; bin < PULSE_TRANSITION_BINS; bin++)
                printf("%s%llu", bin ? "," : "", (unsigned long long)sum.transition_bins[bin]);
            printf("]");
            printf(",\"full_counts\":{");
            int separator = 0;
            for (int id = 0; id < 1024; id++) {
                if (!sum.full_counts[id]) continue;
                printf("%s\"%d\":%llu", separator++ ? "," : "", id,
                       (unsigned long long)sum.full_counts[id]);
            }
            printf("}");
            printf("}\n");
            printed++;
        }
        key = next; has_key = 1;
    }
    free(per_cpu);
    return printed;
}

#ifdef PULSE_TOKENS
#define PULSE_GRAM_ENTRIES 262144
#define PULSE_DRAIN_GUARD_NS 20000000ULL   /* BPF programs run with migration off: a gram is in its map microseconds after its ktime */
static struct pulse_gram_key *gram_keys, *old_keys;
static uint64_t *gram_values;
static uint32_t *old_index;
static const struct pulse_gram_key *sort_keys;

static uint64_t mono_ns(void)
{
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static int by_cgroup_window(const void *left, const void *right)
{
    const struct pulse_gram_key *a = &sort_keys[*(const uint32_t *)left], *b = &sort_keys[*(const uint32_t *)right];
    if (a->cgroup_id != b->cgroup_id) return a->cgroup_id < b->cgroup_id ? -1 : 1;
    if (a->window != b->window) return a->window < b->window ? -1 : 1;
    return 0;
}

static int is_target(uint64_t cgroup_id)
{
    for (size_t index = 0; index < token_target_count; index++)
        if (token_targets[index] == cgroup_id) return 1;
    return 0;
}

/* Print and delete every gram of a window that has closed (window < now_window). One line per (cgroup, window):
 * {"type":"token_grams","window":W,"window_end":wall end,"events":sum,"grams":[[t0,t1,t2,t3,count],...]}. */
static long drain_grams(int map_fd, uint64_t now_window, double wall_minus_mono, uint64_t *drained_total)
{
    uint32_t batch = 0, count = 0, total = 0;
    int first = 1;
    for (;;) {
        count = PULSE_GRAM_ENTRIES - total;
        if (count == 0) break;
        if (count > 8192) count = 8192;
        int result = bpf_map_lookup_batch(map_fd, first ? NULL : &batch, &batch,
                                          gram_keys + total, gram_values + total, &count, NULL);
        int error = result < 0 ? errno : 0;
        total += count;
        first = 0;
        if (error == ENOENT) break;
        if (error) { fprintf(stderr, "gram batch lookup: %s\n", strerror(error)); return -error; }
    }
    uint32_t old = 0;
    for (uint32_t index = 0; index < total; index++)
        if (gram_keys[index].window < now_window) old_index[old++] = index;
    sort_keys = gram_keys;
    qsort(old_index, old, sizeof(*old_index), by_cgroup_window);
    long lines = 0;
    for (uint32_t start = 0; start < old;) {
        const struct pulse_gram_key *head = &gram_keys[old_index[start]];
        uint32_t end = start;
        uint64_t events = 0;
        while (end < old && gram_keys[old_index[end]].cgroup_id == head->cgroup_id &&
               gram_keys[old_index[end]].window == head->window)
            events += gram_values[old_index[end++]];
        if (is_target(head->cgroup_id)) {
            printf("{\"type\":\"token_grams\",\"contract\":\"pulse-token-select1f-v1\",\"cgroup_id\":%llu,\"window\":%u,"
                   "\"window_end\":%.3f,\"events\":%llu,\"grams\":[",
                   (unsigned long long)head->cgroup_id, head->window,
                   (double)(head->window + 1) * 0.5 + wall_minus_mono, (unsigned long long)events);
            for (uint32_t index = start; index < end; index++) {
                const struct pulse_gram_key *key = &gram_keys[old_index[index]];
                printf("%s[%u,%u,%u,%u,%llu]", index > start ? "," : "", key->tok[0], key->tok[1], key->tok[2],
                       key->tok[3], (unsigned long long)gram_values[old_index[index]]);
            }
            printf("]}\n");
            lines++;
        }
        start = end;
    }
    for (uint32_t index = 0; index < old; index++)
        old_keys[index] = gram_keys[old_index[index]];
    for (uint32_t done = 0; done < old;) {
        uint32_t chunk = old - done;
        if (bpf_map_delete_batch(map_fd, old_keys + done, &chunk, NULL) < 0) {
            if (errno != ENOENT) { fprintf(stderr, "gram batch delete: %s\n", strerror(errno)); return -errno; }
            chunk++;   /* the key at done + chunk is already gone: skip it */
        }
        done += chunk;
    }
    *drained_total += old;
    return lines;
}

static uint64_t tok_stat_sum(int fd, uint32_t index, int cpu_count, uint64_t *scratch)
{
    uint64_t sum = 0;
    if (bpf_map_lookup_elem(fd, &index, scratch) == 0)
        for (int cpu = 0; cpu < cpu_count; cpu++) sum += scratch[cpu];
    return sum;
}
#endif

int main(int argc, char **argv)
{
    const char *object_path = NULL, *allow_file = NULL;
    unsigned interval_ms = 1000;
#ifdef PULSE_TOKENS
    const char *token_mode = "grams";
#endif
    for (int index = 1; index < argc; index++) {
        if (!strcmp(argv[index], "--object") && index + 1 < argc) object_path = argv[++index];
        else if (!strcmp(argv[index], "--allow-cgroup-file") && index + 1 < argc) allow_file = argv[++index];
        else if (!strcmp(argv[index], "--interval-ms") && index + 1 < argc) interval_ms = (unsigned)strtoul(argv[++index], NULL, 10);
#ifdef PULSE_TOKENS
        else if (!strcmp(argv[index], "--tokens") && index + 1 < argc) token_mode = argv[++index];
#endif
        else { fprintf(stderr, "usage: %s --object PATH --allow-cgroup-file PATH [--interval-ms 1000]\n", argv[0]); return 2; }
    }
    if (!object_path || !allow_file || interval_ms < 100 || interval_ms > 60000) return 2;
#ifdef PULSE_TOKENS
    /* overhead conditions of reports/Thiết kế probe token Pulse.md: B exit-nofutex, C exit, D grams (the live probe) */
    struct pulse_tok_config token_config;
    if (!strcmp(token_mode, "exit-nofutex")) token_config = (struct pulse_tok_config){ .futex_at_exit = 0, .count_grams = 0 };
    else if (!strcmp(token_mode, "exit")) token_config = (struct pulse_tok_config){ .futex_at_exit = 1, .count_grams = 0 };
    else if (!strcmp(token_mode, "grams")) token_config = (struct pulse_tok_config){ .futex_at_exit = 1, .count_grams = 1 };
    else { fprintf(stderr, "--tokens must be exit-nofutex, exit or grams\n"); return 2; }
    if (token_config.count_grams && interval_ms % 500) { fprintf(stderr, "--tokens grams needs an interval that is a multiple of 500 ms\n"); return 2; }
    gram_keys = calloc(PULSE_GRAM_ENTRIES, sizeof(*gram_keys));
    old_keys = calloc(PULSE_GRAM_ENTRIES, sizeof(*old_keys));
    gram_values = calloc(PULSE_GRAM_ENTRIES, sizeof(*gram_values));
    old_index = calloc(PULSE_GRAM_ENTRIES, sizeof(*old_index));
    if (!gram_keys || !old_keys || !gram_values || !old_index) { fprintf(stderr, "cannot allocate gram buffers\n"); return 1; }
#endif
    signal(SIGINT, stop); signal(SIGTERM, stop); libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    int cpu_count = libbpf_num_possible_cpus();
    if (cpu_count <= 0) { fprintf(stderr, "cannot determine possible CPUs\n"); return 1; }
    struct bpf_object *object = bpf_object__open_file(object_path, NULL);
    int error = libbpf_get_error(object);
    if (error) { fprintf(stderr, "open BPF object: %s\n", strerror(-error)); return 1; }
#ifdef PULSE_TOKENS
    struct bpf_map *token_config_map = bpf_object__find_map_by_name(object, ".rodata.tokcfg");
    if (!token_config_map || bpf_map__set_initial_value(token_config_map, &token_config, sizeof(token_config))) {
        fprintf(stderr, "token config section missing or of another size\n"); bpf_object__close(object); return 1;
    }
#endif
    if ((error = bpf_object__load(object))) { fprintf(stderr, "load BPF object: %s\n", strerror(-error)); bpf_object__close(object); return 1; }
    int cgroups_fd = bpf_object__find_map_fd_by_name(object, "pulse_cgroups");
    int stats_fd = bpf_object__find_map_fd_by_name(object, "pulse_stats");
    if (cgroups_fd < 0 || stats_fd < 0) { fprintf(stderr, "required BPF map missing\n"); bpf_object__close(object); return 1; }
    /* Never let a legacy loader read a projected value or vice versa. */
    struct bpf_map *counter_map = bpf_object__find_map_by_name(object, "pulse_cgroups");
    if (!counter_map || bpf_map__value_size(counter_map) != sizeof(struct pulse_counters)) {
        fprintf(stderr, "counter map layout does not match loader\n");
        bpf_object__close(object);
        return 1;
    }
    int targets = refresh_targets_bounded(cgroups_fd, allow_file, cpu_count);
    if (targets < 0) {
        fprintf(stderr, "failed to populate target cgroups from %s: %s\n",
                allow_file, strerror(-targets));
        bpf_object__close(object);
        return 1;
    }
    if (targets == 0) {
        fprintf(stderr, "no valid target cgroup in %s; refusing host-wide collection\n",
                allow_file);
        bpf_object__close(object);
        return 1;
    }
    struct bpf_program *program = bpf_object__find_program_by_name(object, "pulse_sys_enter");
    struct bpf_link *link = program ? bpf_program__attach_raw_tracepoint(program, "sys_enter") : NULL;
    error = libbpf_get_error(link);
    if (!program || error) { fprintf(stderr, "attach raw tracepoint: %s\n", program ? strerror(-error) : "program missing"); if (error) link = NULL; bpf_object__close(object); return 1; }
    program = bpf_object__find_program_by_name(object, "pulse_seccomp_skip");
    struct bpf_link *seccomp_link = program ? bpf_program__attach_trace(program) : NULL;
    error = libbpf_get_error(seccomp_link);
    if (!program || !seccomp_link || error) {
        fprintf(stderr, "required extended seccomp hook unavailable\n");
        if (!error) bpf_link__destroy(seccomp_link);
        bpf_link__destroy(link); bpf_object__close(object); return 1;
    }
#ifdef PULSE_TOKENS
    /* hooked calls give their token at return through one raw_tp/sys_exit program (pulse_tokens.bpf.h) */
    struct bpf_program *token_program = bpf_object__find_program_by_name(object, "pulse_tok_sys_exit");
    struct bpf_link *token_link = token_program ? bpf_program__attach_raw_tracepoint(token_program, "sys_exit") : NULL;
    if (!token_program || libbpf_get_error(token_link)) { fprintf(stderr, "token hook pulse_tok_sys_exit unavailable\n"); return 1; }
    int grams_fd = bpf_object__find_map_fd_by_name(object, "pulse_grams");
    int token_stats_fd = bpf_object__find_map_fd_by_name(object, "pulse_tok_stats");
    uint64_t *token_scratch = calloc((size_t)cpu_count, sizeof(uint64_t));
    if (grams_fd < 0 || token_stats_fd < 0 || !token_scratch) { fprintf(stderr, "token maps missing\n"); return 1; }
    uint64_t grams_drained = 0;
    fprintf(stderr, "token probe: mode=%s exit=sys_exit hooks=1\n", token_mode);
#endif
    fprintf(stderr, "sentinel-pulse attached; interval=%ums targets=%d cpus=%d\n", interval_ms, targets, cpu_count);
    uint64_t consistency_retries = 0;
    uint64_t consistency_retry_exhausted = 0;
    uint64_t projection_failures = 0;
    while (!exiting) {
#ifdef PULSE_TOKENS
        /* wake just after a 0.5 s boundary of CLOCK_MONOTONIC (the clock of the gram windows) */
        uint64_t step = (uint64_t)interval_ms * 1000000ULL, wake = (mono_ns() / step + 1) * step + PULSE_DRAIN_GUARD_NS;
        struct timespec until = { .tv_sec = (time_t)(wake / 1000000000ULL), .tv_nsec = (long)(wake % 1000000000ULL) };
        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &until, NULL) == EINTR && !exiting) {}
#else
        usleep(interval_ms * 1000U);
#endif
        /* SIGTERM can interrupt usleep. Do not turn that shortened sleep into
         * a final partial feature window; detach cleanly at the boundary. */
        if (exiting)
            break;
        targets = refresh_targets_bounded(cgroups_fd, allow_file, cpu_count);
        if (targets < 0) { fprintf(stderr, "target refresh failed: %s\n", strerror(-targets)); break; }
        if (targets == 0) { fprintf(stderr, "target allow-list became empty; stopping fail-closed\n"); break; }
        double snapshot_started_at = wall_time();
        int snapshots = print_snapshots(
            cgroups_fd, cpu_count, snapshot_started_at,
            &consistency_retries,
            &consistency_retry_exhausted,
            &projection_failures);
        /* The boundary is after all map lookups, so no included count can be
         * timestamped later than the window end used for latency evidence. */
        double observed_at = wall_time();
        double snapshot_read_seconds = observed_at - snapshot_started_at;
#ifdef PULSE_TOKENS
        if (token_config.count_grams) {
            struct timespec wall_now, mono_now;
            clock_gettime(CLOCK_REALTIME, &wall_now);
            clock_gettime(CLOCK_MONOTONIC, &mono_now);
            double wall_minus_mono = (double)(wall_now.tv_sec - mono_now.tv_sec) + (double)(wall_now.tv_nsec - mono_now.tv_nsec) / 1e9;
            uint64_t now_window = ((uint64_t)mono_now.tv_sec * 1000000000ULL + (uint64_t)mono_now.tv_nsec) / PULSE_TOK_WINDOW_NS;
            double drain_started = wall_time();
            long gram_lines = drain_grams(grams_fd, now_window, wall_minus_mono, &grams_drained);
            if (gram_lines < 0) { fprintf(stderr, "token drain failed; stopping fail-closed\n"); break; }
            printf("{\"type\":\"token_drain\",\"observed_at\":%.9f,\"lines\":%ld,\"drain_seconds\":%.6f,\"entries_cumulative\":%llu,"
                   "\"grams_cumulative\":%llu,\"insert_fail_cumulative\":%llu,\"dir_fail_cumulative\":%llu}\n",
                   wall_time(), gram_lines, wall_time() - drain_started, (unsigned long long)grams_drained,
                   (unsigned long long)tok_stat_sum(token_stats_fd, 2, cpu_count, token_scratch),
                   (unsigned long long)tok_stat_sum(token_stats_fd, 0, cpu_count, token_scratch),
                   (unsigned long long)tok_stat_sum(token_stats_fd, 1, cpu_count, token_scratch));
        }
#endif
        uint32_t zero = 0; uint64_t task_failures = 0;
        bpf_map_lookup_elem(stats_fd, &zero, &task_failures);
        printf("{\"type\":\"stat\",\"observed_at\":%.9f,\"name\":\"task_state_update_fail\",\"cumulative\":%llu}\n", observed_at, (unsigned long long)task_failures);
        printf("{\"type\":\"stat\",\"observed_at\":%.9f,\"name\":\"snapshot_consistency_retries\",\"cumulative\":%llu}\n", observed_at, (unsigned long long)consistency_retries);
        printf("{\"type\":\"stat\",\"observed_at\":%.9f,\"name\":\"snapshot_consistency_retry_exhausted\",\"cumulative\":%llu}\n", observed_at, (unsigned long long)consistency_retry_exhausted);
        printf("{\"type\":\"stat\",\"observed_at\":%.9f,\"name\":\"snapshot_projection_fail\",\"cumulative\":%llu}\n", observed_at, (unsigned long long)projection_failures);
        printf("{\"type\":\"snapshot_end\",\"observed_at\":%.9f,\"targets\":%d,\"snapshots\":%d,\"snapshot_read_seconds\":%.9f}\n",
               observed_at, targets, snapshots, snapshot_read_seconds);
        fflush(stdout);
    }
#ifdef PULSE_TOKENS
    bpf_link__destroy(token_link);
#endif
    bpf_link__destroy(seccomp_link);
    bpf_link__destroy(link); bpf_object__close(object);
    return targets <= 0 ? 1 : 0;
}
