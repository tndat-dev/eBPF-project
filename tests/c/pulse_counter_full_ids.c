#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define PULSE_TRACKED 29
#define PULSE_SYSCALL_BINS 64
#define PULSE_TRANSITION_BINS 64
#define PULSE_SECCOMP_EXTENDED
#define PULSE_FULL_IDS
#include "pulse_counter_projection.h"

int main(void) {
    struct pulse_snapshot sum = {0};
    for (int cpu = 0; cpu < 4; cpu++) {
        struct pulse_counters raw = {0};
        for (int id = 0; id < 1024; id++) raw.full_counts[id] = id + cpu;
        raw.seccomp_skipped_or_emulated = 7;
        raw.transition_bins[cpu] = 13;
        assert(pulse_project_cpu(&raw, &sum) == 0);
    }
    uint64_t total = 0, bins[64] = {0};
    for (int id = 0; id < 1024; id++) {
        uint64_t expected = 4 * id + 6;
        assert(sum.full_counts[id] == expected);
        bins[((uint32_t)id * 2654435761U) >> 26] += expected;
        total += expected;
    }
    assert(sum.total == total && sum.seccomp_skipped_or_emulated == 28);
    assert(sum.tracked[0] == sum.full_counts[0]);
    assert(sum.tracked[28] == sum.full_counts[435]);
    for (int i = 0; i < 64; i++) assert(sum.syscall_bins[i] == bins[i]);
    struct pulse_counters overflow = {0};
    overflow.full_counts[1] = UINT64_MAX;
    assert(pulse_project_cpu(&overflow, &sum) == -1);
    puts("PASS: full-ID projection 1024 IDs x 4 CPUs and overflow");
}
