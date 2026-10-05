// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define PULSE_TRACKED 29
#define PULSE_SYSCALL_BINS 64
#define PULSE_TRANSITION_BINS 64
#include "pulse_counter_projection.h"

static int slot_for(unsigned id)
{
    switch (id) {
#define CASE(number, slot) case number: return slot;
        PULSE_TRACKED_ROWS(CASE)
#undef CASE
    default: return -1;
    }
}

int main(void)
{
    struct pulse_snapshot sum = {0}, expected = {0};
    for (unsigned cpu = 0; cpu < 4; cpu++) {
        struct pulse_counters raw = {0};
        for (unsigned id = 0; id < 1024; id++) {
            uint64_t count = ((id * 97U + cpu * 13U) % 47U) + 1;
            unsigned bin = (id * 2654435761U) >> 26;
            int slot = slot_for(id);
            if (slot >= 0) {
                raw.tracked[slot] += count;
                expected.tracked[slot] += count;
            } else {
                raw.other_syscall_bins[bin] += count;
            }
            expected.total += count;
            expected.syscall_bins[bin] += count;
        }
        for (unsigned bin = 0; bin < 64; bin++) {
            raw.transition_bins[bin] = cpu + bin;
            expected.transition_bins[bin] += cpu + bin;
        }
        assert(pulse_project_cpu(&raw, &sum) == 0);
    }
    assert(memcmp(&sum, &expected, sizeof(sum)) == 0);
    uint64_t binned = 0, tracked = 0;
    for (unsigned bin = 0; bin < 64; bin++) binned += sum.syscall_bins[bin];
    for (unsigned slot = 0; slot < 29; slot++) tracked += sum.tracked[slot];
    assert(binned == sum.total && tracked <= sum.total);

    struct pulse_counters empty = {0};
    assert(pulse_project_cpu(&empty, &sum) == 0);
    assert(memcmp(&sum, &expected, sizeof(sum)) == 0);

    struct pulse_counters huge = {0};
    struct pulse_snapshot overflow = {0};
    huge.tracked[0] = UINT64_MAX;
    assert(pulse_project_cpu(&huge, &overflow) == 0);
    huge.tracked[0] = 0;
    huge.other_syscall_bins[1] = 1;
    assert(pulse_project_cpu(&huge, &overflow) == -1);
    memset(&overflow, 0, sizeof(overflow));
    memset(&huge, 0, sizeof(huge));
    overflow.transition_bins[0] = UINT64_MAX;
    huge.transition_bins[0] = 1;
    assert(pulse_project_cpu(&huge, &overflow) == -1);
    printf("projection equivalence: 1024 IDs x 4 CPUs; overflow guards: PASS\n");
    return 0;
}
