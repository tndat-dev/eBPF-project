// SPDX-License-Identifier: GPL-2.0
#ifndef PULSE_COUNTER_PROJECTION_H
#define PULSE_COUNTER_PROJECTION_H
#include <stdint.h>
#include "pulse_counter_ids.h"

/* Kernel ABI: exactly one primary counter is incremented per syscall entry.
 * There is no separately updated total/full histogram to race with that word.
 * Like the legacy per-CPU read this is NOT an atomic cross-CPU time cut. */
struct pulse_counters {
    uint64_t tracked[PULSE_TRACKED];
    uint64_t other_syscall_bins[PULSE_SYSCALL_BINS];
    uint64_t transition_bins[PULSE_TRANSITION_BINS];
};

struct pulse_snapshot {
    uint64_t syscall_bins[PULSE_SYSCALL_BINS];
    uint64_t transition_bins[PULSE_TRANSITION_BINS];
    uint64_t tracked[PULSE_TRACKED];
    uint64_t total;
};

_Static_assert(sizeof(struct pulse_counters) == (29 + 64 + 64) * 8,
               "projected counter map ABI changed");

static inline int pulse_add_u64(uint64_t *destination, uint64_t value)
{
    if (UINT64_MAX - *destination < value)
        return -1;
    *destination += value;
    return 0;
}

/* Input is one already copied per-CPU value, never a live map pointer.
 * A partially written destination on overflow must be discarded by caller. */
static inline int pulse_project_cpu(
    const struct pulse_counters *raw, struct pulse_snapshot *sum)
{
    static const uint32_t ids[PULSE_TRACKED] = {
#define PULSE_ID(id, slot) id,
        PULSE_TRACKED_ROWS(PULSE_ID)
#undef PULSE_ID
    };
    for (int slot = 0; slot < PULSE_TRACKED; slot++) {
        uint64_t count = raw->tracked[slot];
        uint32_t bin = (ids[slot] * 2654435761U) >> 26;
        if (pulse_add_u64(&sum->tracked[slot], count) ||
            pulse_add_u64(&sum->syscall_bins[bin], count) ||
            pulse_add_u64(&sum->total, count))
            return -1;
    }
    for (int bin = 0; bin < PULSE_SYSCALL_BINS; bin++) {
        uint64_t count = raw->other_syscall_bins[bin];
        if (pulse_add_u64(&sum->syscall_bins[bin], count) ||
            pulse_add_u64(&sum->total, count))
            return -1;
    }
    for (int bin = 0; bin < PULSE_TRANSITION_BINS; bin++)
        if (pulse_add_u64(&sum->transition_bins[bin], raw->transition_bins[bin]))
            return -1;
    return 0;
}
#endif
