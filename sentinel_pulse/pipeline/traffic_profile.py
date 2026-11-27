"""Diurnal AIMS traffic profile (protocol load-diurnal-v1): the regimes of testbed/traffic/set_aims_traffic_regime.sh
laid on the wall clock of Vietnam (UTC+7), so a run of at least 24 h covers every regime at the hour it happens in a
real shop: a quiet night, a morning peak around 08:00, a lunch peak, office-hour tool use, an evening peak around 20:00
with a short flash-sale burst, a nightly maintenance window, and the ramps between them.

Day plan (local time, start of each phase):

    00:00 night      quiet night traffic (few users, background jobs only)
    02:00 toolmix    nightly maintenance: batch and report tools, backups (30 min)
    02:30 night
    05:30 recovery   early risers, traffic rising from the night level
    07:00 steady     morning ramp
    08:00 peak       morning peak (commute, opening hours)
    08:30 burst      login storm at the start of the working day (10 min)
    08:40 peak
    10:00 toolmix    office hours: operators and report tools beside normal use
    11:30 peak       lunch peak
    13:00 steady
    14:30 toolmix    afternoon reporting (1 h)
    15:30 steady
    19:00 peak       evening peak
    20:00 burst      evening campaign / flash sale (15 min)
    20:15 peak
    21:30 recovery   evening decline
    23:00 night

Every boundary except 00:00 moves by a seeded jitter of up to +/-10 min per calendar day, so two days of one run are
not copies of each other; the seed is part of the run's CONFIG.json.
"""
# LỊCH TẢI THEO NGÀY (load-diurnal-v1): các chế độ tải đặt theo giờ Việt Nam (UTC+7) như một cửa hàng thật — đêm thấp
# tải, cao điểm 8 giờ, trưa, giờ hành chính có công cụ báo cáo, cao điểm tối 20 giờ có burst ngắn, bảo trì đêm.
from __future__ import annotations

import random

TZ_OFFSET = 7 * 3600
DAY = 86400
REGIMES = ('night', 'recovery', 'steady', 'toolmix', 'peak', 'burst')
# (minute of the local day, regime)
DAY_PLAN = ((0, 'night'), (120, 'toolmix'), (150, 'night'), (330, 'recovery'), (420, 'steady'), (480, 'peak'),
            (510, 'burst'), (520, 'peak'), (600, 'toolmix'), (690, 'peak'), (780, 'steady'), (870, 'toolmix'),
            (930, 'steady'), (1140, 'peak'), (1200, 'burst'), (1215, 'peak'), (1290, 'recovery'), (1380, 'night'))
JITTER_MINUTES = 10


def day_phases(day_start: float, rng: random.Random):
    """[(start, regime)] of one local day starting at day_start (local midnight, unix seconds); boundaries after
    00:00 move by up to +/-JITTER_MINUTES, never past their neighbours, and a burst keeps at least 5 minutes."""
    starts = [m * 60.0 for m, _ in DAY_PLAN]
    moved = [0.0]
    for i in range(1, len(starts)):
        lo = max(moved[-1] + 300.0, starts[i] - JITTER_MINUTES * 60)
        hi = min(starts[i] + JITTER_MINUTES * 60, (starts[i + 1] if i + 1 < len(starts) else DAY) - 300.0)
        moved.append(min(max(starts[i] + rng.uniform(-JITTER_MINUTES, JITTER_MINUTES) * 60, lo), hi))
    return [(day_start + s, regime) for s, (_, regime) in zip(moved, DAY_PLAN)]


def diurnal_schedule(start: float, end: float, seed: int):
    """traffic_schedule entries {start, end, regime} covering [start, end) by the local-time day plan."""
    rng = random.Random(seed)
    first_midnight = ((start + TZ_OFFSET) // DAY) * DAY - TZ_OFFSET
    phases = []
    day = first_midnight
    while day < end:
        phases += day_phases(day, rng)
        day += DAY
    out = []
    for i, (s, regime) in enumerate(phases):
        e = phases[i + 1][0] if i + 1 < len(phases) else day
        s, e = max(s, start), min(e, end)
        if e > s:
            if out and out[-1]['regime'] == regime and out[-1]['end'] == s:
                out[-1]['end'] = e
            else:
                out.append(dict(start=s, end=e, regime=regime))
    return out


# burst-round-v1: a sale day (repeated flash sales), to learn the burst regime; minutes per cycle, burst drawn in [10, 15]
SALE_CYCLE = (('steady', 10), ('peak', 8), ('burst', None), ('peak', 5), ('recovery', 5))


def sale_schedule(start: float, end: float, seed: int):
    """traffic_schedule entries {start, end, regime} of repeated sale cycles (steady, peak, burst 10-15 min, peak,
    recovery) from start to end; each phase except burst moves by up to +/-2 min (seeded), none shorter than 3 min."""
    rng = random.Random(seed)
    out, t = [], start
    while t < end:
        for regime, minutes in SALE_CYCLE:
            length = rng.uniform(10, 15) if minutes is None else max(3.0, minutes + rng.uniform(-2, 2))
            e = min(t + length * 60.0, end)
            if e > t:
                out.append(dict(start=t, end=e, regime=regime))
            t = e
            if t >= end:
                break
    return out


def coverage(schedule):
    """Seconds per regime of a schedule."""
    out = {}
    for p in schedule:
        out[p['regime']] = out.get(p['regime'], 0.0) + p['end'] - p['start']
    return out
