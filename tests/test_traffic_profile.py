import datetime

from sentinel_pulse.pipeline.traffic_profile import REGIMES, TZ_OFFSET, coverage, diurnal_schedule

VN = datetime.timezone(datetime.timedelta(seconds=TZ_OFFSET))


def local(t):
    return datetime.datetime.fromtimestamp(t, VN)


def regime_at(schedule, t):
    return next(p['regime'] for p in schedule if p['start'] <= t < p['end'])


def test_a_day_covers_every_regime_without_gaps_at_their_local_hours():
    start = datetime.datetime(2026, 11, 22, 9, 37, tzinfo=VN).timestamp()
    sched = diurnal_schedule(start, start + 2 * 86400, seed=7)
    assert sched[0]['start'] == start and sched[-1]['end'] == start + 2 * 86400
    assert set(coverage(diurnal_schedule(start, start + 86400, seed=7))) == set(REGIMES)
    assert all(a['end'] == b['start'] for a, b in zip(sched, sched[1:]))
    assert set(coverage(sched)) == set(REGIMES)
    day = datetime.datetime(2026, 11, 23, tzinfo=VN)
    at = lambda h, m=0: regime_at(sched, (day + datetime.timedelta(hours=h, minutes=m)).timestamp())
    assert at(3) == 'night' and at(4, 30) == 'night'          # quiet 00:00-05:30 apart from maintenance at 02:00
    assert at(9) == 'peak' and at(12) == 'peak' and at(19, 30) == 'peak' and at(16) == 'steady'
    assert at(10, 45) == 'toolmix'


def test_seeded_jitter_moves_boundaries_by_at_most_ten_minutes_and_is_reproducible():
    start = datetime.datetime(2026, 11, 22, 0, 0, tzinfo=VN).timestamp()
    a, b = diurnal_schedule(start, start + 2 * 86400, 3), diurnal_schedule(start, start + 2 * 86400, 3)
    assert a == b and a != diurnal_schedule(start, start + 2 * 86400, 4)
    bursts = [p for p in a if p['regime'] == 'burst']
    assert len(bursts) == 4 and all(p['end'] - p['start'] >= 300 for p in bursts)
    first_peak = next(p for p in a if p['regime'] == 'peak')
    assert abs(local(first_peak['start']).hour * 60 + local(first_peak['start']).minute - 480) <= 10
