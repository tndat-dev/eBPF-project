import numpy as np

from sentinel_pulse.attack import rolling_recalibration as rr


def drifting_rows(hours=12, rate=2.0):
    """One container whose normal scores drift upward by one unit per hour."""
    n = int(hours*3600*rate)
    end = np.arange(n)/rate
    rng = np.random.default_rng(1)
    drift = end/3600
    return {'ns/w:c': dict(identity=np.zeros(n, dtype=np.int64), end=end,
                           tree=rng.normal(size=n)+drift, support=rng.normal(size=n)+drift,
                           eligible=np.ones(n, dtype=bool), alpha=0.01)}


def burden(rows, kind, guarded=False):
    static = (0.0, 3600.0)
    blocks = rr.schedule(kind, 3*3600, 12*3600, static, 1, 1)
    flags, cals = rr.run_strategy(rows, blocks, [], guarded=guarded, static_span=static)
    return rr.normal_metrics(rows, flags, 3*3600, 12*3600, [])['1']


def test_rolling_calibration_tracks_drift_that_static_does_not():
    static = burden(drifting_rows(), 'static')
    rolling = burden(drifting_rows(), 'rolling')
    assert static['positive_window_rate'] > 0.5
    assert rolling['positive_window_rate'] < static['positive_window_rate']/4
    assert len(rolling['hourly_episodes_per_replica_hour']) == 9


def test_episode_starts_align_with_inputs():
    identity = np.array([0, 1, 0, 0])
    end = np.array([1.0, 1.0, 1.5, 40.0])
    starts = rr.episode_starts(identity, end, np.array([True, True, True, True]))
    assert starts.tolist() == [True, True, False, True]


def test_campaign_intervals_are_masked():
    end = np.arange(0, 100, 0.5)
    m = rr.masked(end, [(10.0, 20.0)])
    assert m.sum() == 20 and m[np.searchsorted(end, 10.0)]


def test_k_of_n_confirmation_lowers_normal_positives():
    rows = drifting_rows(hours=6)
    static = (0.0, 3600.0)
    blocks = rr.schedule('rolling', 3*3600, 6*3600, static, 1, 1)
    flags, _ = rr.run_strategy(rows, blocks, [], guarded=False, scales=(3.0,), static_span=static)
    one = rr.normal_metrics(rows, flags, 3*3600, 6*3600, [], scales=(3.0,))['3']
    two = rr.normal_metrics(rows, flags, 3*3600, 6*3600, [], scales=(3.0,), confirmation=(2, 2))['3']
    assert 0 < two['positive_window_rate'] < one['positive_window_rate']
