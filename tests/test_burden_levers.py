import importlib.util
from pathlib import Path

import numpy as np

from sentinel_pulse.attack.confirmation_study import EpisodeCounter
from sentinel_pulse.attack.window_table import Signals

ROOT = Path(__file__).resolve().parents[1]


def _module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts'/'analysis'/f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bl = _module('burden_levers')
screen = _module('ideas_screen')


def _stream(seed, n=4000):
    rng = np.random.default_rng(seed)
    ident = np.sort(rng.integers(0, 5, n))
    start = np.zeros(n); end = np.zeros(n)
    for k in np.unique(ident):
        idx = np.flatnonzero(ident == k)
        t = 100.0
        for i in idx:
            t += 0.5 if rng.random() > 0.03 else rng.choice([1.7, 30.0])   # some gaps restart the history
            start[i], end[i] = t, t + 0.5
    p = np.clip(rng.uniform(0, 1, n) ** 4, 1e-9, 1)
    return ident, start, end, p


def _rows(ident, start, end, p, k):
    sel = ident == k
    return [dict(start=s, end=e, joint_p=q, tree_p=q, support_p=q, alpha=0.01)
            for s, e, q in zip(start[sel], end[sel], p[sel])]


def test_vectorised_cusum_equals_the_screen_recursion():
    ident, start, end, p = _stream(1)
    new = bl.segments(ident, start, end)
    x = -np.log(np.maximum(p, 1e-12))
    for b, h in ((2.0, 1.0), (3.0, 6.0), (5.0, 3.0)):
        s = bl.cusum(x - b, new)
        for k in np.unique(ident):
            assert list(s[ident == k] >= h) == screen.alarms_cusum(_rows(ident, start, end, p, k), b, h)


def test_discounted_windows_leave_cusum_unchanged():
    y = np.array([2.0, 0.0, 0.0, 1.5, -10.0, 0.0])
    new = np.array([True, False, False, False, False, False])
    assert np.allclose(bl.cusum(y, new), [2.0, 2.0, 2.0, 3.5, 0.0, 0.0])


def test_vectorised_k2of2_equals_the_screen_rule():
    ident, start, end, p = _stream(2)
    new = bl.segments(ident, start, end)
    alpha = np.full(len(p), 0.01)
    for scale in (3.0, 10.0):
        alarm = bl.kofn2(p <= alpha * scale, new)
        for k in np.unique(ident):
            assert list(alarm[ident == k]) == screen.alarms_kofn(_rows(ident, start, end, p, k), 'joint_p', scale)


def test_episodes_match_the_episode_counter():
    ident, start, end, p = _stream(3)
    positive = p < 0.05
    counter = EpisodeCounter()
    for k, e, pos in zip(ident, end, positive):
        if pos:
            counter.add('w', k, e)
    assert bl.episodes(ident, end, positive, 15.0) == sum(counter.episodes.values())


def test_peer_and_self_novelty():
    s = Signals(bucket=2.0, peer=(30.0,), self_=(60.0,))
    bit = lambda *ids: sum(1 << i for i in ids)
    # replica B keeps running a "probe" (IDs 1, 2); replica A is alone at first
    first = s.observe(('A',), 'W', 0.0, 0.5, bit(1), want=True)
    assert first['novel_peer30'] == -1 and first['novel_self60'] == -1
    t = 0.5
    for i in range(140):                       # 70 s of both replicas
        s.observe(('B',), 'W', t, t + 0.5, bit(1, 2) if i % 20 == 0 else 0)
        s.observe(('A',), 'W', t, t + 0.5, bit(1) if i % 20 == 0 else 0, want=False)
        t += 0.5
    probe = s.observe(('A',), 'W', t, t + 0.5, bit(1, 2, 59), want=True)
    assert probe['launch'] and probe['novel_peer30'] == 1        # 59 never seen on B, 1 and 2 were
    assert probe['novel_self60'] == 2                            # A itself only ever showed ID 1
    s.observe(('B',), 'W', t, t + 0.5, bit(59, 101))
    t += 0.5
    again = s.observe(('A',), 'W', t, t + 0.5, bit(1, 2, 59), want=True)
    assert again['novel_peer30'] == 0                            # B showed 59 in the last 30 s
    assert again['novel_self60'] == 2                            # the previous window is context, not history


def test_trial_outcome_takes_the_first_alarm_in_the_interval():
    tr = bl.Trials.__new__(bl.Trials)
    tr.label = np.array(['attack', 'control']); tr.scenario = np.array(['x', 'x'])
    tr.lo, tr.hi, tr.kernel = np.array([2, 6]), np.array([6, 9]), np.array([1.0, np.nan])
    alarm = np.array([1, 0, 0, 0, 1, 1, 0, 0, 0], bool)
    end = np.arange(9, dtype=float)
    hit, delay = tr.outcome(alarm, end)
    assert list(hit) == [True, False] and delay[0] == 3.0
