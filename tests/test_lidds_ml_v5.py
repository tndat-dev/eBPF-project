"""Gate of lidds-ml-v5 on recordings: hold after execve, threshold from normal only, windows aligned with the token matrix."""
from pathlib import Path
import sys

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))

v5 = pytest.importorskip('lidds_ml_v5')


def test_hold_counts_from_the_last_execve_in_time_order():
    ends = np.asarray([3.0, 1.0, 2.0, 4.0, 5.0])
    execve = np.asarray([0, 1, 0, 0, 1.0])
    assert v5.held_mask(ends, execve, 1.0).tolist() == [False, True, True, False, True]
    assert not v5.held_mask(ends, execve, 0.0).any()


def test_no_execve_holds_nothing():
    assert not v5.held_mask(np.asarray([1.0, 2.0]), np.zeros(2), 2.0).any()


def test_pool_fit_leaves_held_windows_out():
    rec = np.asarray([[1.0, 99.0, 1.0], [5.0, 3.0, 0.0]])
    z = {f'val/{i}': rec + np.asarray([0.0, i * .01, 0.0]) for i in range(20)}
    z['test'] = np.asarray([[1.0, 1e6, 0.0]])

    class Z(dict):
        files = list(z)
    fit = v5.pool_fit(Z(z), 1.0)
    assert v5.m.threshold(fit, .01) < 10


def test_candidates_are_the_token_system_plus_the_reference():
    cands = list(v5.candidates())
    names = [c[0] for c in cands]
    assert len(names) == len(set(names)) == 1 + len(v5.HOLDS) * len(v5.POOL_LEVELS) + len(v5.PHASES) * (len(v5.POOL_LEVELS) - 1)
    assert 'token-hold0-poolnone' in names and 'token-phase1-pool0.01' in names
    assert [c[0] for c in cands if len(c[1]) == 3] == ['three-hold0-poolnone']


class FakeZ(dict):
    @property
    def files(self):
        return list(self)


def test_phase_fit_uses_recordings_with_an_execve_and_needs_three():
    with_exec = np.asarray([[1.0, 30.0, 1.0], [5.0, 3.0, 0.0]])
    without = np.asarray([[1.0, 99.0, 0.0]])
    z = FakeZ({f'val/{i}': with_exec + np.asarray([0.0, i * .1, 0.0]) for i in range(10)})
    z['val/x'] = without
    fit = v5.phase_fit(z, 1.0)
    assert 25 < v5.m.threshold(fit, .01) < 40
    assert v5.phase_fit(FakeZ({'val/0': with_exec, 'val/x': without}), 1.0) is None
