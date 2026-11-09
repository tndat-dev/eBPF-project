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


def test_every_system_has_the_ungated_candidate():
    names = [c[0] for c in v5.candidates()]
    assert 'three-hold0-poolnone' in names and 'token-hold0-poolnone' in names
    assert len(names) == len(set(names)) == 2 * len(v5.HOLDS) * len(v5.POOL_LEVELS)
