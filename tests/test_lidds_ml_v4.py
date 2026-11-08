"""Rule R4 of lidds-ml-v4: moment Gumbel without the top 1 % of the maxima (at least one)."""
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'analysis'))
pytest_import = __import__('pytest')
v4 = pytest_import.importorskip('lidds_ml_v4')


def test_trimmed_gumbel_drops_the_top_one_percent():
    x = np.arange(100.0)
    assert v4.trimmed_gumbel(x) == v4.m.gumbel(x[:99])
    x = np.arange(270.0)
    assert v4.trimmed_gumbel(x) == v4.m.gumbel(x[:267])


def test_small_samples_keep_all_but_the_largest():
    x = np.array([1.0, 2.0, 3.0, 50.0])
    assert v4.trimmed_gumbel(x) == v4.m.gumbel(x[:3])


def test_an_outlier_does_not_move_the_fit():
    x = np.linspace(1, 5, 270)
    y = x.copy()
    y[-1] = 500.0
    assert v4.trimmed_gumbel(x) == v4.trimmed_gumbel(y)
