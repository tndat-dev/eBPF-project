"""Part C of ml-final-study-v1: thresholds from the dumped held-out block maxima."""
import json
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import cluster_threshold as ct  # noqa: E402


def test_thresholds_reproduce_gumbel_and_order_the_rules(tmp_path):
    rng = np.random.default_rng(1)
    blocks = rng.gumbel(5.0, 1.0, 5000)
    (tmp_path / 'a.maxima.json').write_text(json.dumps(dict(workload='w', blocks=[['p', 'c', i, float(v)] for i, v in enumerate(blocks)])))
    g = ct.fit.threshold(ct.fit.trimmed_gumbel(blocks), ct.ALPHA)
    thr, check = ct.thresholds(tmp_path, {'w': ('lm', g)})
    assert check < 1e-12
    t = thr['w']
    assert t['blocks'] == 5000 and abs(t['gumbel'] - g) < 1e-12
    assert t['empirical'] <= blocks.max() and t['empirical'] >= np.sort(blocks)[-2]
    assert abs(t['gumbel_exceedance'] - float((blocks > g).mean())) < 1e-12
