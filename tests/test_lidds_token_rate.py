"""Part D of ml-final-study-v1: the rate signal over seen grams."""
import json
import math
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import test_lidds_evaluate_v2 as base  # noqa: E402
import lidds_token_cache as tc  # noqa: E402
import lidds_token_rate as tr  # noqa: E402
import lidds_token_study as st  # noqa: E402


def keys(rows):
    return st.void(np.asarray(rows, np.uint32))


def test_max_table_and_rate_rows():
    k = keys([[1, 2, 3, 4], [5, 6, 7, 8]])
    t = tr.max_table([(k, np.array([3, 1])), (k[:1], np.array([7]))])
    assert t[1].tolist() == [7, 1]
    ends = np.array([0.5, 0.5, 1.0])
    probe = keys([[1, 2, 3, 4], [9, 9, 9, 9], [5, 6, 7, 8]])
    rows = tr.rate_rows(ends, probe, np.array([15, 100, 1]), t)
    assert rows[:, 0].tolist() == [0.5, 1.0]                     # the unseen gram (9,9,9,9) is ignored
    assert abs(rows[0, 1] - math.log(16 / 8)) < 1e-12 and abs(rows[1, 1] - 0.0) < 1e-12


def test_scenario_scores_cover_the_same_recordings(tmp_path):
    archive = base._archive(tmp_path)
    cache = tmp_path / 'SCN.npz'
    vocab, recs, events = tc.build(archive, cache, lambda name, split: True)
    cache.with_suffix('.json').write_text(json.dumps(dict(n=tc.N, vocab=vocab, recordings=recs, events=events)))
    rate = tr.score_scenario(cache)
    model = st.score_scenario(cache, st.base_spec())
    assert set(rate) == set(model)
    for key, a in rate.items():
        assert a.shape[1] == 2 and set(a[:, 0]) <= set(model[key][:, 0])
