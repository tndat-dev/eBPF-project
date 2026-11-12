"""Worked examples of the token model: the explained window score and threshold are those of the registered scoring."""
import json
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import test_lidds_evaluate_v2 as base  # noqa: E402
import lidds_token_cache as tc  # noqa: E402
import lidds_token_explain as ex  # noqa: E402
import lidds_token_study as st  # noqa: E402


def test_label_follows_the_spec():
    spec = st.base_spec()
    assert ex.label(('openat', 'e', 'ENOENT'), spec) == 'openat!ENOENT'
    assert ex.label(('openat', 'o', 'r:/etc'), spec) == 'openat:r:/etc'
    assert ex.label(('read', 's', '12'), spec) == 'read#12'
    assert ex.label(('getpid', '', ''), spec) == 'getpid'
    assert ex.label(('read', 's', '12'), st.without(spec, {'read'})) == 'read'


def test_explained_scores_are_the_registered_scores(tmp_path):
    archive = base._archive(tmp_path)
    cache = tmp_path / 'SCN.npz'
    vocab, recs, events = tc.build(archive, cache, lambda name, split: True)
    cache.with_suffix('.json').write_text(json.dumps(dict(scenario='SCN', n=tc.N, vocab=vocab, recordings=recs, events=events)))
    doc = ex.explain(cache)
    spec = st.base_spec()
    out = st.score_scenario(cache, spec)
    i = st.columns_of(spec).index('top10')
    maxima = [a[:, i].max() for k, a in out.items() if k.startswith('val/') and len(a)]
    assert abs(doc['threshold'] - st.m.threshold(st.v4.trimmed_gumbel(maxima), st.ALPHA)) < 1e-9
    e = doc['example']
    if e is not None:
        a = out[e['recording']]
        w = e['alarm_window']
        assert abs(a[a[:, 0] == w['window_end'], i][0] - w['score']) < 1e-9
        assert sum(r['used'] for r in w['top']) == min(10, w['events'])
        assert abs(w['backoff_of_first'][-1]['nll'] - w['top'][0]['nll']) < 1e-9
    h = doc['highest_normal']
    assert abs(h['window']['score'] - h['score']) < 1e-9
