import importlib.util
import json
from pathlib import Path
import sys

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
spec = importlib.util.spec_from_file_location('mlv2', ROOT / 'scripts' / 'analysis' / 'lidds_ml_v2.py')
v2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v2)


def test_moment_gumbel_threshold_rises_as_alpha_falls():
    m = np.array([1.0, 2.0, 3.0, 4.0])
    assert v2.threshold(v2.gumbel(m), 0.001) > v2.threshold(v2.gumbel(m), 0.01) > m.mean()


def write(d, name, val, tests, cols):
    np.savez(d / f'{name}.npz', **{f'val/v{i}': np.array(a, float) for i, a in enumerate(val)}, **{k: np.array(a, float) for k, a in tests.items()})
    (d / f'{name}.json').write_text(json.dumps(dict(columns=cols)))


def fixture(tmp_path):
    """Attacks: token score jumps after the exploit at t=10; one attack only moves the frequency branch; a normal
    recording fires the token model before any attack exists."""
    sc, to = tmp_path / 'scores', tmp_path / 'tokens'
    sc.mkdir(); to.mkdir()
    cols_s, cols_t = ['window_end', 'tree_plain', 'support'], ['window_end', 'top10']
    rng = np.random.default_rng(1)
    vs = [[[1, .5, 1 + rng.random()], [2, .5, 1 + rng.random()]] for _ in range(60)]
    vt = [[[1, 2 + rng.random()], [2, 2 + rng.random()]] for _ in range(60)]
    ts, tt, recs = {}, {}, {}
    for i in range(40):
        n = f'a{i}'
        recs[n] = dict(split='test-normal_and_attack', subset='development' if i < 12 else 'official', exploit=10.0)
        ts[n] = [[9.5, .5, 1.5], [10.5, .5, 50.0 if i == 0 else 1.5]]
        tt[n] = [[9.5, 2.5], [10.5, 2.5 if i == 0 else 500.0]]
    for i in range(100):
        n = f'n{i}'
        recs[n] = dict(split='test-normal', subset='official', exploit=None)
        ts[n] = [[1.0, .5, 1.5]]
        tt[n] = [[1.0, 500.0 if i == 0 else 2.5]]
    write(sc, 'SCN', vs, ts, cols_s); write(to, 'SCN', vt, tt, cols_t)
    return sc, to, dict(scenarios=dict(SCN=dict(alarms=recs)))


def test_development_mode_never_reports_official(tmp_path):
    sc, to, doc = fixture(tmp_path)
    out = v2.run(doc, doc, sc, to, official=False, scenarios=['SCN'], cb_name='SCN')
    assert 'official' not in out and out['selected']['config'].startswith('T+tree+support')
    assert out['selected']['development']['detected'] == 12       # the frequency branch keeps a0


def test_official_is_scored_once(tmp_path):
    sc, to, doc = fixture(tmp_path)
    target = tmp_path / 'r.json'
    v2.write_once(target, dict(a=1))
    with pytest.raises(FileExistsError):
        v2.write_once(target, dict(a=2))
    out = v2.run(doc, doc, sc, to, official=True, scenarios=['SCN'], cb_name='SCN')
    assert out['official']['pooled']['detected'] == 28 and set(out['comparators_official']) == set(v2.COMPARATORS)
