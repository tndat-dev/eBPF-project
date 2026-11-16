"""Model aging (pulse-live-v6-v1 amendment 1): v5 models and thresholds on a later normal capture."""
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import model_aging as ma  # noqa: E402
from sentinel_pulse.detector.token_model import CountTokenLM  # noqa: E402

A, B, T = 1 << 23, 2 << 23, 4 << 23


def write_model(path):
    lm = CountTokenLM()
    for _ in range(300):
        lm.learn((A, B, A, B))
        lm.learn((B, A, B, A))
    lm.finalize().save(path)
    return str(path)


def window(end, grams, workload='ns/w:c', pod='p1'):
    return dict(type='token_window', workload_key=workload, pod_uid=pod, container_name='c', window_end=end, grams=grams)


def test_blocks_alarms_and_episodes(tmp_path):
    lm = write_model(tmp_path / 'w.lm.json.gz')
    seg = tmp_path / 'run' / 'workers' / 'n1' / 'segments' / 's00001'
    seg.mkdir(parents=True)
    known, odd = [[A, B, A, B, 30]], [[T, T, T, T, 30]]
    rows = [window(10.0, known), window(10.5, odd), window(11.0, odd),     # block 0: one episode
            window(70.0, known),                                        # block 1: quiet
            window(130.0, odd),                                         # block 2: a second episode
            window(10.0, known, workload='ns/new:c')]                   # no model
    (seg / 'tokens.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    models = {'ns/w:c': (lm, 5.0)}
    m, w, al, un = ma.read_file((str(seg / 'tokens.jsonl'), models, 60.0))
    assert un == {'ns/new:c': 1} and w == {'ns/w:c': 5} and len(al) == 3
    rows, pooled = ma.summarize(m, w, al, models)
    r = rows['ns/w:c']
    assert (r['blocks'], r['above'], r['episodes']) == (3, 2, 2)
    assert abs(r['replica_hours'] - 5 / 7200) < 1e-12 and pooled['above'] == 2


def test_episodes_split_on_quiet_gap():
    assert ma.episodes([]) == 0
    assert ma.episodes([1.0, 5.0, 19.9]) == 1
    assert ma.episodes([1.0, 16.0, 16.5]) == 2


def test_v5_heldout_share():
    receipt = dict(thresholds={'ns/w:c': dict(blocks=4000, gumbel=5.0, gumbel_exceedance=0.0005)})
    h = ma.v5_heldout(receipt, {'ns/w:c': ('x', 5.0)})
    assert h == {'ns/w:c': dict(blocks=4000, above=2)}
    rows, pooled = ma.summarize({('ns/w:c', 'p', 'c', 0): 1.0}, {'ns/w:c': 2}, [], {'ns/w:c': ('x', 5.0)}, h)
    assert rows['ns/w:c']['v5_heldout']['rate'] == 0.0005 and pooled['v5_heldout']['above'] == 2
    with pytest.raises(ValueError):
        ma.v5_heldout(receipt, {'ns/w:c': ('x', 5.1)})
