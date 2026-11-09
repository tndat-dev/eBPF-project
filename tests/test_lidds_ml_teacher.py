import importlib.util
from pathlib import Path
import sys

import numpy as np
import pytest

pytest.importorskip('torch')  # the teacher model needs torch, which the pinned test stack leaves out

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import test_lidds_evaluate_v2 as base  # noqa: E402
spec = importlib.util.spec_from_file_location('mlteach', ROOT / 'scripts' / 'analysis' / 'lidds_ml_teacher.py')
te = importlib.util.module_from_spec(spec)
spec.loader.exec_module(te)


def grams(rng, n=4000):
    """A periodic normal language: read, write, futex, close repeating, with a rare token seen once."""
    cycle = ['read#3', 'write#3', 'futex', 'close']
    seq = [cycle[i % 4] for i in range(n)]
    seq[17] = 'rare'
    return [tuple(seq[max(0, i - te.CONTEXT):i + 1]) for i in range(len(seq))]


def test_teacher_learns_the_language_and_grades_what_it_never_saw():
    m = te.Teacher(seed=7, hidden=32, embedding=16)
    report = m.fit(grams(np.random.default_rng(1)), epochs=8, seconds=120)
    assert report['epochs'] >= 1 and report['oov_targets'] >= 1
    ctx = ('read#3', 'write#3', 'futex', 'close', 'read#3', 'write#3', 'futex', 'close')
    usual = m.nll([ctx + ('read#3',)])[0]
    odd_order = m.nll([ctx + ('write#3',)])[0]
    unseen = m.nll([ctx + ('ptrace',)])[0]
    assert usual < 1.0 < odd_order and usual < unseen and np.isfinite(unseen)


def test_fit_stops_at_its_time_limit():
    m = te.Teacher(seed=7, hidden=8, embedding=4)
    report = m.fit(grams(np.random.default_rng(1)), epochs=50, seconds=0)
    assert report['epochs'] <= 1 and report['stopped_by_time']


def test_end_to_end_scores_validation_and_test_with_the_token_windows(tmp_path):
    archive = base._archive(tmp_path)
    out, meta, report = te.evaluate(archive, epochs=2, seconds=60, hidden=16, embedding=8)
    assert sum(k.startswith('val/') for k in out) == 45 and len(meta) == 16
    assert all(v.shape[1] == len(te.COLUMNS) for v in out.values())
    attack = [n for n, r in meta.items() if r['exploit']][0]
    assert out[attack][:, 1].max() > np.median(out[attack][:, 1])
    assert report['train_cpu_hours'] >= 0
