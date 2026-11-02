import importlib.util
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import test_lidds_evaluate_v2 as base  # noqa: E402
spec = importlib.util.spec_from_file_location('mls_scores', ROOT / 'scripts' / 'analysis' / 'lidds_ml_scores.py')
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)


def test_surprise_mass_grows_with_the_number_of_rare_events_and_marks_unseen_items():
    m = sc.Multinomial()
    m.learn(['a'] * 1000 + ['b'] * 2)
    m.finalize()
    assert m.mass(['a'] * 50) == (0.0, 0.0)                  # common items add nothing
    one, unseen_one = m.mass(['new'])
    three, unseen_three = m.mass(['new'] * 3)
    assert one > 0 and unseen_one == one and np.isclose(three, 3 * one) and unseen_three == three
    rare, unseen_rare = m.mass(['b'])
    assert 0 < rare < one and unseen_rare == 0.0             # rare but seen: graded, not 'unseen'


def test_end_to_end_keeps_scores_that_give_back_the_v1_p_values(tmp_path):
    archive = base._archive(tmp_path)
    header = tmp_path / 'unistd.h'
    header.write_text('\n'.join(f'#define __NR_{n} {i}' for i, n in enumerate(base.NAMES + [f'x{j}' for j in range(320)])) + '\n')
    base.convert.convert_scenario(archive, tmp_path / 'conv' / 'SCN', header=header)
    out, meta = sc.evaluate(tmp_path / 'conv' / 'SCN', archive, 0.05)
    _, _, kept = sc.g.evaluate('SCN', tmp_path / 'conv' / 'SCN', archive, 0.05)
    names = [n for n in meta if len(out[n])]
    assert names and all(out[n].shape[1] == len(sc.COLUMNS) for n in names)
    assert any(k.startswith('val/') and len(v) for k, v in out.items())
    cal = np.sort(np.concatenate([v[:, sc.COLUMNS.index('support')] for k, v in out.items() if k.startswith('val/')]))
    for n in names:
        p = (len(cal) - np.searchsorted(cal, out[n][:, sc.COLUMNS.index('support')], side='left') + 1.0) / (len(cal) + 1.0)
        assert np.allclose(p, kept[n][:, 3], atol=2 / len(cal))   # same support p-values as lidds_ml_groups
        assert np.array_equal(out[n][:, 0], kept[n][:, 0])
