import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import test_lidds_evaluate_v2 as base  # noqa: E402
spec = importlib.util.spec_from_file_location('mlg', ROOT / 'scripts' / 'analysis' / 'lidds_ml_groups.py')
mlg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mlg)


def test_language_model_ranks_unseen_sequences_lower_but_never_zero():
    lm = mlg.NgramLM(n=3)
    lm.learn([('read', 'write', 'read'), ('write', 'read', 'write')] * 50)
    lm.finalize()
    seen, unseen = lm.prob(('read', 'write', 'read')), lm.prob(('read', 'write', 'mmap'))
    assert seen > 0.5 and 0 < unseen < seen
    assert lm.score([('read', 'write', 'mmap')]) > lm.score([('read', 'write', 'read')])


def test_fusions():
    import numpy as np
    ps = np.array([[0.001, 0.5], [0.5, 0.5], [0.5, 0.5]])
    assert np.allclose(mlg.combine(ps, 'bonferroni'), [0.003, 1.0])
    c = mlg.combine(ps, 'cauchy')
    assert c[0] < 0.01 and 0.4 < c[1] < 0.6


def test_end_to_end_reproduces_the_v1_ml_arm_and_scores_every_configuration(tmp_path):
    archive = base._archive(tmp_path)
    header = tmp_path / 'unistd.h'
    header.write_text('\n'.join(f'#define __NR_{n} {i}' for i, n in enumerate(base.NAMES + [f'x{j}' for j in range(320)])) + '\n')
    base.convert.convert_scenario(archive, tmp_path / 'conv' / 'SCN', header=header)
    info, outcomes, kept = mlg.evaluate('SCN', tmp_path / 'conv' / 'SCN', archive, 0.05)
    assert len(outcomes) == len(mlg.FIX_A) * len(mlg.GROUP_SETS) * len(mlg.FUSIONS) == 24
    _, raw = base.ev2.evaluate_scenario('SCN', tmp_path / 'conv' / 'SCN', archive, exec_set=set())
    old = sorted(tuple(o[:4]) + (o[5], o[6]) for o in raw['ml'])
    new = sorted(tuple(o[:4]) + (o[5], o[6]) for o in outcomes[mlg.config_name(False, ('g0',), 'bonferroni')])
    assert old == new                                   # G0, no fix, Bonferroni = the current ML
    assert all(v.shape[1] == 11 for v in kept.values() if len(v))
    assert {'g0_tree_0', 'g0_tree_1', 'g0_support', 'g1_tree_1', 'g2_lm'} <= set(info['fits'])
