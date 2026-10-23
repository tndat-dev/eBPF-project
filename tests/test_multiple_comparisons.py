import importlib.util
import json
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location('multiple_comparisons', Path(__file__).parents[1]/'scripts/analysis/multiple_comparisons.py')
mc = importlib.util.module_from_spec(spec); spec.loader.exec_module(mc)


def test_holm_steps_down_and_stays_monotone():
    assert mc.holm([0.01, 0.04, 0.03, 0.5]) == [0.04, 0.09, 0.09, 0.5]


def test_family_skips_the_reference_and_flags_conclusions_that_holm_overturns(tmp_path):
    diff = lambda point, lo, hi, p: dict(point=point, ci95=[lo, hi], p_two_sided=p)
    boot = dict(reference='base29', reps=10000, budgets={
        '1': dict(base29=dict(recall_diff=diff(0, 0, 0, 1.0)),
                  ae=dict(recall_diff=diff(0.05, 0.02, 0.08, 0.0002), separation_diff=diff(-0.26, -0.39, -0.13, 0.0002))),
        '5': dict(ae=dict(recall_diff=diff(0.02, 0.001, 0.04, 0.03), separation_diff=None)),
        '18': dict(ae=dict(recall_diff=diff(0.02, 0.001, 0.04, 0.03)))})
    path, out = tmp_path/'boot.json', tmp_path/'out.json'
    path.write_text(json.dumps(boot))
    sys.argv = ['mc', '--bootstrap', str(path), '--metric', 'recall_diff', '--metric', 'separation_diff', '--output', str(out)]
    mc.main()
    d = json.loads(out.read_text())
    assert d['tests'] == 4                                           # base29 and the missing separation are left out
    assert [(r['budget'], r['significant_holm']) for r in d['rows']] == [('1', True), ('1', True), ('5', False), ('18', False)]
    assert [c['budget'] for c in d['changed']] == ['5', '18']           # 2 x 0.03 = 0.06 after Holm, though each CI excludes 0
