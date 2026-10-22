import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('fgv', Path(__file__).parents[1]/'scripts'/'analysis'/'feature_group_verdict.py')
fgv = importlib.util.module_from_spec(spec); spec.loader.exec_module(fgv)


def diff(point, lo, hi, one):
    return dict(point=point, ci95=[lo, hi], lower95_one_sided=one)


def sets(comp, rec, sep, p95):
    boot = dict(budgets={'1': {'base29': {}, comp: dict(recall_diff=rec, separation_diff=sep)}})
    res = dict(matched_budget={'1': {'base29': dict(delay_p95=2.0), comp: dict(delay_p95=2.0 + p95)}})
    return {'pulse-live-recalibrated': (res, boot)}


def test_needed_removable_inconclusive():
    v = fgv.verdict(sets('drop_rolling', diff(-.04, -.09, -.004, -.08), diff(.18, .08, .30, .09), 0))
    assert v['drop_rolling']['verdict'] == 'needed' and v['drop_rolling']['provisional']
    v = fgv.verdict(sets('drop_ratios', diff(0, -.01, .01, -.008), diff(0, -.02, .02, -.015), .1))
    assert v['drop_ratios']['verdict'] == 'removable'
    v = fgv.verdict(sets('drop_ratios', diff(-.005, -.015, .002, -.013), diff(-.056, -.127, .001, -.11), 0))
    assert v['drop_ratios']['verdict'] == 'inconclusive'
    v = fgv.verdict(sets('history1', diff(0, -.01, .01, -.008), diff(0, -.02, .02, -.015), .25))
    assert v['history1']['verdict'] == 'needed'          # p95 worse by >= 0.2 s on every set
    assert v['drop_log_counts']['verdict'] == 'not_evaluated'


def test_separation_clause_uses_only_the_set_with_benign_launches():
    live = sets('drop_ratios', diff(0, -.01, .01, -.008), diff(0, -.02, .02, -.015), .1)
    dev = sets('drop_ratios', diff(0, -.01, .01, -.008), None, .1)['pulse-live-recalibrated']
    v = fgv.verdict(dict(live, **{'pulse-attack-dev': dev}))
    assert v['drop_ratios']['verdict'] == 'removable' and not v['drop_ratios']['provisional']
    only_dev = fgv.verdict({'pulse-attack-dev': dev})
    assert only_dev['drop_ratios']['verdict'] == 'inconclusive'     # no set can show the separation clause
