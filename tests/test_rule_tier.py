import importlib.util
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'/'analysis'))
spec = importlib.util.spec_from_file_location('rule_tier', ROOT/'scripts'/'analysis'/'rule_tier.py')
rt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rt)
bl = rt.bl


def test_paged_metrics_hold_back_probe_only_episodes_and_fail_open():
    # one container, three normal episodes: probe-only case, normal case, no case
    end = np.array([10.0, 10.5, 100.0, 100.5, 200.0, 300.0, 300.5])
    alarm = np.array([1, 1, 1, 1, 1, 0, 1], bool)
    a = dict(ident=np.zeros(7, int), workload=np.zeros(7, int), end=end, start=end - 0.5,
             normal=np.array([1, 1, 1, 1, 1, 0, 0], bool), hours=1.0)
    triage = {('n', 'p', 'c'): [(12.0, True), (101.0, False), (301.0, True)]}
    tr = bl.Trials.__new__(bl.Trials)
    tr.label = np.array(['attack', 'control']); tr.scenario = np.array(['x', 'x'])
    tr.lo, tr.hi = np.array([5, 6]), np.array([7, 7])
    tr.kernel, tr.start = np.array([299.0, np.nan]), np.array([299.5, 300.2])
    out = rt.paged_metrics(alarm, a, tr, triage, [('n', 'p', 'c')])
    assert out['episodes'] == 3 and out['episodes_with_case'] == 2 and out['held_back'] == 1
    assert out['paged_failopen'] == 2.0                 # the episode without a case pages
    assert abs(out['paged_estimate'] - 1.5) < 1e-12     # it is held back at the matched share (1 of 2)
    assert out['attack'] == 0.0 and out['attack_held_back'] == 1   # its only case in [start, start + 20] is probe-only


def test_rule_tier_rescores_the_ml_choices_unchanged(tmp_path, monkeypatch):
    import json
    sys.path.insert(0, str(ROOT/'tests'))
    import test_burden_levers as tb
    tb.test_end_to_end_on_a_synthetic_run(tmp_path, monkeypatch)        # writes tables, calibration, out.json
    monkeypatch.setattr(rt, 'load_triage', lambda cases, spec: ({}, 0))
    runs = []
    for r in ('r1', 'r2'):
        runs += ['--run', f'name={r},table={tmp_path/r}.npz,since=10000.0,campaign={tmp_path/r/"campaign"},cases={tmp_path}']
    out = tmp_path/'rule.json'
    monkeypatch.setattr(sys, 'argv', ['rule_tier', *runs, '--calibration', str(tmp_path/'calibration.npz'),
                                      '--calibration-table', str(tmp_path/'cal.npz'), '--ml-results', str(tmp_path/'out.json'),
                                      '--probe-spec', str(tmp_path/'spec.json'), '--output', str(out)])
    (tmp_path/'spec.json').write_text(json.dumps(dict(workloads={})))
    rt.main()
    ref = json.loads(out.read_text())['runs']['r1']['configs']['reference']
    for k in ('burden', 'attack', 'control', 'precision', 'p95'):
        assert ref['ml'][k] == ref['ml_as_chosen'][k]                   # the rule tier sees the same ML alarms
    assert ref['paged']['held_back'] == 0 and ref['paged']['attack'] == ref['ml']['attack']   # no case: fail-open
