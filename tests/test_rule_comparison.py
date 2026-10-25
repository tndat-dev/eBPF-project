import importlib.util
from pathlib import Path
import sys

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'/'analysis'))
spec = importlib.util.spec_from_file_location('rule_comparison', ROOT/'scripts'/'analysis'/'rule_comparison.py')
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)
bl = rc.bl

FIELDS = ['workload_key', 'node_name', 'pod_uid', 'container_name', 'workload_revision', 'cgroup_id']


def _setup():
    """Two containers (u0 of w0, u1 of w1), windows every 0.5 s up to 600 s; campaign 300-600, normal from 50."""
    end = np.arange(1, 1201) * 0.5
    a = dict(ident=np.repeat([0, 1], 1200), end=np.tile(end, 2), start=np.tile(end - 0.5, 2),
             identities=[['production/w0:app', 'n', 'u0', 'app', 'r', 'c0'], ['production/w1:app', 'n', 'u1', 'app', 'r', 'c1']],
             identity_fields=FIELDS)
    a['normal'] = a['end'] < 300
    row = lambda ident, e: ident * 1200 + int(round(e / 0.5)) - 1
    alarm = np.zeros(2400, bool)
    for ident, e in ((0, 100.0), (0, 100.5), (1, 200.0), (0, 311.0), (0, 351.0)):
        alarm[row(ident, e)] = True
    tr = bl.Trials.__new__(bl.Trials)
    tr.label = np.array(['attack', 'attack', 'control', 'benign'])
    tr.scenario = np.array(['s', 's', 's', 's'])
    tr.start = np.array([310.0, 330.0, 350.0, 370.0]); tr.kernel = np.array([310.2, 330.1, np.nan, np.nan])
    tr.rate = np.full(4, 12.0)
    idents = [0, 1, 0, 1]
    tr.lo = np.array([row(i, s + 0.5) for i, s in zip(idents, tr.start)])
    tr.hi = np.array([row(i, s + 15.0) + 1 for i, s in zip(idents, tr.start)])
    falco = dict(trials=[dict(kind='attack', start=310.0, detected=True, first_event=310.6),
                         dict(kind='attack', start=330.0, detected=False, first_event=None),
                         dict(kind='control', start=350.0, detected=False, first_event=None),
                         dict(kind='benign', start=370.0, detected=False, first_event=None)],
                 normal_events=[dict(time=108.0, pod='pod0', container_name='app'),     # merges with the ML episode
                                dict(time=250.0, pod='pod1', container_name='app'),     # its own episode
                                dict(time=150.0, pod='ghost', container_name='x'),      # unmapped pod
                                dict(time=20.0, pod='pod0', container_name='app'),      # before the normal span
                                dict(time=400.0, pod='pod0', container_name='app')])    # in the campaign
    tripwire = dict(trials=[dict(label='attack', start=310.0, novel=False, first_novel_end=None),
                            dict(label='attack', start=330.0, novel=True, first_novel_end=331.0),
                            dict(label='control', start=350.0, novel=False, first_novel_end=None),
                            dict(label='benign', start=370.0, novel=None, first_novel_end=None)],
                    normal=dict(alerts=[dict(end=200.4, pod_uid='u1', container_name='app')]))
    cases = {('u0', 'app'): [(100.2, True, 101.0), (311.0, False, 312.5), (351.0, True, 352.0)]}
    names = {'pod0': {'u0'}, 'pod1': {'u1', 'u1-before-restart'}}
    return a, tr, alarm, falco, tripwire, cases, names


def test_arms_combine_streams_per_trial_and_per_container():
    a, tr, alarm, falco, tripwire, cases, names = _setup()
    out = rc.compare(a, tr, 50.0, alarm, falco, tripwire, cases, names, {}, (300.0, 600.0))
    arms = {k: v['primary'] for k, v in out['arms'].items()}
    assert arms['A']['attack'] == .5 and arms['A']['control'] == 1.0 and arms['A']['precision'] == .5
    assert arms['B1']['attack'] == .5 and abs(arms['B1']['p50'] - .4) < 1e-9          # Falco earlier than ML
    assert arms['B2']['attack'] == 1.0 and arms['B2']['control'] == 1.0
    assert arms['B3']['attack'] == .5 and arms['B3']['control'] == 0.0                 # probe-only trial held back
    assert abs(arms['B3']['p50'] - 2.3) < 1e-9                                          # case creation time
    assert arms['B_all']['attack'] == 1.0 and arms['B_all']['control'] == 0.0 and arms['B_all']['precision'] == 1.0
    hours = 2 * 499 * 0.5 / 3600                                                        # starts >= 50, ends < 300
    assert abs(out['normal']['replica_hours'] - hours) < 1e-12
    episodes = {k: round(v['burden'] * hours, 6) for k, v in out['arms'].items()}
    assert episodes == dict(A=2, B1=4, B2=2, B3=1, B_all=4)
    s = out['streams']
    assert s['falco_unmapped_pods'] == ['ghost'] and s['falco_pod_names_with_several_pods'] == ['pod1']
    assert s['falco_normal_events'] == 3 and s['falco_episodes_outside_window_table'] == 1
    assert s['ml_normal_episodes'] == 2 and s['ml_normal_episodes_held_back'] == 1 and s['ml_normal_episodes_with_case'] == 1
    alone = out['standalone']
    assert alone['falco']['primary']['attack'] == .5 and alone['tripwire']['primary']['attack'] == .5
    assert round(alone['falco']['burden'] * hours, 6) == 3 and round(alone['tripwire']['burden'] * hours, 6) == 1
    assert round(out['check']['ml_burden_window_table_episodes'] * hours, 6) == 2
    assert s['triage_failopen_trials'] == 0 and s['trials_unmatched'] == dict(falco=0, tripwire=0)
    cmp_ = out['comparison_primary']
    assert set(cmp_) == {'B1', 'B2', 'B3', 'B_all'}
    assert abs(cmp_['B1']['burden_diff']['point'] - 2 / hours) < 1e-9
    assert cmp_['B2']['attack_diff']['point'] == .5 and cmp_['B3']['control_diff']['point'] == -1.0
    assert out['arms']['B1']['normal_episodes_by_workload']['unmapped:ghost:x'] == 1


def test_triage_and_trial_keys():
    cases = [(10.0, True, 11.0), (12.0, False, 13.0), (40.0, True, 41.0)]
    assert rc.triage(cases, 9, 11) == (True, True, 11.0)
    assert rc.triage(cases, 9, 13) == (True, False, 11.0)
    assert rc.triage(cases, 20, 30) == (False, False, None)
    assert rc.triage(None, 0, 100) == (False, False, None)
    with pytest.raises(ValueError, match='share'):
        rc.by_trial([dict(kind='attack', start=1.0), dict(label='attack', start=1.0004)])
