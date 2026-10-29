import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rgc', ROOT/'scripts'/'analysis'/'rca_grouping_causes.py')
rgc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rgc)
ID = ('n', 'u', 'c')


def _trial(start):
    return dict(start_at=start, node_name='n', pod_uid='u', container_name='c', trial_id=f't{start}'), dict(start_at=start - 20)


def test_each_cause():
    cases = {ID: [(85.0, 86.0), (185.0, 186.0), (285.0, 286.0), (385.0, 386.0), (505.0, 507.0)]}   # benign cases; t500 has its own
    starts = {ID: [dict(episode='e1', bridge_received_at=84.0), dict(episode='e3', bridge_received_at=291.0),
                   dict(episode='e4', bridge_received_at=398.0)]}
    ends = {'e1': 120.0, 'e3': 293.0, 'e4': 399.0}
    trials = [_trial(100.0), _trial(200.0), _trial(290.0), _trial(390.0), _trial(500.0)]
    causes, rows = rgc.classify(trials, cases, starts, ends)
    assert {r['trial_id']: r['cause'] for r in rows} == {'t100.0': 'episode_carried_over', 't200.0': 'no_new_episode',
                                                          't290.0': 'trigger_refused_too_soon', 't390.0': 'trigger_refused_exec_check'}
    assert sum(causes.values()) == 4
