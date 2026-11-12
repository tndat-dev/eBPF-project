"""Follow-up audit of the RCA: why an attack trial has no case of its own, and the exec lag."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))

import rca_follow_up as m  # noqa: E402

ATTACK = '/operator/attack'


def trial(start, pod='p'):
    return dict(start_at=start, node_name='n', pod_uid=pod, container_name='c', binary_path=ATTACK)


def line(window_end, verdict, binary=None, at=None, received=None, pod='p'):
    latest = dict(binary=binary, at=at, received=received) if binary else None
    return dict(verdict=verdict, identity=json.dumps(['n', pod, 'c']), window_end=window_end, latest_exec=latest)


def test_classes_of_an_attack_trial():
    audit = [line(101.0, 'allowed', ATTACK, 100.2, 100.3),                       # trial at 100: follow-up allowed
             line(201.0, 'binary_not_new', '/bin/ls', 180.0, 180.1),             # trial at 200: the exec had not arrived
             line(205.0, 'too_soon', '/bin/ls', 180.0, 180.1),
             line(301.0, 'too_soon', ATTACK, 300.2, 300.4),                      # trial at 300: known and refused
             line(399.0, 'allowed', ATTACK, 398.0, 398.1)]                       # before the trial at 400: not its window
    cases = {('n', 'q', 'c'): [501.0]}
    trials = [trial(100.0), trial(200.0), trial(300.0), trial(400.0), trial(500.0, 'q'), trial(50.0)]
    out = m.analyse(audit, cases, trials, since=90.0, stalls=[(190.0, 210.0)])
    assert out['attack_trials'] == 5                                             # the trial at 50 is before --since
    assert out['classes'] == dict(own_case=2, exec_missing=1, exec_known_refused=1, no_decision=1)
    assert out['verdicts_of_trials_without_own_case'] == dict(binary_not_new=1, too_soon=2)
    assert out['without_own_case_in_stall'] == 1
    assert [r['cls'] for r in out['trials_without_own_case']] == ['exec_missing', 'exec_known_refused', 'no_decision']
    lag = out['exec_lag_seconds']
    assert lag['attack_binary']['n'] == 2 and abs(lag['attack_binary']['max'] - 0.2) < 1e-9
    assert lag['outside_stall']['n'] == 5 and lag['inside_stall'] is None      # no exec inside the stalled span itself


def test_exec_lag_is_split_by_the_stalled_spans():
    audit = [line(10.0, 'no_exec', '/bin/a', 5.0, 5.1), line(60.0, 'no_exec', '/bin/a', 20.0, 55.0)]
    out = m.analyse(audit, {}, [], since=0.0, stalls=[(50.0, 58.0)])
    lag = out['exec_lag_seconds']
    assert lag['outside_stall']['n'] == 1 and lag['inside_stall']['n'] == 1 and lag['inside_stall']['over_10s'] == 1


def test_case_windows_reads_the_signal_trigger(tmp_path):
    doc = dict(nodes=[dict(kind='container'), dict(kind='signal', trigger=dict(node_name='n', pod_uid='p', container_name='c', window_end=7.5))])
    (tmp_path / 'a.json').write_text(json.dumps(doc))
    assert m.case_windows(tmp_path) == {('n', 'p', 'c'): [7.5]}
