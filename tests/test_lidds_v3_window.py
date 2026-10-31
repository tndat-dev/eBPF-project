import importlib.util
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
spec = importlib.util.spec_from_file_location('v3w', ROOT / 'scripts' / 'analysis' / 'lidds_v3_window.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


def test_firing_needs_two_branches_inside_the_horizon():
    arms = dict(system=[10.0], path=[12.0], ngram=[40.0])
    assert w.firings(arms, 0.5) == []
    assert w.firings(arms, 2.0) == []                  # 12 - 2 = 10: the window ending at 10 is outside (10, 12]
    assert w.firings(arms, 5.0) == [12.0]
    assert w.firings(arms, math.inf) == [12.0, 40.0]   # per recording: any earlier alarm of another branch counts
    assert w.firings(dict(system=[1.0, 2.0, 3.0]), math.inf) == []   # one branch alone never fires


def doc():
    """One scenario: attacks seen by path at 21 s and ngram at 23 s (exploit 20 s); a normal recording with path at
    5 s and bytes at 50 s; 30 % of attacks development."""
    alarms = {}
    for i in range(10):
        alarms[f'a{i}'] = dict(split='test-normal_and_attack', subset='development' if i < 3 else 'official',
                               exploit=20.0, arms=dict(path=[21.0], ngram=[23.0]))
    for i in range(20):
        alarms[f'n{i}'] = dict(split='test-normal', subset='official', exploit=None,
                               arms=dict(path=[5.0], bytes=[50.0]) if i == 0 else {})
    return dict(scenarios={'SCN': dict(alarms=alarms)})


def test_horizon_trades_recall_against_false_alarms_and_latency_is_the_second_branch():
    off = w.evaluate(doc(), 'official')
    assert off['H0.5s']['pooled']['recall'] == 0.0
    assert off['H5s']['pooled']['recall'] == 1.0 and off['H5s']['pooled']['latency_p50'] == 3.0
    assert off['H5s']['pooled']['detected_within_3s'] == 7
    every = w.evaluate(doc(), 'all')
    assert every['H30s']['pooled']['false_alarm_recordings'] == 0          # 5 s and 50 s are 45 s apart
    assert every['per_recording']['pooled']['false_alarm_recordings'] == 1


def test_selection_prefers_the_shortest_horizon_at_the_highest_recall():
    chosen, ok = w.select(w.evaluate(doc(), 'development'))
    assert ok and chosen == 'H5s'
