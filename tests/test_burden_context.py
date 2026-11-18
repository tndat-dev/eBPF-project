"""burden_context.py: episodes, replica concurrency and incident grouping."""
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'analysis'))
import burden_context as bc  # noqa: E402


def test_episodes_merge_alarms_less_than_quiet_apart():
    assert bc.episodes([0, 5, 30, 31]) == [(0, 5), (30, 31)]


def test_consensus_labels_concurrent_replicas_multi():
    alarms = {('p1', 'c'): [100.0, 500.0], ('p2', 'c'): [102.0], ('p3', 'x'): [100.0]}
    workload = {('p1', 'c'): 'w', ('p2', 'c'): 'w', ('p3', 'x'): 'v'}
    counts, eps = bc.consensus(alarms, workload, lambda t: True)
    assert counts['w'] == [1, 2]          # p1@500 single; p1@100 and p2@102 multi
    assert counts['v'] == [1, 0]          # another workload does not count


def test_incidents_group_one_workload_within_the_gap():
    eps = [('w', 0, 10, False), ('w', 300, 310, False), ('w', 2000, 2001, True), ('v', 0, 1, False)]
    assert bc.incidents(eps) == {'w': 2, 'v': 1}


def test_concurrent_window():
    x = np.array([10.0, 50.0])
    assert bc.concurrent(x, 14, 14) and not bc.concurrent(x, 20, 30)
