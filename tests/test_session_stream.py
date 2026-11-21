"""session-stream-v1: session features and the burden of each system."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import session_stream as ss  # noqa: E402


def test_features_count_calls_and_error_tokens():
    ptrace_err = (101 << 23) | (1 << 21) | 1          # ptrace, kind 1 (errno)
    read_size = (0 << 23) | (2 << 21) | 12            # read, kind 2 (size)
    calls, events, errors = ss.features([[0, 0, 0, ptrace_err, 3], [0, 0, 0, read_size, 2]])
    assert calls == {101: 3, 0: 2} and events == 5 and errors == 3


def test_burden_merges_alarms_into_episodes_per_system():
    alarms = [(('p', 'c'), 'w', t, dict(S0=True, S1=t < 5, S2=False), True, True) for t in (0.0, 1.0, 2.0, 40.0)]
    out = ss.burden(alarms, {'w': 3600.0})
    assert out['replica_hours'] == 1.0
    assert out['systems']['S0']['episodes'] == 2 and out['systems']['S1']['episodes'] == 1
    assert out['systems']['S2']['episodes'] == 0


def test_branch_threshold_is_the_gumbel_quantile():
    assert abs(ss.gumbel_threshold((4.0, 1.0), 0.0003) - (4.0 + 8.1115)) < 1e-3
