"""H1 of pulse-live-v6-v1: the native stream is the window minus its session part."""
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import native_stream as ns  # noqa: E402
from sentinel_pulse.detector.token_model import TOK_NONE, CountTokenLM  # noqa: E402

A, B, T = 1 << 23, 2 << 23, 4 << 23


def model():
    lm = CountTokenLM()
    for _ in range(300):
        lm.learn((A, B, A, B))
        lm.learn((B, A, B, A))
    return lm.finalize()


def test_native_is_the_window_minus_the_session_part():
    grams = [[A, B, A, B, 9], [B, A, B, A, 4], [T, T, T, T, 5]]
    session = [[T, T, T, T, 5], [A, B, A, B, 2]]
    assert sorted(ns.native_of(grams, session)) == sorted([[A, B, A, B, 7], [B, A, B, A, 4]])
    with pytest.raises(ValueError):
        ns.native_of([[A, B, A, B, 1]], [[A, B, A, B, 2]])


def test_a_session_only_tool_flags_the_whole_window_but_not_the_native_stream():
    lm = model()
    service = [A, B, A, B, 40]
    tool = [[TOK_NONE, TOK_NONE, TOK_NONE, T, 1], [T, T, T, T, 20]]
    windows = {('p', 'c'): [(101.0, [service] + tool, tool), (201.0, [service] + tool, [])]}
    trials = [dict(label='admin', start=100.0, key=('p', 'c'), pair=1, workload='w', rate=12),
              dict(label='attack', start=200.0, key=('p', 'c'), pair=1, workload='w', rate=12)]
    res = ns.evaluate(trials, windows, {'w': ('unused', 5.0)}, {'w': lm})
    assert res['admin']['whole']['k'] == 1 and res['admin']['native']['k'] == 0
    assert res['attack']['native']['k'] == 1          # the same grams counted on native threads
    assert 0 < res['admin']['session_share'] < 1


def test_control_of_a_dilution_pair_goes_to_its_pad_set():
    lm = model()
    win = [(101.0, [[A, B, A, B, 40]], [])]
    trials = [dict(label='control', start=100.0, key=('p', 'c'), pair=1, workload='w', rate=None),
              dict(label='attack', start=100.0, key=('p', 'c'), pair=1, workload='w', rate=12, pad=300),
              dict(label='control', start=100.0, key=('p', 'c'), pair=2, workload='w', rate=None),
              dict(label='attack', start=100.0, key=('p', 'c'), pair=2, workload='w', rate=12)]
    res = ns.evaluate(trials, {('p', 'c'): win}, {'w': ('unused', 5.0)}, {'w': lm})
    assert res['control-pad300']['native']['n'] == 1 and res['control']['native']['n'] == 1
    assert res['control-primary']['native']['n'] == 1
