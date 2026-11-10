"""Step 2 of lidds-ml-v5: gate semantics per trial, phase maxima from benign launches only, and the registered choice."""
import math
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

s = pytest.importorskip('pulse_v5_select')


def w(end, score, pool, execve=False):
    return ('p', 'c', end, score, pool, execve)


def test_since_exec_counts_from_the_last_execve():
    assert s.since_exec([w(1, 0, 0), w(2, 0, 0, True), w(3, 0, 0), w(5, 0, 0, True)]) == [math.inf, 0, 1, 0]


def test_hold_candidate_skips_the_phase_and_needs_the_pool():
    windows = [w(100.0, 30, 30, True), w(100.5, 30, 30), w(102.0, 30, 9), w(103.0, 30, 12)]
    since = s.since_exec(windows)
    assert s.fires(windows, since, 100.0, 10, None, 0.0, None)                 # no gate: the first window
    assert not s.fires(windows[:2], since[:2], 100.0, 10, None, 1.0, None)     # both within the 1 s hold
    assert s.fires(windows, since, 100.0, 10, 10, 1.0, None)                   # 103.0: outside, pool 12 > 10
    assert not s.fires(windows[:3], since[:3], 100.0, 10, 10, 1.0, None)       # 102.0: pool 9 <= 10
    assert not s.fires(windows, since, 100.0, 40, None, 0.0, None)             # below the workload threshold


def test_phase_candidate_uses_its_own_threshold_inside_the_phase():
    windows = [w(100.0, 30, 30, True), w(102.0, 30, 9)]
    since = s.since_exec(windows)
    assert s.fires(windows, since, 100.0, 10, 10, 1.0, 25)        # inside: 30 > 25
    assert not s.fires(windows, since, 100.0, 10, 10, 1.0, 35)    # inside: 30 <= 35; outside: 9 <= 10
    assert s.fires(windows, since, 100.0, 10, 8, 1.0, 35)         # outside: 9 > 8


def test_trial_window_is_start_to_start_plus_15():
    windows = [w(99.9, 30, 30), w(115.1, 30, 30)]
    assert not s.fires(windows, s.since_exec(windows), 100.0, 10, None, 0.0, None)


def test_phase_maxima_come_from_benign_launches_only():
    by = {('p', 'c'): [w(100.0, 0, 20, True), w(100.5, 0, 25), w(103.0, 0, 99), w(200.0, 0, 50, True)]}
    trials = [dict(label='benign', start=100.0, key=('p', 'c')), dict(label='attack', start=200.0, key=('p', 'c'))]
    assert s.phase_maxima(trials, by, 1.0) == [25]


def result(primary, benign, phase=False, seconds=1.0, level=0.01):
    return dict(primary_hits=primary, primary_n=100, benign_hits=benign, benign_n=100, phase=phase, seconds=seconds, level=level)


def test_choice_follows_the_registered_order():
    results = dict(a=result(100, 50), b=result(96, 10), c=result(94, 0), d=result(100, 10, phase=True), e=result(100, 0))
    assert s.choose(results, {'a', 'b', 'c', 'd'}) == 'd'       # e is not eligible, c misses 95 %, d (phase) before b
    assert s.choose(results, {'a', 'c'}) == 'a'
    assert s.choose(results, {'c'}) is None
    ties = dict(x=result(100, 5, seconds=2.0), y=result(100, 5, seconds=1.0, level=0.001), z=result(100, 5, seconds=1.0, level=0.01))
    assert s.choose(ties, set(ties)) == 'z'                     # shorter seconds, then the looser level


def test_gate_files_for_hold_phase_and_no_gate(tmp_path):
    import json
    (tmp_path / 'pool.lm.json.gz').write_bytes(b'x')
    spec = {'w': dict(lm='m', lm_sha256='h', threshold=10.0)}
    fits = {'w': {'0': (5.0, 1.0), '1': (6.0, 1.0), '2': (7.0, 1.0)}}
    out = tmp_path / 'hold'
    out.mkdir()
    s.gate_files('token-hold1-pool0.01', dict(seconds=1.0, level=0.01, phase=False, phase_threshold=None), spec, fits, tmp_path, out)
    gate, models = json.loads((out / 'GATE.json').read_text()), json.loads((out / 'MODELS.json').read_text())
    assert gate['exec_hold_seconds'] == 1.0 and 'phase_threshold' not in gate
    assert models['w']['pool_threshold'] == s.threshold((6.0, 1.0), 0.01)
    out = tmp_path / 'phase'
    out.mkdir()
    s.gate_files('token-phase2-pool0.001', dict(seconds=2.0, level=0.001, phase=True, phase_threshold=33.0), spec, fits, tmp_path, out)
    assert json.loads((out / 'GATE.json').read_text())['phase_threshold'] == 33.0
    out = tmp_path / 'plain'
    out.mkdir()
    s.gate_files('token-hold0-poolnone', dict(seconds=0.0, level=None, phase=False, phase_threshold=None), spec, fits, tmp_path, out)
    assert not (out / 'GATE.json').exists() and 'pool_threshold' not in json.loads((out / 'MODELS.json').read_text())['w']
    out = tmp_path / 'holdonly'
    out.mkdir()
    s.gate_files('token-hold1-poolnone', dict(seconds=1.0, level=None, phase=False, phase_threshold=None), spec, fits, tmp_path, out)
    assert json.loads((out / 'MODELS.json').read_text())['w']['pool_threshold'] == -1.0
