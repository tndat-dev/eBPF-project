import importlib.util
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'/'analysis'))
sys.path.insert(0, str(ROOT/'tests'))
spec = importlib.util.spec_from_file_location('recal_comparison', ROOT/'scripts'/'analysis'/'recal_comparison.py')
rcmp = importlib.util.module_from_spec(spec); spec.loader.exec_module(rcmp)
from test_rule_comparison import _setup  # noqa: E402


def test_identical_arms_tie_and_do_not_win():
    a, tr, alarm, _, tripwire, _, names = _setup()
    out = rcmp.run(a, tr, alarm.copy(), alarm.copy(), 50.0, (300.0, 600.0), epoch0_end=150.0, tripwire=tripwire, resolver=(names, {}))
    assert out['F_check'] == dict(rows=int((a['end'] < 150.0).sum()), agreement=1.0, passed=True)
    assert out['arms']['R']['burden'] == out['arms']['F']['burden'] and out['R_minus_F']['burden_diff']['point'] == 0
    assert out['decision']['R_beats_F'] is False and out['decision']['checks']['recall_within_2pt']
    assert out['arms']['R_system']['primary']['attack'] == 1.0     # tripwire catches the second attack


def test_fewer_normal_episodes_win_when_trials_are_kept():
    a, tr, alarm, *_ = _setup()
    r = alarm.copy(); r[1 * 1200 + int(200.0 / 0.5) - 1] = False   # R drops the w1 normal episode at 200 s
    out = rcmp.run(a, tr, r, alarm.copy(), 50.0, (300.0, 600.0), epoch0_end=150.0)
    assert out['arms']['R']['burden'] < out['arms']['F']['burden']
    assert out['decision']['R_beats_F'] is True
    hours = 2 * 499 * 0.5 / 3600
    assert abs(out['R_minus_F']['burden_diff']['point'] + 1 / hours) < 1e-9


def test_a_disagreement_before_the_first_refresh_blocks_the_decision():
    a, tr, alarm, *_ = _setup()
    r = alarm.copy(); r[0 * 1200 + int(100.0 / 0.5) - 1] = False
    out = rcmp.run(a, tr, r, alarm.copy(), 50.0, (300.0, 600.0), epoch0_end=150.0)
    assert out['F_check']['passed'] is False and out['decision']['R_beats_F'] is None
