"""Part A of ml-final-study-v1: attack-specific scoring drops the launch grams of the same trial's benign interval."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import live_attribution as la  # noqa: E402
from sentinel_pulse.detector.token_model import TOK_NONE, CountTokenLM  # noqa: E402

A, B, L, X = 1 << 23, 2 << 23, 3 << 23, 4 << 23      # service tokens A, B; launch token L; attack token X


def model():
    lm = CountTokenLM()
    for _ in range(200):
        lm.learn((A, B, A, B))
        lm.learn((B, A, B, A))
    return lm.finalize()


def trial(label, start, pair=1):
    return dict(label=label, start=start, key=('pod', 'c'), pair=pair, workload='w', rate=12, scenario='s', command='ls')


def test_attack_specific_needs_the_attack_grams():
    lm = model()
    launch = [(TOK_NONE, TOK_NONE, TOK_NONE, L, 5), (A, B, A, B, 50)]
    attack_launch_only = [(TOK_NONE, TOK_NONE, TOK_NONE, L, 5), (A, B, A, B, 50)]
    attack_op = [(TOK_NONE, TOK_NONE, TOK_NONE, L, 5), (L, X, X, X, 10)]
    thr = 5.0
    windows = {('pod', 'c'): [(101.0, launch, None, thr), (201.0, attack_launch_only, None, thr), (302.0, attack_op, None, thr)]}
    models = {'w': ('unused', thr)}
    trials = [trial('benign', 100.0), trial('attack', 200.0), trial('benign', 300.0, pair=2), trial('attack', 301.0, pair=2)]
    # pair 2's benign interval [300, 315] also holds the window at 302: the launch reference then holds L and X grams
    trials[2]['key'] = ('pod', 'other')
    gate, rows = la.part_a(trials, windows, models, {'w': lm})
    assert gate['missing_score'] == 3 and gate['windows'] == 0
    first, second = sorted(rows, key=lambda r: r['pair'])
    assert first['as_run'] == 201.0 and first['attack_specific'] is None      # only the launch token made it fire
    assert second['as_run'] == 302.0 and second['attack_specific'] == 302.0   # X grams are not in any reference
    assert first['post_launch'] is None and second['post_launch'] is None     # both alarms within 1.5 s of the start


def test_score_drop_matches_window_score():
    lm = model()
    grams = [(A, B, A, B, 3), (L, X, X, X, 2)]
    assert la.score(lm, grams) == lm.window_score(grams)
    assert la.score(lm, grams, frozenset({(L, X, X, X)})) == lm.window_score([(A, B, A, B, 3)])
