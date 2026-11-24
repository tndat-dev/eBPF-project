"""improvement_round2.py: the B1 overlay model and the split of the S1a evaluation into a native and a session part."""
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))
import improvement_round2 as r2  # noqa: E402
from sentinel_pulse.detector.token_model import TOK_NONE, CountTokenLM, strip  # noqa: E402


def tok(n, v=0):
    return (n << 23) | v


def windows(rng, calls, count=40, length=6):
    out = []
    for _ in range(count):
        hist, grams = [TOK_NONE] * 3, {}
        for _ in range(length):
            t = tok(rng.choice(calls), rng.choice((0, 0, 1)))
            g = tuple(hist + [t])
            grams[g] = grams.get(g, 0) + rng.randint(1, 3)
            hist = hist[1:] + [t]
        out.append([[*g, c] for g, c in grams.items()])
    return out


def test_overlay_gives_the_probabilities_of_learning_everything():
    rng = random.Random(7)
    base_w, extra_w = windows(rng, [1, 2, 3, 4]), windows(rng, [2, 3, 5, 6], count=15)
    base = CountTokenLM()
    for w in base_w:
        base.learn_window(w)
    base.finalize()
    base.default_top = 3
    extra = CountTokenLM()
    for w in extra_w:
        extra.learn_window(w)
    full = CountTokenLM()
    for w in base_w + extra_w:
        full.learn_window(w)
    full.finalize()
    full.default_top = 3
    over = r2.OverlayLM(base, extra)
    probe = windows(rng, [1, 2, 3, 5, 6, 7], count=30)
    for w in probe:
        for *g, _ in w:
            assert abs(over.prob(strip(g)) - full.prob(strip(g))) < 1e-12
        assert abs(over.window_score(w) - full.window_score(w)) < 1e-9
    assert base.total == sum(c for w in base_w for *_, c in w)


class Model:
    """A stand-in model: the window score is the largest count of the window's grams."""
    default_top = 3

    def window_score(self, grams):
        return max((g[-1] for g in grams), default=0.0)


def test_split_evaluation_equals_one_pass(monkeypatch):
    import live_attribution as la
    monkeypatch.setattr(la, 'HORIZON', 10.0)
    trials = [dict(pair=1, label='attack', key='a', workload='w', start=100.0, rate=1),
              dict(pair=1, label='control', key='c', workload='w', start=100.0),
              dict(pair=2, label='attack', key='b', workload='w', start=200.0, rate=1),
              dict(pair=3, label='admin', key='z', workload='w', start=0.0, command='find')]     # no attack pair
    g = lambda n: [[TOK_NONE, TOK_NONE, TOK_NONE, tok(1), n]]
    ws = {'a': [(99.5, g(9), []), (100.0, g(1), g(1)), (100.5, g(9), g(8)), (101.0, g(9), [])],     # session at 100.5
          'c': [(100.0, g(1), []), (105.0, g(1), [])],
          'b': [(200.5, g(9), g(9)), (201.0, g(1), [])]}                                             # both at 200.5
    native = {'w': (Model(), 5.0)}
    nh = r2.native_hits(trials, ws, native)
    # native_of(whole, session) is the whole minus the session part: 'a' at 100.5 has native 9 - 8 = 1, below 5
    assert nh == {0: 101.0, 1: None, 2: None}
    counts, lat = r2.evaluate_system(trials, ws, native, Model(), 5.0)
    assert counts['attack'] == [2, 2] and counts['control'] == [0, 1]
    firsts = r2.with_session(trials, ws, nh, Model(), 5.0)
    assert firsts == {0: 100.5, 1: None, 2: 200.5}
