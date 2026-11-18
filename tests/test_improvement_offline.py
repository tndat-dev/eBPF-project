"""improvement_offline.py: the Kneser-Ney variant of the token model, the CUSUM and the GEV threshold."""
import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'analysis'))
import improvement_offline as io  # noqa: E402
from sentinel_pulse.detector.token_model import TOK_NONE, CountTokenLM  # noqa: E402


def tok(n, v=0):
    return (n << 23) | v


def toy(cls):
    lm = cls()
    seq = [tok(1), tok(2), tok(3), tok(1), tok(2), tok(4), tok(1), tok(2), tok(3)] * 20
    hist = [TOK_NONE] * 3
    for t in seq:
        g = [x for x in hist if x != TOK_NONE] + [t]
        lm.learn(tuple(g), 1)
        hist = hist[1:] + [t]
    return lm.finalize()


def test_kn_ranks_like_a_language_model_and_differs_from_witten_bell():
    kn, wb = toy(io.KNTokenLM), toy(CountTokenLM)
    ctx = (tok(3), tok(1), tok(2))
    seen = [kn.prob(ctx + (tok(3),)), kn.prob(ctx + (tok(4),))]
    unseen = kn.prob(ctx + (tok(9),))
    assert all(1 >= p > unseen > 0 and math.isfinite(p) for p in seen)
    order = lambda lm: kn.prob(ctx + (tok(3),)) > kn.prob(ctx + (tok(4),))
    assert (wb.prob(ctx + (tok(3),)) > wb.prob(ctx + (tok(4),))) == order(kn)
    assert abs(kn.prob(ctx + (tok(4),)) - wb.prob(ctx + (tok(4),))) > 1e-6


def test_kn_mass_over_the_vocabulary_is_at_most_one():
    kn = toy(io.KNTokenLM)
    ctx = (tok(1), tok(2), tok(3))
    total = sum(kn.prob(ctx + (w,)) for w in (tok(1), tok(2), tok(3), tok(4)))
    assert 0.5 < total <= 1.0 + 1e-9


def test_cusum_accumulates_and_resets():
    x = np.array([0, 2, 2, 2, 0, 0, 0, 5.0])
    s = io.cusum(x, 1.0)
    assert list(s) == [0, 1, 2, 3, 2, 1, 0, 4]


def test_gev_threshold_reduces_to_gumbel_at_zero_shape():
    rng = np.random.default_rng(1)
    mx = rng.gumbel(10, 2, 300)
    g = io.gev_threshold(mx, 0.0, 0, 0.0003)
    ref = io.m.threshold(io.m.gumbel(np.sort(mx)), 0.0003)
    assert abs(g - ref) < 1e-6 * max(1, abs(ref))
    assert io.gev_threshold(mx, 0.1, 0, 0.0003) > io.gev_threshold(mx, -0.1, 0, 0.0003)
