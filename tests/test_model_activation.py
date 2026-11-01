import numpy as np

from sentinel_pulse.detector.model import PulseExtraTrees


def rows(n=600, seed=1):
    rng = np.random.default_rng(seed)
    x = np.zeros((n, 6), dtype=np.float32)
    x[:, :4] = rng.normal(3.0, 0.3, size=(n, 4))     # coordinates 4 and 5 are always 0 in training
    return x


def test_default_corruption_is_unchanged_and_never_moves_a_constant_coordinate():
    cur = rows()
    plain = PulseExtraTrees(history=1)._corrupt(cur)
    again = PulseExtraTrees(history=1, activate_fraction=0.0)._corrupt(cur)
    assert np.array_equal(plain, again)
    assert np.all(plain[:, 4:] == 0)


def test_activation_moves_only_constant_coordinates_and_keeps_the_rest_identical():
    cur = rows()
    plain = PulseExtraTrees(history=1)._corrupt(cur)
    act = PulseExtraTrees(history=1, activate_fraction=0.2)._corrupt(cur)
    assert np.array_equal(plain[:, :4], act[:, :4])
    moved = np.count_nonzero(act[:, 4:].any(axis=1))
    assert 0.1 * len(cur) < moved < 0.3 * len(cur)


def test_activation_lets_the_tree_score_a_moved_constant_coordinate():
    normal = rows(1200)
    seqs = [normal[:800], normal[800:]]
    plain, act = PulseExtraTrees(history=1, alpha=0.01), PulseExtraTrees(history=1, alpha=0.01, activate_fraction=0.2)
    for m in (plain, act):
        m.fit_sequences(seqs, train_fraction=0.7)
    hist, cur = normal[-2:-1], normal[-1:].copy()
    cur[0, 5] = 3.0
    d_plain, d_act = plain.predict(hist, cur[0]), act.predict(hist, cur[0])
    assert d_act.conformal_p < d_plain.conformal_p and d_act.conformal_p <= 0.05
