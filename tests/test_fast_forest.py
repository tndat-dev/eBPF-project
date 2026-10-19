import numpy as np
from sklearn.ensemble import ExtraTreesClassifier

from sentinel_pulse.detector.fast_forest import VerifiedFastScorer, forest_predict_proba


def test_forest_predict_proba_is_bit_identical_to_sklearn():
    rng = np.random.default_rng(3)
    x = rng.normal(size=(600, 12)).astype(np.float32)
    y = (x[:, 0] + rng.normal(scale=.5, size=600) > 0).astype(int)
    forest = ExtraTreesClassifier(n_estimators=64, min_samples_leaf=3, random_state=0, n_jobs=1).fit(x, y)
    for batch in (x[:1], x[:7], x[100:356]):
        assert np.array_equal(forest_predict_proba(forest, batch), forest.predict_proba(batch))


class _Model:
    def __init__(self, result): self.result, self.calls = result, 0
    def predict_contexts(self, contexts):
        self.calls += 1
        return self.result


def test_verified_scorer_falls_back_when_fast_path_differs(monkeypatch):
    import sentinel_pulse.detector.fast_forest as ff
    model = _Model({'joint_p': np.array([0.5])})
    monkeypatch.setattr(ff, 'predict_contexts', lambda m, c: {'joint_p': np.array([0.4])})
    scorer = VerifiedFastScorer()
    assert scorer('w', model, None)['joint_p'][0] == 0.5
    assert scorer('w', model, None)['joint_p'][0] == 0.5 and scorer.disabled == ['w']
    monkeypatch.setattr(ff, 'predict_contexts', lambda m, c: {'joint_p': np.array([0.5])})
    good = _Model({'joint_p': np.array([0.5])})
    scorer('g', good, None); scorer('g', good, None)
    assert good.calls == 1   # verified once, then fast only
