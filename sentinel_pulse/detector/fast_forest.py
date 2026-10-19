"""Bit-identical, low-overhead scoring for the frozen ExtraTrees + support model.

Profiling the matched worker (19/10) showed ~85% of per-frame time in
``ForestClassifier.predict_proba``, almost all of it per-tree Python overhead
(fitted checks, warning filters, config contexts, joblib dispatch) because
each frame calls it ~18 times on a handful of rows with ~190 trees each.

``forest_predict_proba`` performs exactly the arithmetic of scikit-learn's
sequential path: start from float64 zeros, add every tree's
``tree_.predict(X)[:, :n_classes_]`` in estimator order, divide by the number
of trees. ``predict_contexts`` mirrors ``PulseSupportEnsemble.predict_contexts``.

The first batch of every model is scored both ways; any difference disables
the fast path for that model for the life of the process.
"""
from __future__ import annotations

import numpy as np

from .support_model import pvalues


def forest_predict_proba(forest, x):
    x = np.ascontiguousarray(x, dtype=np.float32)
    if getattr(forest, 'n_outputs_', 1) != 1:
        return forest.predict_proba(x)
    classes = int(forest.n_classes_)
    total = np.zeros((len(x), classes), dtype=np.float64)
    for tree in forest.estimators_:
        total += tree.tree_.predict(x)[:, :classes]
    total /= len(forest.estimators_)
    return total


def predict_contexts(model, contexts):
    x = np.asarray(contexts, dtype=np.float32)
    dim = model.base.feature_dim
    if x.ndim != 2 or x.shape[1] != (model.base.history + 1) * dim or not np.isfinite(x).all():
        raise ValueError('invalid temporal contexts')
    if model.support_calibration is None:
        raise RuntimeError('support reference not calibrated')
    tree_score = forest_predict_proba(model.base.estimator, x)[:, 1]
    tree_p = pvalues(tree_score, model.base.calibration_scores)
    support_score = model.support_scores(x[:, -dim:])
    support_p = pvalues(support_score, model.support_calibration)
    joint_p = np.minimum(1., 2 * np.minimum(tree_p, support_p))
    return {'tree_score': tree_score, 'tree_p': tree_p, 'support_score': support_score,
            'support_p': support_p, 'joint_p': joint_p, 'anomalous': joint_p <= model.alpha}


class VerifiedFastScorer:
    """Use the fast path per model only after it reproduced the reference exactly."""

    def __init__(self):
        self.state = {}   # id(model) -> True (verified) / False (disabled)
        self.disabled = []

    def __call__(self, workload, model, contexts):
        state = self.state.get(id(model))
        if state is False:
            return model.predict_contexts(contexts)
        fast = predict_contexts(model, contexts)
        if state is None:
            reference = model.predict_contexts(contexts)
            same = all(np.array_equal(np.asarray(fast[k]), np.asarray(reference[k])) for k in reference)
            self.state[id(model)] = same
            if not same:
                self.disabled.append(workload)
                return reference
        return fast
