"""Normal-only learned support branch for an exploratory Pulse model ensemble.

The original ExtraTrees artifact is read-only. A separate branch can score
features outside training support, including coordinates constant during
corruption training. Both p-values are calibrated on normal suffixes; the
combination pays a two-branch multiple-testing budget, not an uncorrected OR.
This module does not plug into the frozen production detector/policy.
"""
from __future__ import annotations

import math
import numpy as np

from .syscall_analysis import pvalues


class PulseSupportEnsemble:
    def __init__(self, base, interval_fpr_budget=.05, horizon_windows=30):
        if not math.isfinite(interval_fpr_budget) or not 0 < interval_fpr_budget < 1:
            raise ValueError('invalid interval false-positive budget')
        if type(horizon_windows) is not int or horizon_windows < 1:
            raise ValueError('positive integer horizon required')
        self.base = base
        self.alpha = interval_fpr_budget / horizon_windows
        self.interval_fpr_budget = interval_fpr_budget
        self.horizon_windows = horizon_windows
        self.low = self.high = self.scale = self.support_calibration = None

    @property
    def minimum_calibration_examples_per_branch(self):
        return math.ceil(2 / self.alpha) - 1

    def support_scores(self, current):
        current = np.asarray(current, dtype=np.float32)
        if self.low is None:
            raise RuntimeError('support reference not fitted')
        if current.ndim != 2 or current.shape[1] != self.base.feature_dim or not np.isfinite(current).all():
            raise ValueError('invalid support feature batch')
        excess = np.maximum(self.low - current, current - self.high)
        return (np.maximum(excess, 0).astype(np.float64) / self.scale).max(axis=1)

    def fit_support(self, training_current, calibration_current):
        train = np.asarray(training_current, dtype=np.float32)
        cal = np.asarray(calibration_current, dtype=np.float32)
        if train.ndim != 2 or cal.ndim != 2 or train.shape[1] != self.base.feature_dim or cal.shape[1] != self.base.feature_dim:
            raise ValueError('support training/calibration shape mismatch')
        if len(train) < 100 or not np.isfinite(train).all() or not np.isfinite(cal).all():
            raise ValueError('insufficient or invalid normal reference')
        minimum = self.minimum_calibration_examples_per_branch
        if len(cal) < minimum or len(self.base.calibration_scores) < minimum:
            raise ValueError('insufficient conformal resolution for the two-branch interval budget')
        # Fixed before evaluation. Max across all coordinates is calibrated as
        # ONE support score; no per-coordinate p-value/uncorrected OR.
        self.low = np.quantile(train, .01, axis=0).astype(np.float64)
        self.high = np.quantile(train, .99, axis=0).astype(np.float64)
        self.scale = np.maximum(self.high - self.low, .05)
        self.support_calibration = np.sort(self.support_scores(cal))
        return {'training_rows': len(train), 'calibration_rows': len(cal),
                'constant_training_coordinates': int(np.sum(np.ptp(train, axis=0) == 0)),
                'alpha_per_window_combined': self.alpha,
                'minimum_calibration_examples_per_branch': minimum,
                'fitted_from_attack_data': False}

    def predict_contexts(self, contexts):
        x = np.asarray(contexts, dtype=np.float32)
        dim = self.base.feature_dim
        if x.ndim != 2 or x.shape[1] != (self.base.history + 1) * dim or not np.isfinite(x).all():
            raise ValueError('invalid temporal contexts')
        if self.support_calibration is None:
            raise RuntimeError('support reference not calibrated')
        tree_score = self.base.estimator.predict_proba(x)[:, 1]
        tree_p = pvalues(tree_score, self.base.calibration_scores)
        support_score = self.support_scores(x[:, -dim:])
        support_p = pvalues(support_score, self.support_calibration)
        joint_p = np.minimum(1., 2 * np.minimum(tree_p, support_p))
        return {'tree_score': tree_score, 'tree_p': tree_p, 'support_score': support_score,
                'support_p': support_p, 'joint_p': joint_p, 'anomalous': joint_p <= self.alpha}
