"""Recompute conformal p-values of recorded decisions against new normal scores.

Each scored decision stores the raw ``tree_score`` and ``support_score`` of
the frozen model, so p-values can be re-derived offline against a different
normal calibration sample without touching the model. Combination is the same
as ``PulseSupportEnsemble``: ``joint_p = min(1, 2 * min(tree_p, support_p))``.
"""
from __future__ import annotations

from collections import defaultdict

import numpy as np

from .support_model import pvalues


class Recalibrator:
    def __init__(self, tree: dict, support: dict, minimum_examples: int = 1200):
        self.tree = {k: np.sort(np.asarray(v, dtype=np.float64)) for k, v in tree.items()}
        self.support = {k: np.sort(np.asarray(v, dtype=np.float64)) for k, v in support.items()}
        # Below 2/alpha - 1 examples the smallest attainable joint p cannot reach alpha.
        self.usable = {k for k in self.tree if min(len(self.tree[k]), len(self.support[k])) >= minimum_examples}

    @classmethod
    def from_rows(cls, rows, minimum_examples: int = 1200):
        tree, support = defaultdict(list), defaultdict(list)
        for row in rows:
            tree[row['workload_key']].append(float(row['tree_score']))
            support[row['workload_key']].append(float(row['support_score']))
        return cls(tree, support, minimum_examples)

    def sizes(self):
        return {k: len(v) for k, v in self.tree.items()}

    def rewrite(self, row):
        """Return a copy with recomputed p-values, or None without usable calibration."""
        key = row['workload_key']
        if key not in self.usable:
            return None
        tree_p = float(pvalues(np.array([float(row['tree_score'])]), self.tree[key])[0])
        support_p = float(pvalues(np.array([float(row['support_score'])]), self.support[key])[0])
        return dict(row, frozen_joint_p=row['joint_p'], tree_p=tree_p, support_p=support_p,
                    joint_p=min(1.0, 2 * min(tree_p, support_p)))
