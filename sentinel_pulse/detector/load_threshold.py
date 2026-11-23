"""Load-aware threshold of protocol load-threshold-v1: the threshold of a window depends on its own event count.

A window's score is the mean of its few most surprising events, so a window with many events holds a rare gram by
chance more often; one threshold per unit alarms more under heavy load. Here a unit's held-out windows are split into
B bins of event count (edges at the k/B quantiles, snapped to powers of two), and each bin gets its own moment Gumbel
threshold, fitted on the maxima per held-out unit (recording or 60 s block) of the windows in that bin. The event count
is what the probe measures in the window ('events'); nothing tells the model the traffic regime.

Shared by the dataset study, the cluster fit and the worker (TokenBranch), so every place applies the same rule.
"""
# NGƯỠNG THEO MỨC TẢI (load-threshold-v1): ngưỡng của một cửa sổ phụ thuộc số sự kiện của chính nó (probe đo), chia
# nhóm theo phân vị của cửa sổ giữ ra (làm tròn về lũy thừa 2), mỗi nhóm một ngưỡng Gumbel.
from __future__ import annotations

from bisect import bisect_right
import math

import numpy as np

MINIMUM_UNITS = 30
TRIM = 0.005


def snap(x: float) -> int:
    """Nearest power of two (at least 1)."""
    return 1 << max(0, int(round(math.log2(max(1.0, float(x))))))


def edges_of(events, bins: int) -> list[int]:
    """Bin edges at the k/bins quantiles of held-out window event counts, snapped to powers of two, deduplicated."""
    if bins < 2:
        return []
    q = np.quantile(np.asarray(events, float), [k / bins for k in range(1, bins)])
    return sorted({snap(v) for v in q})


def bin_of(events: float, edges) -> int:
    return bisect_right(edges, events) if edges else 0          # bin k holds edges[k-1] <= events < edges[k]


def gumbel(maxima):
    beta = max(float(np.std(maxima)) * math.sqrt(6) / math.pi, 1e-6)
    return float(np.mean(maxima)) - 0.5772 * beta, beta


def trimmed_gumbel(maxima, trim=TRIM):
    """Moment Gumbel without the top share of the maxima, at least one (the rule of token_branch_fit.trimmed_gumbel)."""
    x = np.sort(np.asarray(maxima, float))
    return gumbel(x[:max(2, len(x) - max(1, int(round(len(x) * trim))))])


def threshold(fit, alpha):
    return fit[0] - fit[1] * math.log(-math.log(1 - alpha))


def fit_bins(bin_maxima, fallback: float, alpha: float, trim: float = TRIM, minimum: int = MINIMUM_UNITS):
    """[threshold per bin]: moment Gumbel on each bin's unit maxima at alpha; a bin with fewer than `minimum` units
    takes the fallback (the unit's single threshold)."""
    out = []
    for maxima in bin_maxima:
        if len(maxima) >= minimum:
            out.append(float(threshold(trimmed_gumbel(maxima, trim), alpha)))
        else:
            out.append(float(fallback))
    return out


class LoadThreshold:
    """Edges and per-bin thresholds of one unit; spec {"edges": [...], "thresholds": [...]}."""

    def __init__(self, edges, thresholds):
        self.edges, self.thresholds = [int(e) for e in edges], [float(t) for t in thresholds]
        if len(self.thresholds) != len(self.edges) + 1 or not all(math.isfinite(t) for t in self.thresholds):
            raise ValueError('a load threshold needs one finite threshold per bin')

    def __call__(self, events: float) -> float:
        return self.thresholds[bin_of(events, self.edges)]

    def to_json(self):
        return dict(edges=self.edges, thresholds=self.thresholds)
