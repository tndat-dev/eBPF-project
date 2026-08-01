"""Small dependency-free Peaks-Over-Threshold calibration for MCP scores.

The detector only feeds this calibrator scores already classified as clean by
the immutable baseline threshold. This prevents a burst of suspicious traffic
from raising the threshold and hiding itself (online threshold poisoning).
"""

from __future__ import annotations

from collections import deque
import math
from typing import Iterable


def quantile(values: Iterable[float], fraction: float) -> float:
    """Deterministic linear quantile without NumPy/SciPy at runtime."""

    ordered = sorted(float(value) for value in values if math.isfinite(float(value)))
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    position = max(0.0, min(1.0, fraction)) * (len(ordered) - 1)
    lower = int(position)
    upper = min(len(ordered) - 1, lower + 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


class AdaptivePOTThreshold:
    """Conservative empirical POT threshold for a single agent/pod.

    A Generalized Pareto MLE is not useful for a short online window and adds a
    heavyweight dependency. This estimates the extreme tail directly, with a
    tail margin and an immutable floor obtained from clean baseline training.
    """

    def __init__(
        self,
        *,
        minimum: float,
        warmup: int = 20,
        capacity: int = 512,
        tail_quantile: float = 0.90,
        target_quantile: float = 0.995,
        margin: float = 0.25,
    ) -> None:
        if minimum <= 0 or warmup < 1 or capacity < warmup:
            raise ValueError("invalid POT threshold configuration")
        self.minimum = float(minimum)
        self.warmup = int(warmup)
        self.tail_quantile = float(tail_quantile)
        self.target_quantile = float(target_quantile)
        self.margin = float(margin)
        self._scores: deque[float] = deque(maxlen=capacity)
        self._current = self.minimum

    @property
    def ready(self) -> bool:
        return len(self._scores) >= self.warmup

    @property
    def current(self) -> float:
        return self._current

    @property
    def samples(self) -> int:
        return len(self._scores)

    def observe_clean(self, score: float) -> float:
        if not math.isfinite(score):
            return self._current
        self._scores.append(float(score))
        if not self.ready:
            return self._current
        tail_start = quantile(self._scores, self.tail_quantile)
        tail = [value for value in self._scores if value >= tail_start]
        tail_limit = quantile(tail, self.target_quantile)
        self._current = max(self.minimum, tail_limit + self.margin)
        return self._current
