"""k-of-n temporal confirmation on top of the frozen per-window joint p-value.

The frozen preview policy raises a signal whenever one 500 ms window has
``joint_p <= alpha``. A confirmation policy instead requires at least ``k`` of
the last ``n`` consecutive scored windows of the same container to pass a
threshold ``alpha * alpha_scale`` (stricter below 1, looser above 1 —
only meaningful after recalibration has restored p-value validity). It never refits the
model or recalibrates p-values; it only changes how per-window evidence is
turned into a signal. Development use only until frozen and blind-tested.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

IDENTITY = ('workload_key', 'node_name', 'pod_uid', 'container_name',
            'workload_revision', 'cgroup_id')
SCORED = 'candidate-raw-score-only'


@dataclass(frozen=True)
class ConfirmationPolicy:
    k: int = 1
    n: int = 1
    alpha_scale: float = 1.0
    # A larger gap between consecutive windows means the history was broken
    # (reset, eviction, collector gap); confirmation starts over.
    max_gap_seconds: float = 1.0

    def __post_init__(self):
        if not 1 <= self.k <= self.n:
            raise ValueError('confirmation requires 1 <= k <= n')
        if not 0 < self.alpha_scale <= 20:
            raise ValueError('alpha_scale must be in (0, 20]')

    @property
    def name(self):
        return f'k{self.k}of{self.n}_a{self.alpha_scale:g}'

    @property
    def minimum_added_delay_seconds(self):
        return 0.5 * (self.k - 1)


class ConfirmationState:
    """Streaming evaluation of one policy over many containers."""

    def __init__(self, policy: ConfirmationPolicy):
        self.policy = policy
        self.history = {}

    def update(self, row) -> bool:
        """Return the confirmed signal for one scored decision row."""
        key = tuple(str(row.get(name)) for name in IDENTITY)
        alpha = float(row['candidate_policy_alpha']) * self.policy.alpha_scale
        passed = float(row['joint_p']) <= alpha
        last_end, window = self.history.get(key, (None, None))
        start = float(row['window_start'])
        if window is None or last_end is None or start - last_end > self.policy.max_gap_seconds or start < last_end - 0.25:
            window = deque(maxlen=self.policy.n)
        window.append(passed)
        self.history[key] = (float(row['window_end']), window)
        return passed and sum(window) >= self.policy.k


def apply(rows, policy: ConfirmationPolicy):
    """Copy rows in window order with ``candidate_alert_preview`` recomputed.

    Unscored rows pass through unchanged. Only scored rows that carry a
    joint p-value are rewritten; the original value is kept for audit.
    """
    state = ConfirmationState(policy)
    out = []
    for row in sorted(rows, key=lambda r: (float(r.get('window_end', 0)), float(r.get('window_start', 0)))):
        if row.get('status') == SCORED and row.get('joint_p') is not None:
            row = dict(row, frozen_candidate_alert_preview=row.get('candidate_alert_preview'),
                       candidate_alert_preview=state.update(row), confirmation_policy=policy.name)
        out.append(row)
    return out


def looser_grid():
    """Second development grid (registered 2026-10-18 after the recalibration
    result showed lost recall): looser per-window alpha on recalibrated p-values."""
    return [ConfirmationPolicy(k=k, n=n, alpha_scale=scale)
            for scale in (1.0, 2.0, 3.0, 5.0, 10.0) for k, n in ((1, 1), (2, 2), (2, 3))]


def latency3s_grid():
    """Third development grid (registered 2026-10-21 before the pulse-stable-candidate final numbers):
    the looser grid plus 3- and 4-window confirmations, which fit the relaxed latency goal
    (< 2 s preferred, <= 3 s acceptable); k4of4 approximates "wait 1 s after the first preview"."""
    extra = [ConfirmationPolicy(k=k, n=n, alpha_scale=scale)
             for scale in (3.0, 5.0, 10.0, 20.0) for k, n in ((3, 3), (3, 4), (4, 4), (4, 5))]
    extra += [ConfirmationPolicy(k=k, n=n, alpha_scale=20.0) for k, n in ((1, 1), (2, 2), (2, 3))]
    return looser_grid() + extra


def default_grid():
    """Registered development grid; chosen before looking at any result."""
    grid = []
    for scale in (1.0, 0.5, 0.25):
        for k, n in ((1, 1), (2, 2), (2, 3), (3, 3), (3, 4), (3, 5), (4, 6)):
            grid.append(ConfirmationPolicy(k=k, n=n, alpha_scale=scale))
    return grid
