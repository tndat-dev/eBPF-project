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
import math

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
        # evidence discount (Pulse 5.22, adopted blind 5.25): a window whose context brings no syscall ID new to the
        # other replicas carries no evidence; absent key = no discount (the behaviour before 24/10)
        passed = float(row['joint_p']) <= alpha and not row.get('evidence_discounted', False)
        last_end, window = self.history.get(key, (None, None))
        start = float(row['window_start'])
        if window is None or last_end is None or start - last_end > self.policy.max_gap_seconds or start < last_end - 0.25:
            window = deque(maxlen=self.policy.n)
        window.append(passed)
        self.history[key] = (float(row['window_end']), window)
        return passed and sum(window) >= self.policy.k


def cauchy_p(tree_p: float, support_p: float) -> float:
    """Cauchy combination of the two branch p-values (Liu & Xie, JASA 2020), equal weights; p clipped to
    [1e-15, 1 - 1e-15]. Same definition as the offline screen (scripts/analysis/ideas_screen.py, Pulse 5.11a)."""
    clip = lambda p: min(max(float(p), 1e-15), 1 - 1e-15)
    t = (math.tan((0.5 - clip(tree_p)) * math.pi) + math.tan((0.5 - clip(support_p)) * math.pi)) / 2
    return 0.5 - math.atan(t) / math.pi


ON_ALARM = ('keep', 'cap', 'restart')


@dataclass(frozen=True)
class CusumPolicy:
    """CUSUM on s_t = -ln(joint_p) - drift per container; signal while S_t >= threshold (Pulse 5.11a).

    ``on_alarm`` (stable-selection-v1 amendment 1): ``keep`` lets S grow without bound, so an alarm can outlast
    the anomaly by minutes; ``cap`` holds S at the threshold (the alarm stops at the first window with
    -ln p < drift); ``restart`` sets S to 0 after an alarm window (Page's restart after a signal)."""
    drift: float = 3.0
    threshold: float = 6.0
    max_gap_seconds: float = 1.0
    on_alarm: str = 'keep'

    def __post_init__(self):
        if not (self.drift > 0 and self.threshold > 0 and self.max_gap_seconds > 0):
            raise ValueError('CUSUM needs positive drift, threshold and gap')
        if self.on_alarm not in ON_ALARM:
            raise ValueError('CUSUM on_alarm must be one of ' + ', '.join(ON_ALARM))

    @property
    def name(self):
        return f'cusum_b{self.drift:g}_h{self.threshold:g}' + ('' if self.on_alarm == 'keep' else '_' + self.on_alarm)


class CusumState:
    """Streaming CUSUM over many containers; the statistic restarts after a gap (as ConfirmationState)."""

    def __init__(self, policy: CusumPolicy):
        self.policy = policy
        self.history = {}

    def update(self, row) -> bool:
        key = tuple(str(row.get(name)) for name in IDENTITY)
        last_end, s = self.history.get(key, (None, 0.0))
        start = float(row['window_start'])
        if last_end is None or start - last_end > self.policy.max_gap_seconds or start < last_end - 0.25:
            s = 0.0
        s = max(0.0, s - math.log(max(float(row['joint_p']), 1e-12)) - self.policy.drift)
        alarm = s >= self.policy.threshold
        if self.policy.on_alarm == 'cap':
            s = min(s, self.policy.threshold)
        elif self.policy.on_alarm == 'restart' and alarm:
            s = 0.0
        self.history[key] = (float(row['window_end']), s)
        return alarm


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


def latency3s_fine_grid():
    """latency3s plus the finer alpha scales registered in Pulse 5.8f item 2 (21/10 11:12) for the families on the
    rule-v2 frontier of pulse-stable-candidate (k2of2, k2of3, k3of3, k3of4): does the coarse grid hide a better point?"""
    fine = [ConfirmationPolicy(k=k, n=n, alpha_scale=scale)
            for scale in (4.0, 6.0, 7.0, 8.0, 12.0, 15.0) for k, n in ((2, 2), (2, 3), (3, 3), (3, 4))]
    return latency3s_grid() + fine


def default_grid():
    """Registered development grid; chosen before looking at any result."""
    grid = []
    for scale in (1.0, 0.5, 0.25):
        for k, n in ((1, 1), (2, 2), (2, 3), (3, 3), (3, 4), (3, 5), (4, 6)):
            grid.append(ConfirmationPolicy(k=k, n=n, alpha_scale=scale))
    return grid
