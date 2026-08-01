"""Low-latency, dependency-free anomaly detector for MCP behavior graphs.

This bridge is intentionally separate from the syscall detector.  It accepts
the bounded graph features produced in userspace and uses a robust baseline
(median + MAD) with a multi-window confirmation rule.  The confirmation rule
is important in practice: a single unusual but legitimate MCP request must
not immediately isolate a workload.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import math
import time
from typing import Iterable, Mapping

from agent_runtime.detector.graph_features import DEFAULT_FEATURE_NAMES, graph_feature_vector
from agent_runtime.detector.evt_pot import AdaptivePOTThreshold
from agent_runtime.mcp.graph import GraphSnapshot


@dataclass(frozen=True)
class MCPBaseline:
    """Robust per-feature reference distribution learned from clean traffic."""

    feature_names: tuple[str, ...]
    median: tuple[float, ...]
    mad: tuple[float, ...]
    minimum_scale: float = 0.05

    @classmethod
    def fit(
        cls,
        snapshots: Iterable[GraphSnapshot],
        feature_names: Iterable[str] = DEFAULT_FEATURE_NAMES,
        minimum_scale: float = 0.05,
    ) -> "MCPBaseline":
        names = tuple(feature_names)
        rows = [_scoring_vector(snapshot, names) for snapshot in snapshots]
        if len(rows) < 3:
            raise ValueError("at least three clean graph snapshots are required")
        columns = list(zip(*rows))
        medians = tuple(_median(column) for column in columns)
        mads = tuple(max(minimum_scale, _median(abs(value - median) for value in column)) for column, median in zip(columns, medians))
        return cls(names, medians, mads, minimum_scale)

    def score(self, snapshot: GraphSnapshot) -> tuple[float, dict[str, float]]:
        values = _scoring_vector(snapshot, self.feature_names)
        contributions: dict[str, float] = {}
        for name, value, median, mad in zip(self.feature_names, values, self.median, self.mad):
            # 1.4826 makes MAD comparable to sigma for normal traffic.  A
            # one-sided score avoids treating a quiet period as malicious.
            robust_z = max(0.0, (value - median) / (1.4826 * mad))
            contributions[name] = robust_z
        # Mean of the strongest three signals is stable when one feature is
        # noisy yet preserves sensitivity to multi-dimensional abuse.
        strongest = sorted(contributions.values(), reverse=True)[:3]
        return (sum(strongest) / max(1, len(strongest))), contributions

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class MCPAnomalyAlert:
    """Alert envelope deliberately aligned with the V1 ``AnomalyAlert``."""

    pod_name: str
    pod_namespace: str
    node_name: str
    detected_at: str
    ensemble_score: float
    lstm_score: float
    if_score: float
    threshold: float
    top_syscalls: tuple[dict[str, float | str], ...]
    window_start: float
    window_end: float
    detection_latency: float
    source: str = "mcp-behavior-graph"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DetectionDecision:
    decision: str
    score: float
    threshold: float
    inference_ms: float
    end_to_end_ms: float
    alert: MCPAnomalyAlert | None = None


class OnlineMCPDetector:
    """Realtime graph detector with two-window confirmation and cooldown."""

    def __init__(
        self,
        baseline: MCPBaseline,
        *,
        threshold: float = 4.0,
        confirmation_windows: int = 2,
        cooldown_seconds: float = 60.0,
        adaptive_pot: bool = True,
        pot_warmup: int = 20,
    ) -> None:
        if threshold <= 0:
            raise ValueError("threshold must be positive")
        if confirmation_windows < 1:
            raise ValueError("confirmation_windows must be at least one")
        self.baseline = baseline
        self.threshold = threshold
        self.confirmation_windows = confirmation_windows
        self.cooldown_seconds = cooldown_seconds
        self.adaptive_pot = adaptive_pot
        self.pot_warmup = pot_warmup
        self._pending: dict[str, int] = {}
        self._last_alert: dict[str, float] = {}
        self._calibrators: dict[str, AdaptivePOTThreshold] = {}

    def evaluate(self, snapshot: GraphSnapshot, *, node_name: str = "unknown") -> DetectionDecision:
        started = time.perf_counter()
        score, contributions = self.baseline.score(snapshot)
        inference_ms = (time.perf_counter() - started) * 1_000
        events = snapshot.events
        if not events:
            return DetectionDecision("normal", score, self.threshold, inference_ms, inference_ms)

        pod_key = f"{events[-1].namespace}/{events[-1].pod}"
        threshold = self._threshold_for(pod_key)
        if score < threshold:
            self._pending.pop(pod_key, None)
            # Only baseline-clean windows calibrate the adaptive tail. This is
            # the guard against threshold poisoning during an attack.
            if self.adaptive_pot:
                self._calibrators[pod_key].observe_clean(score)
            return DetectionDecision("normal", score, threshold, inference_ms, inference_ms)

        count = self._pending.get(pod_key, 0) + 1
        self._pending[pod_key] = count
        if count < self.confirmation_windows:
            return DetectionDecision("pending", score, threshold, inference_ms, inference_ms)

        now = time.time()
        if now - self._last_alert.get(pod_key, 0.0) < self.cooldown_seconds:
            return DetectionDecision("cooldown", score, threshold, inference_ms, inference_ms)
        self._last_alert[pod_key] = now
        self._pending.pop(pod_key, None)

        top_features = sorted(contributions.items(), key=lambda item: item[1], reverse=True)[:5]
        last = events[-1]
        window_start = min(event.ts for event in events)
        latency_ms = max(0.0, (time.time() - last.ts) * 1_000)
        alert = MCPAnomalyAlert(
            pod_name=last.pod,
            pod_namespace=last.namespace,
            node_name=node_name,
            detected_at=datetime.now(timezone.utc).isoformat(),
            ensemble_score=score,
            # Names retained for downstream compatibility; this baseline is
            # an interpretable pre-GAT detector, not a fake LSTM/IF model.
            lstm_score=0.0,
            if_score=0.0,
            threshold=threshold,
            top_syscalls=tuple({"name": name, "freq": value, "count": value} for name, value in top_features),
            window_start=window_start,
            window_end=snapshot.generated_at,
            detection_latency=latency_ms / 1_000,
        )
        end_to_end_ms = (time.perf_counter() - started) * 1_000
        return DetectionDecision("alert", score, threshold, inference_ms, end_to_end_ms, alert)

    def _threshold_for(self, pod_key: str) -> float:
        if not self.adaptive_pot:
            return self.threshold
        calibrator = self._calibrators.setdefault(
            pod_key, AdaptivePOTThreshold(minimum=self.threshold, warmup=self.pot_warmup)
        )
        return calibrator.current


def _median(values: Iterable[float]) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return 0.0
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _scoring_vector(snapshot: GraphSnapshot, names: Iterable[str]) -> list[float]:
    """Normalise cumulative window counters before robust scoring.

    The graph intentionally retains raw counts for future GAT features.  A
    streaming baseline must not score those raw counters directly: an ordinary
    agent would otherwise become more anomalous solely because its 60-second
    window has filled.  Convert volume counters to per-observed-second values
    while retaining ratios, diversity and high-risk semantic signals.
    """

    values = dict(snapshot.features)
    total = max(1.0, values.get("events_total", 0.0))
    rate = max(0.0, values.get("event_rate_per_second", 0.0))
    observed_seconds = max(1.0, total / rate) if rate else max(1.0, snapshot.window_seconds)
    for name in ("events_total", "max_tool_calls", "max_resource_touches", "raw_kib"):
        values[name] = values.get(name, 0.0) / observed_seconds
    return [float(values.get(name, 0.0)) for name in names]
