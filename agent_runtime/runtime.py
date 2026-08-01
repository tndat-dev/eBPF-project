"""Realtime MCP payload-to-alert bridge and lightweight latency benchmark."""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from typing import Iterable

from agent_runtime.detector.online_detector import DetectionDecision, OnlineMCPDetector
from agent_runtime.mcp.graph import SlidingMCPGraph, parse_jsonrpc_payload


@dataclass(frozen=True)
class RuntimeMetrics:
    events: int
    decisions: int
    alerts: int
    p50_ms: float
    p95_ms: float
    p99_ms: float


class MCPRuntime:
    """Single-process bounded realtime path: payload -> graph -> decision."""

    def __init__(self, detector: OnlineMCPDetector, *, window_seconds: float = 60.0) -> None:
        self.detector = detector
        self.window_seconds = window_seconds
        # A shared graph across unrelated agents turns ordinary diversity into
        # an anomaly. Keep the V1 per-workload lesson intact for V2: each
        # agent/pod receives an independent bounded behavior window.
        self._graphs: dict[str, SlidingMCPGraph] = {}

    def ingest(
        self,
        payload: bytes | str,
        *,
        namespace: str,
        pod: str,
        agent_id: str | None = None,
        node_name: str = "unknown",
        ts: float | None = None,
    ) -> DetectionDecision:
        events = parse_jsonrpc_payload(payload, namespace=namespace, pod=pod, agent_id=agent_id, ts=ts)
        now = time.time() if ts is None else ts
        graph_key = agent_id or f"{namespace}/{pod}"
        graph = self._graphs.setdefault(graph_key, SlidingMCPGraph(window_seconds=self.window_seconds))
        graph.add_events(events)
        return self.detector.evaluate(graph.snapshot(now=now), node_name=node_name)

    def benchmark(self, payloads: Iterable[bytes | str], *, namespace: str, pod: str) -> RuntimeMetrics:
        samples: list[float] = []
        decisions = alerts = events = 0
        for payload in payloads:
            started = time.perf_counter()
            decision = self.ingest(payload, namespace=namespace, pod=pod)
            samples.append((time.perf_counter() - started) * 1_000)
            decisions += 1
            alerts += int(decision.decision == "alert")
            events += len(parse_jsonrpc_payload(payload, namespace=namespace, pod=pod))
        if not samples:
            return RuntimeMetrics(0, 0, 0, 0.0, 0.0, 0.0)
        ordered = sorted(samples)
        return RuntimeMetrics(events, decisions, alerts, _percentile(ordered, 50), _percentile(ordered, 95), _percentile(ordered, 99))


def _percentile(sorted_values: list[float], percentile: int) -> float:
    index = max(0, min(len(sorted_values) - 1, int((len(sorted_values) - 1) * percentile / 100)))
    return sorted_values[index]
