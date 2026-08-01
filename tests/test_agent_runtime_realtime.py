from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_runtime.detector.online_detector import MCPBaseline, OnlineMCPDetector
from agent_runtime.detector.evt_pot import AdaptivePOTThreshold
from agent_runtime.mcp.graph import SlidingMCPGraph, parse_jsonrpc_payload
from agent_runtime.runtime import MCPRuntime


NORMAL = json.dumps(
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "search_docs", "arguments": {"uri": "kb://runbook"}}}
)
ATTACK = json.dumps(
    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "kubectl_delete", "arguments": {"namespace": "production", "resource": "deployment/payments"}}}
)


def _snapshot(payload: str, count: int, ts: float):
    graph = SlidingMCPGraph(window_seconds=60)
    for index in range(count):
        # The clean corpus contains normal request bursts.  Snapshotting after
        # one second makes event-rate a genuine calibrated feature instead of
        # an accidental product of the unit-test clock.
        graph.add_events(parse_jsonrpc_payload(payload, namespace="demo", pod="agent", ts=ts))
    return graph.snapshot(now=ts + 1)


def _baseline() -> MCPBaseline:
    # A clean baseline must include ordinary burst variation; otherwise the
    # detector would confuse startup/request-rate growth with an attack.
    return MCPBaseline.fit([_snapshot(NORMAL, count, 10.0) for count in range(1, 11)])


def test_normal_realtime_traffic_does_not_alert():
    detector = OnlineMCPDetector(_baseline(), threshold=3.0, confirmation_windows=2)
    runtime = MCPRuntime(detector)
    decisions = [runtime.ingest(NORMAL, namespace="demo", pod="agent") for _ in range(5)]
    assert {decision.decision for decision in decisions} == {"normal"}


def test_sustained_normal_rate_stays_normal_after_sliding_window_fills():
    detector = OnlineMCPDetector(_baseline(), threshold=3.0, confirmation_windows=2)
    runtime = MCPRuntime(detector, window_seconds=60)
    decisions = [
        runtime.ingest(NORMAL, namespace="demo", pod="agent", ts=1_000.0 + index * 0.2)
        for index in range(600)
    ]
    assert {decision.decision for decision in decisions} == {"normal"}


def test_attack_requires_confirmation_then_emits_compatible_alert():
    detector = OnlineMCPDetector(_baseline(), threshold=3.0, confirmation_windows=2, cooldown_seconds=60)
    runtime = MCPRuntime(detector)
    for _ in range(3):
        runtime.ingest(NORMAL, namespace="demo", pod="agent")
    first = runtime.ingest(ATTACK, namespace="demo", pod="agent")
    second = runtime.ingest(ATTACK, namespace="demo", pod="agent")
    assert first.decision == "pending"
    assert second.decision == "alert"
    assert second.alert is not None
    assert second.alert.source == "mcp-behavior-graph"
    assert second.alert.to_dict()["pod_namespace"] == "demo"
    assert second.inference_ms < 100


def test_attack_after_sustained_clean_traffic_still_alerts():
    detector = OnlineMCPDetector(_baseline(), threshold=3.0, confirmation_windows=2)
    runtime = MCPRuntime(detector, window_seconds=60)
    start = 2_000.0
    for index in range(300):
        assert runtime.ingest(NORMAL, namespace="demo", pod="agent", ts=start + index * 0.2).decision == "normal"
    first = runtime.ingest(ATTACK, namespace="demo", pod="agent", ts=start + 60.0)
    second = runtime.ingest(ATTACK, namespace="demo", pod="agent", ts=start + 60.2)
    assert first.decision == "pending"
    assert second.decision == "alert"


def test_runtime_benchmark_has_sub_100ms_p99_for_small_payloads():
    detector = OnlineMCPDetector(_baseline(), threshold=1000.0)
    metrics = MCPRuntime(detector).benchmark([NORMAL] * 200, namespace="demo", pod="agent")
    assert metrics.decisions == 200
    assert metrics.events == 200
    assert metrics.alerts == 0
    assert metrics.p99_ms < 100


def test_independent_agent_windows_do_not_mix_normal_behaviors():
    detector = OnlineMCPDetector(_baseline(), threshold=3.0, confirmation_windows=2)
    runtime = MCPRuntime(detector)

    first = runtime.ingest(NORMAL, namespace="demo", pod="agent-a", agent_id="agent-a")
    second = runtime.ingest(NORMAL, namespace="demo", pod="agent-b", agent_id="agent-b")

    assert first.decision == "normal"
    assert second.decision == "normal"
    assert len(runtime._graphs) == 2


def test_adaptive_pot_uses_only_clean_scores_and_never_lowers_baseline_floor():
    calibrator = AdaptivePOTThreshold(minimum=3.0, warmup=4, margin=0.25)
    for score in (0.1, 0.3, 0.2, 0.4):
        calibrator.observe_clean(score)
    assert calibrator.ready is True
    assert calibrator.current == 3.0

    detector = OnlineMCPDetector(_baseline(), threshold=3.0, confirmation_windows=2, pot_warmup=2)
    runtime = MCPRuntime(detector)
    for _ in range(3):
        runtime.ingest(NORMAL, namespace="demo", pod="agent")
    before = detector._calibrators["demo/agent"].samples
    runtime.ingest(ATTACK, namespace="demo", pod="agent")
    assert detector._calibrators["demo/agent"].samples == before
