import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_runtime.detector.graph_features import graph_feature_vector
from agent_runtime.eval.agent_scenarios import AGENT_ATTACK_SCENARIOS
from agent_runtime.mcp.graph import SlidingMCPGraph, parse_jsonrpc_payload


def test_parse_mcp_tool_call_extracts_tool_resources_and_risk():
    payload = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "kubectl.delete",
            "arguments": {
                "namespace": "production",
                "resource": "deployment/nginx",
                "secret": "api-token",
            },
        },
    }

    events = parse_jsonrpc_payload(
        __import__("json").dumps(payload),
        namespace="agents",
        pod="planner-0",
        agent_id="planner",
        ts=100.0,
    )

    assert len(events) == 1
    event = events[0]
    assert event.tool_name == "kubectl.delete"
    assert event.jsonrpc_method == "tools/call"
    assert event.high_risk is True
    assert event.agent_id == "planner"
    assert event.request_id == "7"
    assert len(event.resources) >= 3


def test_batch_parser_ignores_jsonrpc_responses_without_method():
    payload = '[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":1,"result":{}}]'

    events = parse_jsonrpc_payload(payload, namespace="agents", pod="worker-0", ts=1.0)

    assert [event.tool_name for event in events] == ["tools/list"]


def test_sliding_graph_expires_old_events_and_builds_features():
    graph = SlidingMCPGraph(window_seconds=10)
    old_event = parse_jsonrpc_payload(
        '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
        namespace="agents",
        pod="a",
        ts=1.0,
    )
    new_event = parse_jsonrpc_payload(
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell.exec","path":"/proc/1/root"}}',
        namespace="agents",
        pod="a",
        ts=20.0,
    )
    graph.add_events(old_event + new_event)

    snapshot = graph.snapshot(now=20.0)
    vector = graph_feature_vector(snapshot)

    assert len(snapshot.events) == 1
    assert snapshot.features["events_total"] == 1.0
    assert snapshot.features["high_risk_events"] == 1.0
    assert len(snapshot.nodes) >= 3
    assert len(snapshot.edges) >= 2
    assert len(vector) == 11


def test_invalid_payload_returns_no_events():
    assert parse_jsonrpc_payload("{not-json", namespace="agents", pod="x") == []


def test_sensitive_resource_marks_event_high_risk_before_storage_hashing():
    events = parse_jsonrpc_payload(
        '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"inventory.lookup","resource":"secret/production-db"}}',
        namespace="agents",
        pod="reader-0",
        ts=1.0,
    )

    assert events[0].high_risk is True
    assert "secret" not in events[0].resources[0]


def test_production_namespace_alone_is_not_a_high_risk_signal():
    events = parse_jsonrpc_payload(
        '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"inventory.lookup","namespace":"production"}}',
        namespace="agents",
        pod="reader-0",
        ts=1.0,
    )

    assert events[0].high_risk is False


def test_sliding_graph_has_a_hard_event_capacity():
    graph = SlidingMCPGraph(window_seconds=100, max_events=2)
    for timestamp in range(3):
        graph.add_events(
            parse_jsonrpc_payload(
                '{"jsonrpc":"2.0","method":"tools/list"}',
                namespace="agents",
                pod="reader-0",
                ts=float(timestamp),
            )
        )

    assert [event.ts for event in graph.snapshot(now=3.0).events] == [1.0, 2.0]


def test_agent_attack_scenarios_cover_v2_methodology():
    assert len(AGENT_ATTACK_SCENARIOS) == 5
    assert {scenario.scenario_id for scenario in AGENT_ATTACK_SCENARIOS} == {
        "agent-secret-exfiltration",
        "agent-overprivileged-kubectl",
        "agent-production-delete",
        "agent-lateral-movement",
        "agent-container-escape",
    }
