from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_runtime.detector.online_detector import MCPBaseline, OnlineMCPDetector
from agent_runtime.detector.baseline_store import load_baseline, save_baseline
from agent_runtime.mcp.graph import SlidingMCPGraph, parse_jsonrpc_payload
from agent_runtime.mcp.transport import TLSJSONReassembler
from agent_runtime.ring_reader import MCPRingReader, consume_lines, lab_runtime, parse_capture_line
from agent_runtime.runtime import MCPRuntime


NORMAL = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_docs","arguments":{"uri":"kb://runbook"}}}'


def _baseline() -> MCPBaseline:
    snapshots = []
    for count in range(1, 5):
        graph = SlidingMCPGraph(window_seconds=60)
        for _ in range(count):
            graph.add_events(parse_jsonrpc_payload(NORMAL, namespace="lab", pod="agent", ts=10.0))
        snapshots.append(graph.snapshot(now=11.0))
    return MCPBaseline.fit(snapshots)


def _capture_line(pid: int, payload: bytes, ts_ns: int) -> str:
    return json.dumps({"ts_ns": ts_ns, "pid": pid, "direction": "write", "payload_hex": payload.hex()})


def test_reassembler_handles_fragmented_http_request():
    request = b"POST /mcp HTTP/1.1\r\nHost: mcp\r\nContent-Length: " + str(len(NORMAL)).encode() + b"\r\n\r\n" + NORMAL
    reassembler = TLSJSONReassembler()
    assert reassembler.feed(request[:21]) == []
    assert reassembler.feed(request[21:]) == [NORMAL]


def test_ring_reader_routes_fragmented_loader_events_without_echoing_plaintext():
    request = b"POST /mcp HTTP/1.1\r\nContent-Length: " + str(len(NORMAL)).encode() + b"\r\n\r\n" + NORMAL
    timestamp = time.time_ns()
    runtime = MCPRuntime(OnlineMCPDetector(_baseline(), threshold=100.0))
    reader = MCPRingReader(runtime, namespace="agent-sentinel-lab", pod="mcp-normal-loadgen", agent_id="documentation-agent")
    output = io.StringIO()
    emitted = consume_lines(reader, [_capture_line(31337, request[:17], timestamp), _capture_line(31337, request[17:], timestamp + 1)], output)
    assert emitted == 1
    assert '"decision": "normal"' in output.getvalue()
    assert "search_docs" not in output.getvalue()


def test_capture_parser_rejects_malformed_or_oversized_event():
    assert parse_capture_line("not-json") is None
    assert parse_capture_line(json.dumps({"ts_ns": 1, "pid": 1, "direction": "write", "payload_hex": "00" * 513})) is None


def test_bundled_lab_runtime_keeps_normal_mcp_request_normal():
    decision = lab_runtime().ingest(NORMAL, namespace="agent-sentinel-lab", pod="mcp-normal-loadgen")
    assert decision.decision == "normal"


def test_ring_reader_converts_bpf_monotonic_time_before_detection_latency():
    attack = b'{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"kubectl.delete","arguments":{"namespace":"production","resource":"deployment/payments"}}}'
    runtime = MCPRuntime(OnlineMCPDetector(_baseline(), threshold=3.0, confirmation_windows=2))
    reader = MCPRingReader(runtime, namespace="agent-sentinel-lab", pod="mcp-normal-loadgen")
    first = reader.consume(parse_capture_line(_capture_line(99, attack, time.monotonic_ns())))
    second = reader.consume(parse_capture_line(_capture_line(99, attack, time.monotonic_ns() + 1_000_000)))
    assert first[0].decision == "pending"
    assert second[0].alert is not None
    assert 0 <= second[0].alert.detection_latency < 2


def test_reviewed_baseline_round_trip_and_agent_binding(tmp_path):
    path = tmp_path / "documentation-agent.json"
    baseline = _baseline()
    save_baseline(path, baseline, agent_id="documentation-agent")
    assert load_baseline(path, expected_agent_id="documentation-agent") == baseline
    with pytest.raises(ValueError, match="another agent"):
        load_baseline(path, expected_agent_id="other-agent")


def test_baseline_digest_detects_tampering(tmp_path):
    path = tmp_path / "baseline.json"
    save_baseline(path, _baseline(), agent_id="documentation-agent")
    value = json.loads(path.read_text())
    value["median"][0] = 999
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="digest"):
        load_baseline(path)
