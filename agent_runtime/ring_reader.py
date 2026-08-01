"""Bridge controlled TLS-u​probe JSONL output into the realtime MCP detector.

The C loader only emits a payload when started with ``--emit-payload`` for an
explicit PID.  This reader accepts that JSONL stream on stdin, reconstructs
fragmented HTTP/JSON data per PID, and never writes captured plaintext to disk.
"""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import json
import sys
import time
from typing import Iterable, TextIO

from agent_runtime.mcp.transport import TLSJSONReassembler
from agent_runtime.detector.online_detector import MCPBaseline, OnlineMCPDetector
from agent_runtime.detector.baseline_store import load_baseline
from agent_runtime.mcp.graph import SlidingMCPGraph, parse_jsonrpc_payload
from agent_runtime.runtime import MCPRuntime


@dataclass(frozen=True)
class TLSCapture:
    ts_ns: int
    pid: int
    direction: str
    payload: bytes


def parse_capture_line(line: str, *, max_payload_bytes: int = 512) -> TLSCapture | None:
    """Decode one loader JSON line without accepting oversized input."""

    try:
        value = json.loads(line)
        payload_hex = value["payload_hex"]
        payload = bytes.fromhex(payload_hex)
        capture = TLSCapture(
            ts_ns=int(value["ts_ns"]),
            pid=int(value["pid"]),
            direction=str(value["direction"]),
            payload=payload,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    if capture.ts_ns < 0 or capture.pid <= 0 or len(capture.payload) > max_payload_bytes:
        return None
    return capture


class MCPRingReader:
    """In-memory-only reassembly and routing for explicitly captured TLS data."""

    def __init__(self, runtime: MCPRuntime, *, namespace: str, pod: str, agent_id: str | None = None) -> None:
        self.runtime = runtime
        self.namespace = namespace
        self.pod = pod
        self.agent_id = agent_id
        self._reassemblers: dict[int, TLSJSONReassembler] = {}
        # bpf_ktime_get_ns() is monotonic since boot, while detection latency
        # uses wall-clock epoch seconds. Anchor the first event once and retain
        # only monotonic deltas afterwards; never subtract the two clock bases.
        self._clock_anchor_mono_ns: int | None = None
        self._clock_anchor_wall: float | None = None

    def consume(self, capture: TLSCapture):
        if capture.direction != "write":
            return []
        reassembler = self._reassemblers.setdefault(capture.pid, TLSJSONReassembler())
        event_ts = self._event_timestamp(capture.ts_ns)
        decisions = []
        for payload in reassembler.feed(capture.payload):
            decisions.append(
                self.runtime.ingest(
                    payload,
                    namespace=self.namespace,
                    pod=self.pod,
                    agent_id=self.agent_id,
                    ts=event_ts,
                )
            )
        return decisions

    def _event_timestamp(self, monotonic_ns: int) -> float:
        if self._clock_anchor_mono_ns is None:
            self._clock_anchor_mono_ns = monotonic_ns
            self._clock_anchor_wall = time.time()
        assert self._clock_anchor_wall is not None
        return self._clock_anchor_wall + (monotonic_ns - self._clock_anchor_mono_ns) / 1_000_000_000


def consume_lines(reader: MCPRingReader, lines: Iterable[str], output: TextIO = sys.stdout) -> int:
    """Consume loader JSONL and emit decisions only; no plaintext is echoed."""

    emitted = 0
    for line in lines:
        capture = parse_capture_line(line)
        if capture is None:
            continue
        for decision in reader.consume(capture):
            value = {"decision": decision.decision, "score": decision.score, "threshold": decision.threshold,
                     "inference_ms": decision.inference_ms, "end_to_end_ms": decision.end_to_end_ms}
            if decision.alert:
                value["alert"] = decision.alert.to_dict()
            output.write(json.dumps(value, sort_keys=True) + "\n")
            output.flush()
            emitted += 1
    return emitted


def lab_runtime() -> MCPRuntime:
    """Create an explicit, non-production baseline for the HTTPS lab only."""

    normal = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_docs","arguments":{"uri":"kb://runbook"}}}'
    snapshots = []
    for count in range(1, 11):
        graph = SlidingMCPGraph(window_seconds=60)
        for _ in range(count):
            graph.add_events(parse_jsonrpc_payload(normal, namespace="agent-sentinel-lab", pod="mcp-normal-loadgen", ts=10.0))
        snapshots.append(graph.snapshot(now=11.0))
    baseline = MCPBaseline.fit(snapshots)
    return MCPRuntime(OnlineMCPDetector(baseline, threshold=3.0, confirmation_windows=2))


def main() -> int:
    parser = argparse.ArgumentParser(description="Consume controlled MCP TLS-u​probe JSONL without persisting plaintext")
    baseline_group = parser.add_mutually_exclusive_group(required=True)
    baseline_group.add_argument("--lab-baseline", action="store_true", help="use only the fixed agent-sentinel-lab baseline")
    baseline_group.add_argument("--baseline-file", help="reviewed digest-validated per-agent baseline JSON")
    parser.add_argument("--namespace", default="agent-sentinel-lab")
    parser.add_argument("--pod", default="mcp-normal-loadgen")
    parser.add_argument("--agent-id", default="documentation-agent")
    args = parser.parse_args()
    if args.lab_baseline:
        runtime = lab_runtime()
    else:
        baseline = load_baseline(args.baseline_file, expected_agent_id=args.agent_id)
        runtime = MCPRuntime(OnlineMCPDetector(baseline, threshold=3.0, confirmation_windows=2))
    reader = MCPRingReader(runtime, namespace=args.namespace, pod=args.pod, agent_id=args.agent_id)
    consume_lines(reader, sys.stdin)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
