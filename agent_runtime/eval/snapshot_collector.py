"""Convert controlled TLS-u​probe JSONL into sanitized graph-snapshot JSONL."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from agent_runtime.mcp.graph import MCPEvent, SlidingMCPGraph, parse_jsonrpc_payload
from agent_runtime.mcp.transport import TLSJSONReassembler
from agent_runtime.ring_reader import parse_capture_line


def record(snapshot, review_status: str):
    # Events contain hashed resources and metadata only; raw payload is never persisted.
    return {"generated_at": snapshot.generated_at, "window_seconds": snapshot.window_seconds,
            "review_status": review_status,
            "events": [{"ts": e.ts, "namespace": e.namespace, "pod": e.pod, "agent_id": e.agent_id,
                        "jsonrpc_method": e.jsonrpc_method, "tool_name": e.tool_name, "request_id": e.request_id,
                        "resources": list(e.resources), "raw_size": e.raw_size, "high_risk": e.high_risk} for e in snapshot.events]}


def collect(lines, *, namespace: str, pod: str, agent_id: str, every: int = 1,
            review_status: str = "pending_review"):
    graph = SlidingMCPGraph()
    reassemblers = {}
    count = 0
    for line in lines:
        capture = parse_capture_line(line)
        if not capture or capture.direction != "write":
            continue
        parser = reassemblers.setdefault(capture.pid, TLSJSONReassembler())
        for payload in parser.feed(capture.payload):
            events = parse_jsonrpc_payload(payload, namespace=namespace, pod=pod, agent_id=agent_id, ts=capture.ts_ns / 1e9)
            graph.add_events(events)
            count += 1
            if count % every == 0:
                yield record(graph.snapshot(now=capture.ts_ns / 1e9), review_status)


def main() -> int:
    parser = argparse.ArgumentParser(description="Store sanitized MCP graph snapshots from controlled TLS capture")
    parser.add_argument("--output", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--pod", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--every", type=int, default=1)
    parser.add_argument("--review-status", choices=("pending_review", "approved_normal"),
                        default="pending_review", help="approval is explicit and outside the capture path")
    args = parser.parse_args()
    if args.every < 1: parser.error("every must be positive")
    with Path(args.output).open("w", encoding="utf-8") as output:
        for value in collect(sys.stdin, namespace=args.namespace, pod=args.pod, agent_id=args.agent_id,
                             every=args.every, review_status=args.review_status):
            output.write(json.dumps(value, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
