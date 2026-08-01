"""Repeatable latency benchmark for the V2 semantic pipeline.

This measures userspace work only: JSON-RPC parsing, bounded graph update,
snapshot generation, and feature-vector construction. Kernel uprobe delivery
and model inference are measured separately in the deployed V1 harness.
"""

from __future__ import annotations

import argparse
import json
import time
from typing import Iterable

from agent_runtime.detector.graph_features import graph_feature_vector
from agent_runtime.mcp.graph import SlidingMCPGraph, parse_jsonrpc_payload


DEFAULT_PAYLOAD = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "inventory.lookup",
            "arguments": {"resource": "service/catalog", "namespace": "production"},
        },
    },
    separators=(",", ":"),
)


def percentile(values: Iterable[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * fraction)))
    return ordered[index]


def run(iterations: int, snapshot_every: int, window_seconds: float) -> dict[str, float]:
    graph = SlidingMCPGraph(window_seconds=window_seconds)
    latencies_ms: list[float] = []
    snapshot_latencies_ms: list[float] = []
    base_ts = time.time()

    for index in range(iterations):
        started = time.perf_counter()
        events = parse_jsonrpc_payload(
            DEFAULT_PAYLOAD,
            namespace="agents",
            pod="benchmark-0",
            agent_id="benchmark",
            ts=base_ts + (index / 1000.0),
        )
        graph.add_events(events)
        latencies_ms.append((time.perf_counter() - started) * 1000.0)

        if (index + 1) % snapshot_every == 0:
            started = time.perf_counter()
            snapshot = graph.snapshot(now=base_ts + (index / 1000.0))
            graph_feature_vector(snapshot)
            snapshot_latencies_ms.append((time.perf_counter() - started) * 1000.0)

    return {
        "iterations": float(iterations),
        "snapshot_every": float(snapshot_every),
        "ingest_p50_ms": percentile(latencies_ms, 0.50),
        "ingest_p95_ms": percentile(latencies_ms, 0.95),
        "ingest_p99_ms": percentile(latencies_ms, 0.99),
        "snapshot_p50_ms": percentile(snapshot_latencies_ms, 0.50),
        "snapshot_p95_ms": percentile(snapshot_latencies_ms, 0.95),
        "snapshot_p99_ms": percentile(snapshot_latencies_ms, 0.99),
        "events_retained": float(
            len(graph.snapshot(now=base_ts + ((iterations - 1) / 1000.0)).events)
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark V2 MCP semantic pipeline latency")
    parser.add_argument("--iterations", type=int, default=10_000)
    parser.add_argument("--snapshot-every", type=int, default=100)
    parser.add_argument("--window-seconds", type=float, default=300.0)
    args = parser.parse_args()
    if args.iterations <= 0 or args.snapshot_every <= 0 or args.window_seconds <= 0:
        parser.error("iterations, snapshot-every and window-seconds must be positive")
    print(json.dumps(run(args.iterations, args.snapshot_every, args.window_seconds), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
