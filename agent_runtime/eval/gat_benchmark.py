"""Repeatable CPU latency benchmark for the optional GAT graph scorer."""

from __future__ import annotations

import argparse
import json
import time

from agent_runtime.detector.gat_model import GATGraphScorer, available
from agent_runtime.eval.replay_validation import NORMAL
from agent_runtime.mcp.graph import SlidingMCPGraph, parse_jsonrpc_payload


def snapshot(count: int, ts: float):
    graph = SlidingMCPGraph(window_seconds=60)
    for index in range(count):
        graph.add_events(parse_jsonrpc_payload(NORMAL, namespace="gat-benchmark", pod="agent", ts=ts + index * 0.2))
    return graph.snapshot(now=ts + 60)


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, int((len(ordered) - 1) * fraction)))]


def run(iterations: int, epochs: int) -> dict[str, float]:
    if not available():
        raise RuntimeError("torch-geometric is required")
    clean = [snapshot(count, 100.0 + count) for count in (180, 240, 300, 360)]
    scorer = GATGraphScorer.fit(clean, epochs=epochs)
    target = clean[2]
    # warm-up avoids measuring module initialization/cache effects.
    scorer.score(target)
    timings = []
    for _ in range(iterations):
        started = time.perf_counter()
        scorer.score(target)
        timings.append((time.perf_counter() - started) * 1_000)
    return {
        "iterations": float(iterations),
        "threshold": scorer.threshold,
        "p50_ms": percentile(timings, 0.50),
        "p95_ms": percentile(timings, 0.95),
        "p99_ms": percentile(timings, 0.99),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark Agent Runtime Sentinel GAT inference")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--epochs", type=int, default=80)
    args = parser.parse_args()
    if args.iterations <= 0 or args.epochs <= 0:
        parser.error("iterations and epochs must be positive")
    print(json.dumps(run(args.iterations, args.epochs), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
