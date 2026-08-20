"""Benchmark a frozen Pulse bundle without making an accuracy claim."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import resource
import time

import numpy as np

from .detect import PulseRuntime
from .integrity import sha256_file


def distribution(values: list[float]) -> dict:
    if not values:
        return {"count": 0, "mean": None, "p50": None, "p95": None, "p99": None, "max": None}
    samples = np.asarray(values, dtype=np.float64)
    return {
        "count": int(len(samples)),
        "mean": float(np.mean(samples)),
        "p50": float(np.quantile(samples, 0.50)),
        "p95": float(np.quantile(samples, 0.95)),
        "p99": float(np.quantile(samples, 0.99)),
        "max": float(np.max(samples)),
    }


def benchmark(
    model_dir: Path,
    dataset: Path,
    decision_policy: Path,
    per_workload: int,
) -> dict:
    if per_workload <= 0:
        raise ValueError("per-workload sample count must be positive")
    load_started = time.perf_counter()
    runtime = PulseRuntime(model_dir, decision_policy)
    load_seconds = time.perf_counter() - load_started
    target_workloads = set(runtime.models)
    scored_by_workload: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    inference_by_workload: dict[str, list[float]] = defaultdict(list)
    inference_ms: list[float] = []
    source_rows = 0
    replay_started = time.perf_counter()
    with dataset.open(encoding="utf-8") as source:
        for line in source:
            record = json.loads(line)
            if record.get("schema") == "sentinel-pulse-feature-schema-v1":
                continue
            source_rows += 1
            workload = record.get("workload_key")
            if workload not in target_workloads or scored_by_workload[workload] >= per_workload:
                continue
            result = runtime.score(record)
            statuses[result["status"]] += 1
            if "inference_ms" in result:
                value = float(result["inference_ms"])
                inference_ms.append(value)
                inference_by_workload[workload].append(value)
                scored_by_workload[workload] += 1
            if all(scored_by_workload[name] >= per_workload for name in target_workloads):
                break
    replay_seconds = time.perf_counter() - replay_started
    missing = sorted(target_workloads - set(scored_by_workload))
    short = {
        name: scored_by_workload[name]
        for name in sorted(target_workloads)
        if scored_by_workload[name] < per_workload
    }
    return {
        "schema": "sentinel-pulse-inference-benchmark-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model_manifest_sha256": runtime.model_manifest_sha256,
        "dataset_sha256": sha256_file(dataset),
        "decision_policy_sha256": runtime.decision_policy_sha256,
        "method": "bounded in-sample replay with equal per-workload scored-window cap",
        "in_sample": True,
        "accuracy_evidence": False,
        "latency_scope": "model inference only; excludes telemetry window and ingest lag",
        "target_workloads": len(target_workloads),
        "per_workload_target": per_workload,
        "source_rows_read": source_rows,
        "model_load_seconds": load_seconds,
        "replay_seconds": replay_seconds,
        "scored_windows_per_second": len(inference_ms) / replay_seconds if replay_seconds else None,
        "max_rss_kib": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
        "status_counts": dict(sorted(statuses.items())),
        "missing_workloads": missing,
        "short_workloads": short,
        "inference_ms": distribution(inference_ms),
        "inference_ms_by_workload": {
            name: distribution(inference_by_workload[name])
            for name in sorted(target_workloads)
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--decision-policy", type=Path, required=True)
    parser.add_argument("--per-workload", type=int, default=500)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = benchmark(
        args.model_dir,
        args.dataset,
        args.decision_policy,
        args.per_workload,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report["missing_workloads"] or report["short_workloads"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
