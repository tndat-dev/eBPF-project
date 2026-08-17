"""Validate and aggregate paired OFF/ON Sentinel Pulse 500 ms overhead blocks."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import statistics
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def bootstrap_median(values: list[float], seed: int) -> dict:
    if not values:
        raise ValueError("empty paired effect sample")
    rng = random.Random(seed)
    samples = [
        statistics.median(rng.choice(values) for _ in values)
        for _ in range(10_000)
    ]
    return {
        "pairs": len(values),
        "values_percent": values,
        "median_percent": statistics.median(values),
        "bootstrap_95ci_percent": [
            percentile(samples, 0.025),
            percentile(samples, 0.975),
        ],
    }


def aggregate(root: Path, protocol_path: Path) -> dict:
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    if protocol.get("schema") != "sentinel-pulse-500ms-overhead-protocol-v1":
        raise ValueError("unsupported overhead protocol")
    phases = protocol.get("phases", [])
    if not phases or len(phases) % 2:
        raise ValueError("overhead protocol requires complete adjacent pairs")

    records = []
    for expected_index, phase in enumerate(phases, 1):
        if int(phase.get("index", 0)) != expected_index:
            raise ValueError("non-contiguous phase index")
        condition = phase.get("condition")
        if condition not in ("off", "on"):
            raise ValueError("invalid overhead condition")
        phase_name = str(phase.get("name", ""))
        if not re.fullmatch(r"p[0-9]{2}-(off|on)", phase_name):
            raise ValueError("unsafe phase name")
        matches = list(root.glob(f"{phase_name}-*/report.json"))
        if len(matches) != 1:
            raise ValueError(f"expected one phase report for {phase_name}, got {len(matches)}")
        report_path = matches[0]
        if not report_path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"unsafe phase report: {report_path}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if (
            report.get("experiment_id") != protocol.get("campaign_id")
            or report.get("phase") != phase.get("name")
            or report.get("url") != protocol.get("endpoint", {}).get("url")
            or report.get("quality_gate", {}).get("passed") is not True
            or int(report.get("failed_requests_total", -1)) != 0
            or len(report.get("runs", []))
            != int(protocol.get("repetitions_per_phase", 0))
        ):
            raise ValueError(f"phase integrity/quality failed: {phase.get('name')}")
        records.append(
            {
                "index": expected_index,
                "name": phase_name,
                "condition": condition,
                "report": str(report_path.relative_to(root)),
                "report_sha256": sha256(report_path),
                "rps_median": float(report["requests_per_second"]["median"]),
                "latency_p99_ms_median": float(report["latency_p99_ms"]["median"]),
            }
        )

    throughput, latency, pairs = [], [], []
    for offset in range(0, len(records), 2):
        pair = records[offset : offset + 2]
        if {item["condition"] for item in pair} != {"off", "on"}:
            raise ValueError(f"phase pair {offset // 2 + 1} is not OFF/ON balanced")
        by_condition = {item["condition"]: item for item in pair}
        off, on = by_condition["off"], by_condition["on"]
        if off["rps_median"] <= 0 or off["latency_p99_ms_median"] <= 0:
            raise ValueError("zero control metric")
        throughput_effect = 100.0 * (1.0 - on["rps_median"] / off["rps_median"])
        latency_effect = 100.0 * (
            on["latency_p99_ms_median"] / off["latency_p99_ms_median"] - 1.0
        )
        throughput.append(throughput_effect)
        latency.append(latency_effect)
        pairs.append(
            {
                "pair": offset // 2 + 1,
                "order": [item["condition"] for item in pair],
                "throughput_loss_percent": throughput_effect,
                "p99_latency_increase_percent": latency_effect,
            }
        )

    inferential = protocol.get("mode") == "full" and len(pairs) >= 4
    return {
        "schema": "sentinel-pulse-500ms-overhead-result-v1",
        "campaign_id": protocol["campaign_id"],
        "mode": protocol.get("mode"),
        "valid": True,
        "inferential": inferential,
        "protocol_sha256": sha256(protocol_path),
        "records": records,
        "pairs": pairs,
        "effects": {
            "throughput_loss": bootstrap_median(throughput, 20260817),
            "p99_latency_increase": bootstrap_median(latency, 20260818),
        },
        "limitations": [
            "Treatment runs on one worker and targets its ingress pod directly.",
            "Smoke mode validates machinery only and is not inferential evidence.",
            "Service cgroup accounting does not capture all eBPF CPU charged to workloads.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = aggregate(args.root, args.protocol)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
