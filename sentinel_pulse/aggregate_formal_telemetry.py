"""Aggregate checksum-bound telemetry gates for a formal Pulse normal soak."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path

from .validate_capture import HARD_INTEGRITY_COUNTERS


def _finite(value, label: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"{label} is not finite")
    return parsed


def aggregate(marker: dict, reports: dict[str, dict]) -> dict:
    contract = marker["telemetry_availability_contract"]
    nominal = _finite(contract["nominal_interval_seconds"], "nominal interval")
    minimum = _finite(contract["minimum_availability"], "minimum availability")
    maximum_gap = _finite(
        contract["maximum_single_gap_seconds"], "maximum single gap"
    )
    if nominal <= 0 or not 0 < minimum <= 1 or maximum_gap < 0.8:
        raise ValueError("invalid telemetry availability contract")

    nodes = {}
    for node, report in sorted(reports.items()):
        if report.get("telemetry_availability_contract") != contract:
            raise ValueError(f"telemetry contract mismatch: {node}")
        availability = report.get("telemetry_availability", {})
        observed_availability = _finite(
            availability.get("availability", 0.0), f"{node} availability"
        )
        observed_maximum_gap = _finite(
            availability.get("maximum_gap_seconds", math.inf),
            f"{node} maximum gap",
        )
        hard = {
            name: int(report.get("collector_max_drops", {}).get(name, 0))
            for name in HARD_INTEGRITY_COUNTERS
        }
        node_valid = (
            report.get("valid") is True
            and all(value == 0 for value in hard.values())
            and observed_availability >= minimum
            and observed_maximum_gap <= maximum_gap
        )
        nodes[node] = {
            "valid": node_valid,
            "duration_seconds": report.get("duration_seconds"),
            "rows": report.get("rows"),
            "workload_count": report.get("workload_count"),
            "telemetry_availability": availability,
            "hard_integrity_counters": hard,
        }

    return {
        "schema": "sentinel-pulse-formal-telemetry-report-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run_id": marker["run_id"],
        "contract": contract,
        "nodes": nodes,
        "valid": len(nodes) == 3 and all(item["valid"] for item in nodes.values()),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--marker", required=True, type=Path)
    parser.add_argument("--node-report", required=True, action="append")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError(f"refusing to overwrite telemetry report: {args.output}")
    reports = {}
    for item in args.node_report:
        node, separator, raw_path = item.partition("=")
        if not separator or not node or node in reports:
            raise ValueError(f"invalid or duplicate node report: {item}")
        reports[node] = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    marker = json.loads(args.marker.read_text(encoding="utf-8"))
    result = aggregate(marker, reports)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    raise SystemExit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
