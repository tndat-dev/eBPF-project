"""Summarize detector operational latency on marker-bound normal evidence."""

from __future__ import annotations

import argparse
from datetime import datetime
import heapq
import json
import math
from pathlib import Path

import numpy as np

from .integrity import sha256_file


def percentiles(values: list[float]) -> dict:
    if not values:
        return {}
    array = np.asarray(values, dtype=np.float64)
    return {
        "count": int(array.size),
        "mean": float(array.mean()),
        "p50": float(np.quantile(array, 0.50)),
        "p95": float(np.quantile(array, 0.95)),
        "p99": float(np.quantile(array, 0.99)),
        "p99_9": float(np.quantile(array, 0.999)),
        "max": float(array.max()),
    }


def load_marker(path: Path) -> dict:
    marker = json.loads(path.read_text(encoding="utf-8"))
    if (
        not str(marker.get("schema", "")).startswith(
            "sentinel-pulse-semantic-soak-start-"
        )
        or marker.get("blind_evaluation_started") is not False
    ):
        raise ValueError("invalid normal-only soak marker")
    try:
        started_at = datetime.fromisoformat(str(marker["started_not_before"])).timestamp()
    except (KeyError, ValueError) as error:
        raise ValueError("invalid normal-only soak marker time") from error
    return {"record": marker, "started_at": started_at, "sha256": sha256_file(path)}


def evaluate(paths: list[Path], soak_marker_path: Path) -> dict:
    if not paths:
        raise ValueError("at least one decision source is required")
    marker = load_marker(soak_marker_path)
    combined = {
        "inference_ms": [],
        "post_window_processing_seconds": [],
        "window_start_to_decision_seconds": [],
        "window_end_to_decision_seconds": [],
    }
    source_reports = []
    excluded = 0
    delayed_over_two_seconds = 0
    top_delays: list[tuple[float, int, dict]] = []
    sequence = 0

    for path in paths:
        source_values = {name: [] for name in combined}
        source_rows = 0
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                record = json.loads(line)
                if record.get("schema") != "sentinel-pulse-decision-v1" or record.get(
                    "status"
                ) not in {"normal", "suppressed", "alert"}:
                    continue
                try:
                    window_start = float(record["window_start"])
                    window_end = float(record["window_end"])
                    alerted_at = float(record["alerted_at"])
                    inference_ms = float(record["inference_ms"])
                    processing = float(record["post_window_processing_seconds"])
                except (KeyError, TypeError, ValueError) as error:
                    raise ValueError(
                        f"{path}:{line_number}: incomplete operational latency record"
                    ) from error
                values = (
                    window_start,
                    window_end,
                    alerted_at,
                    inference_ms,
                    processing,
                )
                if not all(math.isfinite(value) for value in values):
                    raise ValueError(f"{path}:{line_number}: non-finite latency value")
                if window_end < marker["started_at"]:
                    excluded += 1
                    continue
                expected = marker["record"]
                if (
                    record.get("run_id") != expected.get("run_id")
                    or record.get("model_manifest_sha256")
                    != expected.get("model_manifest_sha256")
                    or record.get("decision_policy_sha256")
                    != expected.get("decision_policy_sha256")
                ):
                    raise ValueError(
                        f"{path}:{line_number}: decision identity differs from soak marker"
                    )
                if window_start > window_end or alerted_at < window_end or processing < 0.0:
                    raise ValueError(f"{path}:{line_number}: impossible latency ordering")
                measured = {
                    "inference_ms": inference_ms,
                    "post_window_processing_seconds": processing,
                    "window_start_to_decision_seconds": alerted_at - window_start,
                    "window_end_to_decision_seconds": alerted_at - window_end,
                }
                for name, value in measured.items():
                    source_values[name].append(value)
                    combined[name].append(value)
                source_rows += 1
                total_delay = measured["window_start_to_decision_seconds"]
                if total_delay > 2.0:
                    delayed_over_two_seconds += 1
                item = {
                    "source": str(path),
                    "line": line_number,
                    "workload_key": record.get("workload_key"),
                    "status": record.get("status"),
                    "window_end": window_end,
                    **measured,
                }
                sequence += 1
                heap_item = (total_delay, sequence, item)
                if len(top_delays) < 20:
                    heapq.heappush(top_delays, heap_item)
                elif total_delay > top_delays[0][0]:
                    heapq.heapreplace(top_delays, heap_item)
        source_reports.append(
            {
                "path": str(path),
                "sha256": sha256_file(path),
                "scored_rows": source_rows,
                "latency": {
                    name: percentiles(values) for name, values in source_values.items()
                },
            }
        )

    scored_rows = len(combined["inference_ms"])
    return {
        "schema": "sentinel-pulse-operational-latency-report-v1",
        "normal_only_evidence": True,
        "true_attack_kernel_to_alert_claim": False,
        "soak_marker_sha256": marker["sha256"],
        "excluded_scored_windows_before_marker": excluded,
        "scored_rows": scored_rows,
        "sources": source_reports,
        "latency": {name: percentiles(values) for name, values in combined.items()},
        "window_start_to_decision_over_2s": delayed_over_two_seconds,
        "window_start_to_decision_over_2s_ratio": (
            delayed_over_two_seconds / scored_rows if scored_rows else None
        ),
        "top_20_window_start_to_decision": [
            item for _delay, _sequence, item in sorted(top_delays, reverse=True)
        ],
        "interpretation": (
            "Operational normal-path timing is not injection-to-alert latency. "
            "Blind live attack markers remain required for the paper latency claim."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decisions", type=Path, action="append", required=True)
    parser.add_argument("--soak-marker", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = evaluate(args.decisions, args.soak_marker)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
