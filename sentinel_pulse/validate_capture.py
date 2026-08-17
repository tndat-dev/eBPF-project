"""Fail-closed integrity and latency validation for Pulse feature captures."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys
import zlib

import numpy as np

from .encoding import decode_vector, schema_digest
from .integrity import sha256_file


DROP_COUNTERS = (
    "count_insert_fail",
    "transition_insert_fail",
    "task_state_update_fail",
    "snapshot_consistency_retry_exhausted",
    "snapshot_total_mismatch",
    "target_snapshot_gap",
)


def validate(
    path: Path,
    minimum_rows_per_workload: int = 100,
    interval_min_seconds: float = 0.80,
    interval_max_seconds: float = 1.50,
) -> dict:
    if interval_min_seconds <= 0 or interval_max_seconds <= interval_min_seconds:
        raise ValueError("invalid capture interval bounds")
    errors = []
    rows = 0
    workloads = Counter()
    cgroup_last_end = {}
    intervals = []
    lags = []
    window_to_emit = []
    snapshot_reads = []
    columns = None
    max_drops = defaultdict(int)
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                errors.append(f"line {line_number}: invalid JSON: {error}")
                continue
            if record.get("schema") == "sentinel-pulse-feature-schema-v1":
                current_columns = record.get("columns", [])
                if schema_digest(current_columns) != record.get("feature_schema_sha256"):
                    errors.append(f"line {line_number}: invalid schema digest")
                if columns is None:
                    columns = current_columns
                elif current_columns != columns:
                    errors.append(f"line {line_number}: feature schema drift")
                continue
            if record.get("schema") != "sentinel-pulse-feature-v1":
                errors.append(f"line {line_number}: unsupported schema")
                continue
            rows += 1
            workload = str(record.get("workload_key", ""))
            workloads[workload] += 1
            current_columns = record.get("columns")
            if current_columns is not None:
                if columns is None:
                    columns = current_columns
                elif current_columns != columns:
                    errors.append(f"line {line_number}: feature schema drift")
            if columns is None:
                errors.append(f"line {line_number}: feature row precedes schema")
                continue
            if len(columns) != len(set(columns)):
                errors.append("feature columns are not unique")
            try:
                vector = decode_vector(record)
            except (ValueError, zlib.error) as error:
                errors.append(f"line {line_number}: {error}")
                continue
            if len(vector) != len(columns):
                errors.append(f"line {line_number}: vector length mismatch")
            start, end = float(record["window_start"]), float(record["window_end"])
            interval = end - start
            intervals.append(interval)
            if not interval_min_seconds <= interval <= interval_max_seconds:
                errors.append(f"line {line_number}: invalid interval {interval:.6f}s")
            source_identity = "|".join(
                (
                    str(record.get("node_name", "unknown-node")),
                    str(record.get("pod_uid", "unknown-pod")),
                    str(record.get("container_name", "unknown-container")),
                    str(record["cgroup_id"]),
                )
            )
            previous = cgroup_last_end.get(source_identity)
            if previous is not None and end <= previous:
                errors.append(f"line {line_number}: non-monotonic cgroup timestamp")
            cgroup_last_end[source_identity] = end
            exact_sum = sum(int(value) for value in record.get("exact_counts", {}).values())
            if exact_sum != int(record.get("exact_total", -1)):
                errors.append(f"line {line_number}: exact count total mismatch")
            emitted_at = float(record.get("emitted_at", end))
            lags.append(max(0.0, emitted_at - end))
            window_to_emit.append(max(0.0, emitted_at - start))
            snapshot_reads.append(max(0.0, float(record.get("snapshot_read_seconds", 0.0))))
            stats = record.get("collector_stats", {})
            for name in DROP_COUNTERS:
                max_drops[name] = max(max_drops[name], int(stats.get(name, 0)))
    if rows == 0:
        errors.append("capture has no feature rows")
    for workload, count in workloads.items():
        if count < minimum_rows_per_workload:
            errors.append(f"{workload}: only {count} rows, need {minimum_rows_per_workload}")
    for name in DROP_COUNTERS:
        if max_drops[name] != 0:
            errors.append(f"collector loss: {name}={max_drops[name]}")

    def percentiles(values):
        if not values:
            return {}
        return {
            "p50": float(np.quantile(values, 0.50)),
            "p95": float(np.quantile(values, 0.95)),
            "p99": float(np.quantile(values, 0.99)),
            "max": float(np.max(values)),
        }

    return {
        "schema": "sentinel-pulse-capture-validation-v1",
        "valid": not errors,
        "path": str(path),
        "capture_sha256": sha256_file(path),
        "rows": rows,
        "feature_dim": len(columns or []),
        "accepted_interval_seconds": {
            "minimum": interval_min_seconds,
            "maximum": interval_max_seconds,
        },
        "workloads": dict(sorted(workloads.items())),
        "interval_seconds": percentiles(intervals),
        "ingest_lag_seconds": percentiles(lags),
        "window_start_to_emit_seconds": percentiles(window_to_emit),
        "snapshot_read_seconds": percentiles(snapshot_reads),
        "collector_max_drops": dict(max_drops),
        "errors": errors[:200],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--minimum-rows-per-workload", type=int, default=100)
    parser.add_argument("--interval-min-seconds", type=float, default=0.80)
    parser.add_argument("--interval-max-seconds", type=float, default=1.50)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate(
        args.capture,
        args.minimum_rows_per_workload,
        args.interval_min_seconds,
        args.interval_max_seconds,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    raise SystemExit(0 if report["valid"] else 1)


if __name__ == "__main__":
    main()
