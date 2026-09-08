"""Fail-closed integrity and latency validation for Pulse feature captures."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import math
from pathlib import Path
import sys
import zlib

import numpy as np

from .encoding import decode_vector, schema_digest
from .integrity import sha256_file


HARD_INTEGRITY_COUNTERS = (
    "count_insert_fail",
    "transition_insert_fail",
    "task_state_update_fail",
    "snapshot_consistency_retry_exhausted",
    "snapshot_total_mismatch",
    "target_snapshot_gap",
)

CADENCE_COUNTER = "capture_interval_violation"


def validate(
    path: Path,
    minimum_rows_per_workload: int = 100,
    interval_min_seconds: float = 0.80,
    interval_max_seconds: float = 1.50,
    nominal_interval_seconds: float = 1.0,
    minimum_telemetry_availability: float = 1.0,
    maximum_single_gap_seconds: float | None = None,
) -> dict:
    if interval_min_seconds <= 0 or interval_max_seconds <= interval_min_seconds:
        raise ValueError("invalid capture interval bounds")
    if nominal_interval_seconds <= 0:
        raise ValueError("nominal interval must be positive")
    if not 0 < minimum_telemetry_availability <= 1:
        raise ValueError("minimum telemetry availability must be in (0, 1]")
    if maximum_single_gap_seconds is None:
        maximum_single_gap_seconds = interval_max_seconds
    if maximum_single_gap_seconds < interval_max_seconds:
        raise ValueError("maximum single gap cannot be below the interval maximum")
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
    snapshot_intervals = {}
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
            if not np.all(np.isfinite(vector)):
                errors.append(f"line {line_number}: non-finite feature vector")
            start, end = float(record["window_start"]), float(record["window_end"])
            interval = end - start
            intervals.append(interval)
            collector_interval = float(
                record.get("collector_snapshot_interval_seconds", interval)
            )
            snapshot_key = (str(record.get("node_name", "unknown-node")), end)
            prior_interval = snapshot_intervals.setdefault(
                snapshot_key, collector_interval
            )
            if not math.isclose(
                prior_interval, collector_interval, rel_tol=0.0, abs_tol=1e-6
            ):
                errors.append(f"line {line_number}: inconsistent snapshot interval")
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
            for name in (*HARD_INTEGRITY_COUNTERS, CADENCE_COUNTER):
                max_drops[name] = max(max_drops[name], int(stats.get(name, 0)))
    if rows == 0:
        errors.append("capture has no feature rows")
    for workload, count in workloads.items():
        if count < minimum_rows_per_workload:
            errors.append(f"{workload}: only {count} rows, need {minimum_rows_per_workload}")
    for name in HARD_INTEGRITY_COUNTERS:
        if max_drops[name] != 0:
            errors.append(f"collector loss: {name}={max_drops[name]}")

    short_intervals = []
    delayed_intervals = []
    estimated_missing_snapshots = 0
    for interval in snapshot_intervals.values():
        if interval < interval_min_seconds:
            short_intervals.append(interval)
        elif interval > interval_max_seconds:
            delayed_intervals.append(interval)
            estimated_missing_snapshots += max(
                1, int(round(interval / nominal_interval_seconds)) - 1
            )
    if short_intervals:
        errors.append(
            f"telemetry cadence: {len(short_intervals)} intervals below "
            f"{interval_min_seconds:.6f}s"
        )
    if delayed_intervals and max(delayed_intervals) > maximum_single_gap_seconds:
        errors.append(
            f"telemetry cadence: maximum gap {max(delayed_intervals):.6f}s exceeds "
            f"{maximum_single_gap_seconds:.6f}s"
        )
    observed_snapshots = len(snapshot_intervals)
    expected_snapshots = observed_snapshots + estimated_missing_snapshots
    telemetry_availability = (
        observed_snapshots / expected_snapshots if expected_snapshots else 0.0
    )
    if telemetry_availability < minimum_telemetry_availability:
        errors.append(
            f"telemetry availability {telemetry_availability:.9f} is below "
            f"{minimum_telemetry_availability:.9f}"
        )
    reported_cadence_violations = max_drops[CADENCE_COUNTER]
    observed_cadence_violations = len(short_intervals) + len(delayed_intervals)
    if reported_cadence_violations != observed_cadence_violations:
        errors.append(
            "capture interval counter mismatch: "
            f"reported={reported_cadence_violations}, "
            f"observed={observed_cadence_violations}"
        )

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
        "telemetry_availability_contract": {
            "nominal_interval_seconds": nominal_interval_seconds,
            "minimum_availability": minimum_telemetry_availability,
            "maximum_single_gap_seconds": maximum_single_gap_seconds,
        },
        "telemetry_availability": {
            "observed_snapshots": observed_snapshots,
            "estimated_missing_snapshots": estimated_missing_snapshots,
            "availability": telemetry_availability,
            "cadence_violation_events": observed_cadence_violations,
            "short_interval_events": len(short_intervals),
            "delayed_interval_events": len(delayed_intervals),
            "maximum_gap_seconds": max(delayed_intervals, default=0.0),
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
    parser.add_argument("--nominal-interval-seconds", type=float, default=1.0)
    parser.add_argument("--minimum-telemetry-availability", type=float, default=1.0)
    parser.add_argument("--maximum-single-gap-seconds", type=float)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate(
        args.capture,
        args.minimum_rows_per_workload,
        args.interval_min_seconds,
        args.interval_max_seconds,
        args.nominal_interval_seconds,
        args.minimum_telemetry_availability,
        args.maximum_single_gap_seconds,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    raise SystemExit(0 if report["valid"] else 1)


if __name__ == "__main__":
    main()
