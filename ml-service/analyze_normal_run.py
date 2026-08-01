"""Validate a no-attack telemetry run with per-workload score statistics."""

import argparse
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path


TARGETS = ("default/postgres", "production/nginx", "production/redis")


def sensor_snapshot_healthy(health):
    """Return true only for an uninterrupted, fully covered sensor snapshot."""
    if not isinstance(health, dict):
        return False
    active = health.get("active_tetragon_pods", [])
    expected = health.get("expected_tetragon_pods")
    return bool(
        health.get("require_full_coverage")
        and health.get("coverage_healthy") is True
        and isinstance(expected, int) and expected > 0
        and len(active) == expected
        and int(health.get("backpressure_events", 0)) == 0
        and int(health.get("membership_failures", 0)) == 0
        and int(health.get("coverage_failures", 0)) == 0
        and int(health.get("stream_failures", 0)) == 0
    )


def percentile(values, q):
    values = sorted(values)
    position = (len(values) - 1) * q
    low = int(position)
    high = min(low + 1, len(values) - 1)
    return values[low] + (values[high] - values[low]) * (position - low)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("metrics")
    parser.add_argument("--minimum-windows", type=int, default=10)
    parser.add_argument("--minimum-events", type=int, default=100)
    parser.add_argument("--threshold", type=float, default=0.80)
    parser.add_argument("--max-score-exceedances", type=int, default=0,
                        help="Maximum raw model threshold crossings per workload")
    parser.add_argument("--max-behavior-gates", type=int, default=0,
                        help="Maximum workload-conditioned behavior crossings")
    parser.add_argument("--require-healthy-sensors", action="store_true",
                        help="Require at least one clean runtime-health sample")
    parser.add_argument("--since-ts", type=float, default=None,
                        help="Only include telemetry at or after this Unix timestamp")
    parser.add_argument("--until-ts", type=float, default=None,
                        help="Only include telemetry at or before this Unix timestamp")
    parser.add_argument("--output")
    args = parser.parse_args()

    rows = []
    for line in Path(args.metrics).read_text().splitlines():
        try:
            row = json.loads(line)
            timestamp = float(row.get("ts", 0.0))
            if args.since_ts is not None and timestamp < args.since_ts:
                continue
            if args.until_ts is not None and timestamp > args.until_ts:
                continue
            rows.append(row)
        except (ValueError, TypeError):
            continue
    detections = [row for row in rows if row.get("kind") == "detection"]
    health_rows = [
        row for row in rows if row.get("kind") == "runtime_health"
    ]
    sensors_healthy = bool(health_rows) and all(
        sensor_snapshot_healthy(row.get("sensor_health"))
        for row in health_rows
    )
    grouped = defaultdict(list)
    for row in rows:
        if row.get("kind") != "inference":
            continue
        if int(row.get("event_count", args.minimum_events)) < args.minimum_events:
            continue
        grouped[row.get("model_key")].append(row)

    report = {
        "metrics": str(Path(args.metrics).resolve()),
        "since_ts": args.since_ts,
        "until_ts": args.until_ts,
        "observed_ts_min": min(
            (float(row["ts"]) for row in rows if row.get("ts") is not None),
            default=None,
        ),
        "observed_ts_max": max(
            (float(row["ts"]) for row in rows if row.get("ts") is not None),
            default=None,
        ),
        "detections": len(detections),
        "decision_counts": dict(Counter(
            row.get("decision") for row in rows if row.get("kind") == "decision"
        )),
        "sensor_health": {
            "required": args.require_healthy_sensors,
            "samples": len(health_rows),
            "healthy": sensors_healthy,
            "latest": health_rows[-1].get("sensor_health") if health_rows else None,
        },
        "models": {},
    }
    passed = not detections and (
        sensors_healthy or not args.require_healthy_sensors
    )
    for model_key in TARGETS:
        model_rows = grouped[model_key]
        scores = [float(row["score"]) for row in model_rows]
        timings = [float(row["inference_ms"]) for row in model_rows]
        ingest_lags = [
            float(row["ingest_lag_seconds"]) for row in model_rows
            if row.get("ingest_lag_seconds") is not None
        ]
        event_counts = [int(row.get("event_count", 0)) for row in model_rows]
        actionable = [
            float(row["score"]) >= args.threshold
            and bool(row.get(
                "behavior_gate",
                float(row.get("suspicious_mass", 0.0)) >= 0.10,
            ))
            for row in model_rows
        ]
        behavior_gates = sum(bool(row.get(
            "behavior_gate",
            float(row.get("suspicious_mass", 0.0)) >= 0.10,
        )) for row in model_rows)
        consecutive = sum(a and b for a, b in zip(actionable, actionable[1:]))
        enough = len(scores) >= args.minimum_windows
        exceedances = sum(x >= args.threshold for x in scores)
        passed = (
            passed and enough and consecutive == 0
            and exceedances <= args.max_score_exceedances
            and behavior_gates <= args.max_behavior_gates
        )
        report["models"][model_key] = {
            "windows": len(scores),
            "enough_windows": enough,
            "score_median": statistics.median(scores) if scores else None,
            "score_p95": percentile(scores, 0.95) if scores else None,
            "score_p99": percentile(scores, 0.99) if scores else None,
            "score_max": max(scores) if scores else None,
            "score_only_exceedances": exceedances,
            "behavior_gate_exceedances": behavior_gates,
            "behavior_max_ratio": max(
                (float(row.get("behavior_max_ratio", 0.0)) for row in model_rows),
                default=None,
            ),
            "actionable_consecutive_pairs": consecutive,
            "inference_median_ms": statistics.median(timings) if timings else None,
            "inference_p95_ms": percentile(timings, 0.95) if timings else None,
            "inference_p99_ms": percentile(timings, 0.99) if timings else None,
            "ingest_lag_median_seconds": (
                statistics.median(ingest_lags) if ingest_lags else None
            ),
            "ingest_lag_p95_seconds": (
                percentile(ingest_lags, 0.95) if ingest_lags else None
            ),
            "ingest_lag_p99_seconds": (
                percentile(ingest_lags, 0.99) if ingest_lags else None
            ),
            "ingest_lag_max_seconds": max(ingest_lags) if ingest_lags else None,
            "event_count_min": min(event_counts) if event_counts else None,
            "event_count_median": (
                statistics.median(event_counts) if event_counts else None
            ),
            "event_count_p95": (
                percentile(event_counts, 0.95) if event_counts else None
            ),
            "event_count_max": max(event_counts) if event_counts else None,
        }
    report["passed"] = passed
    report["gate"] = {
        "minimum_windows_per_workload": args.minimum_windows,
        "minimum_events_per_window": args.minimum_events,
        "threshold": args.threshold,
        "max_score_exceedances_per_workload": args.max_score_exceedances,
        "max_behavior_gates_per_workload": args.max_behavior_gates,
        "max_actionable_consecutive_pairs": 0,
        "max_detections": 0,
        "require_healthy_sensors": args.require_healthy_sensors,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output:
        Path(args.output).write_text(rendered)
    return 0 if passed else 5


if __name__ == "__main__":
    raise SystemExit(main())
