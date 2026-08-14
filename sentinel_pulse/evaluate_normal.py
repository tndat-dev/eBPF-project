"""Evaluate an independent normal soak without tuning the frozen candidate."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import math
from pathlib import Path

from .integrity import sha256_file


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if trials <= 0:
        return 0.0, 1.0
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (proportion + z * z / (2.0 * trials)) / denominator
    margin = z * math.sqrt(
        proportion * (1.0 - proportion) / trials + z * z / (4.0 * trials * trials)
    ) / denominator
    lower = 0.0 if successes == 0 else max(0.0, centre - margin)
    upper = 1.0 if successes == trials else min(1.0, centre + margin)
    return lower, upper


def evaluate(
    path: Path,
    maximum_alerts: int = 0,
    minimum_scored_windows: int = 86400,
    minimum_duration_hours: float = 24.0,
    minimum_coverage_ratio: float = 0.95,
) -> dict:
    if not 0.0 < minimum_coverage_ratio <= 1.0:
        raise ValueError("minimum coverage ratio must be in (0, 1]")
    statuses = Counter()
    workload_scored = Counter()
    workload_alerts = Counter()
    workload_bounds: dict[str, list[float]] = {}
    workload_second_buckets: dict[str, set[int]] = {}
    model_identities = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"line {line_number}: invalid JSON: {error}") from error
            status = str(record.get("status", "unknown"))
            statuses[status] += 1
            if record.get("schema") != "sentinel-pulse-decision-v1":
                continue
            model_identities.add(str(record.get("model_manifest_sha256", "")))
            workload = str(record.get("workload_key", "unknown"))
            workload_scored[workload] += 1
            if "window_end" in record:
                end = float(record["window_end"])
                bounds = workload_bounds.setdefault(workload, [end, end])
                bounds[0] = min(bounds[0], end)
                bounds[1] = max(bounds[1], end)
                workload_second_buckets.setdefault(workload, set()).add(math.floor(end))
            if status == "alert":
                workload_alerts[workload] += 1

    scored = statuses["normal"] + statuses["alert"]
    alerts = statuses["alert"]
    lower, upper = wilson_interval(alerts, scored)
    workload_reports = {}
    for workload, count in sorted(workload_scored.items()):
        workload_count_alerts = workload_alerts[workload]
        workload_lower, workload_upper = wilson_interval(workload_count_alerts, count)
        bounds = workload_bounds.get(workload)
        duration_hours = (bounds[1] - bounds[0]) / 3600.0 if bounds else 0.0
        buckets = workload_second_buckets.get(workload, set())
        span_seconds = (
            math.floor(bounds[1]) - math.floor(bounds[0]) + 1 if bounds else 0
        )
        coverage_seconds = len(buckets)
        coverage_ratio = coverage_seconds / span_seconds if span_seconds else 0.0
        workload_reports[workload] = {
            "scored_windows": count,
            "alerts": workload_count_alerts,
            "observed_false_alert_rate": workload_count_alerts / count,
            "false_alert_rate_wilson_95": [workload_lower, workload_upper],
            "observed_duration_hours": duration_hours,
            "duration_gate": duration_hours >= minimum_duration_hours,
            "observed_second_buckets": coverage_seconds,
            "span_seconds": span_seconds,
            "coverage_ratio": coverage_ratio,
            "coverage_gate": (
                coverage_seconds >= minimum_duration_hours * 3600.0 * minimum_coverage_ratio
                and coverage_ratio >= minimum_coverage_ratio
            ),
        }
    duration_gate = bool(workload_reports) and all(
        item["duration_gate"] for item in workload_reports.values()
    )
    coverage_gate = bool(workload_reports) and all(
        item["coverage_gate"] for item in workload_reports.values()
    )
    model_identity_gate = (
        len(model_identities) == 1
        and len(next(iter(model_identities))) == 64
        and all(character in "0123456789abcdef" for character in next(iter(model_identities)))
    )
    model_manifest_sha256 = next(iter(model_identities)) if model_identity_gate else None
    return {
        "schema": "sentinel-pulse-normal-soak-report-v1",
        "path": str(path),
        "decisions_sha256": sha256_file(path),
        "minimum_scored_windows": minimum_scored_windows,
        "minimum_duration_hours_per_workload": minimum_duration_hours,
        "minimum_coverage_ratio_per_workload": minimum_coverage_ratio,
        "maximum_alerts": maximum_alerts,
        "scored_windows": scored,
        "alerts": alerts,
        "observed_false_alert_rate": alerts / scored if scored else None,
        "false_alert_rate_wilson_95": [lower, upper],
        "statuses": dict(sorted(statuses.items())),
        "model_manifest_sha256": model_manifest_sha256,
        "model_identity_gate": model_identity_gate,
        "workloads": workload_reports,
        "duration_gate": duration_gate,
        "coverage_gate": coverage_gate,
        "normal_gate": (
            scored >= minimum_scored_windows
            and alerts <= maximum_alerts
            and duration_gate
            and coverage_gate
            and model_identity_gate
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--maximum-alerts", type=int, default=0)
    parser.add_argument("--minimum-scored-windows", type=int, default=86400)
    parser.add_argument("--minimum-duration-hours", type=float, default=24.0)
    parser.add_argument("--minimum-coverage-ratio", type=float, default=0.95)
    args = parser.parse_args()
    report = evaluate(
        args.decisions,
        args.maximum_alerts,
        args.minimum_scored_windows,
        args.minimum_duration_hours,
        args.minimum_coverage_ratio,
    )
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    raise SystemExit(0 if report["normal_gate"] else 1)


if __name__ == "__main__":
    main()
