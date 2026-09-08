"""Cheap fail-closed health check for an active Pulse feature stream.

Formal capture validation still scans the complete immutable stream.  This
module only inspects the newest feature row so the lifecycle monitor can stop
an already-invalid run shortly after a cumulative collector integrity counter
becomes non-zero, instead of discovering it hours later at finalization.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import time


HARD_INTEGRITY_COUNTERS = (
    "count_insert_fail",
    "transition_insert_fail",
    "task_state_update_fail",
    "snapshot_consistency_retry_exhausted",
    "snapshot_total_mismatch",
    "target_snapshot_gap",
)

CADENCE_COUNTER = "capture_interval_violation"


def _recent_lines(path: Path, chunk_size: int = 64 * 1024):
    """Yield non-empty lines from the end without loading a long capture."""

    with path.open("rb") as source:
        source.seek(0, 2)
        position = source.tell()
        discard_newest_fragment = False
        if position:
            source.seek(position - 1)
            discard_newest_fragment = source.read(1) not in {b"\n", b"\r"}
        pending = b""
        while position:
            size = min(position, chunk_size)
            position -= size
            source.seek(position)
            pending = source.read(size) + pending
            lines = pending.splitlines()
            if position and lines:
                pending = lines.pop(0)
            else:
                pending = b""
            for line in reversed(lines):
                if line.strip():
                    if discard_newest_fragment:
                        discard_newest_fragment = False
                        continue
                    yield line


def inspect(
    path: Path,
    *,
    observed_at: float | None = None,
    maximum_age_seconds: float = 5.0,
    interval_min_seconds: float = 0.35,
    interval_max_seconds: float = 0.80,
    maximum_single_gap_seconds: float | None = None,
    maximum_capture_interval_violations: int | None = None,
    nominal_interval_seconds: float = 0.5,
    minimum_telemetry_availability: float = 1.0,
    maximum_estimated_missing_snapshots: int | None = None,
) -> dict:
    if maximum_age_seconds <= 0:
        raise ValueError("maximum feature age must be positive")
    if interval_min_seconds <= 0 or interval_max_seconds <= interval_min_seconds:
        raise ValueError("invalid capture interval bounds")
    if maximum_single_gap_seconds is None:
        maximum_single_gap_seconds = interval_max_seconds
    if maximum_single_gap_seconds < interval_max_seconds:
        raise ValueError("maximum single gap cannot be below interval maximum")
    if nominal_interval_seconds <= 0:
        raise ValueError("nominal interval must be positive")
    if not 0 < minimum_telemetry_availability <= 1:
        raise ValueError("minimum telemetry availability must be in (0, 1]")
    if (
        maximum_estimated_missing_snapshots is not None
        and maximum_estimated_missing_snapshots < 0
    ):
        raise ValueError("maximum estimated missing snapshots cannot be negative")
    if (
        maximum_capture_interval_violations is not None
        and maximum_capture_interval_violations < 0
    ):
        raise ValueError("maximum capture interval violations cannot be negative")

    newest = None
    for raw in _recent_lines(path):
        try:
            candidate = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            return {
                "schema": "sentinel-pulse-feature-tail-health-v1",
                "valid": False,
                "errors": [f"invalid newest JSON row: {error}"],
            }
        if candidate.get("schema") == "sentinel-pulse-feature-v1":
            newest = candidate
            break
    if newest is None:
        return {
            "schema": "sentinel-pulse-feature-tail-health-v1",
            "valid": False,
            "errors": ["capture has no feature row"],
        }

    errors = []
    try:
        start = float(newest["window_start"])
        end = float(newest["window_end"])
        emitted = float(newest["emitted_at"])
    except (KeyError, TypeError, ValueError) as error:
        return {
            "schema": "sentinel-pulse-feature-tail-health-v1",
            "valid": False,
            "errors": [f"feature timestamps are invalid: {error}"],
        }
    if not all(math.isfinite(value) for value in (start, end, emitted)):
        errors.append("feature timestamps are not finite")
    feature_interval = end - start
    try:
        interval = float(
            newest.get("collector_snapshot_interval_seconds", feature_interval)
        )
    except (TypeError, ValueError):
        interval = math.nan
        errors.append("collector snapshot interval is invalid")
    degraded_interval = interval > interval_max_seconds
    if interval < interval_min_seconds or interval > maximum_single_gap_seconds:
        errors.append(f"invalid latest interval {interval:.6f}s")
    age = (time.time() if observed_at is None else observed_at) - emitted
    if not math.isfinite(age) or age < -1.0 or age > maximum_age_seconds:
        errors.append(f"latest feature age is invalid: {age:.6f}s")

    stats = newest.get("collector_stats", {})
    if not isinstance(stats, dict):
        errors.append("collector_stats is not an object")
        stats = {}
    drops = {}
    for name in HARD_INTEGRITY_COUNTERS:
        try:
            value = int(stats.get(name, 0))
        except (TypeError, ValueError):
            errors.append(f"invalid collector counter: {name}")
            continue
        drops[name] = value
        if value != 0:
            errors.append(f"collector loss: {name}={value}")
    try:
        cadence_violations = int(stats.get(CADENCE_COUNTER, 0))
    except (TypeError, ValueError):
        cadence_violations = -1
        errors.append(f"invalid collector counter: {CADENCE_COUNTER}")
    drops[CADENCE_COUNTER] = cadence_violations
    telemetry_state = newest.get("collector_telemetry_availability")
    availability = None
    maximum_observed_gap = None
    if isinstance(telemetry_state, dict):
        try:
            observed_snapshots = int(telemetry_state["observed_snapshots"])
            estimated_missing = int(
                telemetry_state["estimated_missing_snapshots"]
            )
            maximum_observed_gap = float(
                telemetry_state["maximum_snapshot_interval_seconds"]
            )
            minimum_observed_interval = float(
                telemetry_state["minimum_snapshot_interval_seconds"]
            )
            short_interval_events = int(telemetry_state["short_interval_events"])
            reported_availability = float(telemetry_state["availability"])
            reported_cadence = int(telemetry_state["cadence_violation_events"])
            if observed_snapshots <= 0 or estimated_missing < 0:
                raise ValueError("invalid snapshot counts")
            expected_snapshots = observed_snapshots + estimated_missing
            availability = observed_snapshots / expected_snapshots
            if not math.isclose(
                availability, reported_availability, rel_tol=0.0, abs_tol=1e-12
            ):
                errors.append("collector telemetry availability mismatch")
            if reported_cadence != cadence_violations:
                errors.append("collector telemetry cadence counter mismatch")
            if short_interval_events < 0:
                errors.append("collector short interval count is invalid")
            if minimum_observed_interval < interval_min_seconds:
                errors.append(
                    f"telemetry minimum interval {minimum_observed_interval:.6f}s "
                    f"is below {interval_min_seconds:.6f}s"
                )
            if not math.isfinite(maximum_observed_gap):
                errors.append("collector maximum snapshot interval is not finite")
            elif maximum_observed_gap > maximum_single_gap_seconds:
                errors.append(
                    f"telemetry maximum gap {maximum_observed_gap:.6f}s exceeds "
                    f"{maximum_single_gap_seconds:.6f}s"
                )
            if (
                maximum_estimated_missing_snapshots is not None
                and estimated_missing > maximum_estimated_missing_snapshots
            ):
                errors.append(
                    "telemetry missing-snapshot budget exceeded: "
                    f"estimated={estimated_missing}, "
                    f"maximum={maximum_estimated_missing_snapshots}"
                )
            elif (
                maximum_estimated_missing_snapshots is None
                and availability < minimum_telemetry_availability
            ):
                errors.append(
                    f"telemetry availability {availability:.9f} is below "
                    f"{minimum_telemetry_availability:.9f}"
                )
        except (KeyError, TypeError, ValueError) as error:
            errors.append(f"invalid collector telemetry availability: {error}")
    else:
        # Legacy rows have only a cumulative cadence counter. Preserve the old
        # zero-tolerance behavior unless the caller supplied an explicit count
        # budget. New formal runs use the cumulative availability fields above.
        cadence_budget = (
            0
            if maximum_capture_interval_violations is None
            else maximum_capture_interval_violations
        )
        if cadence_violations > cadence_budget:
            errors.append(
                f"telemetry cadence budget exceeded: {CADENCE_COUNTER}="
                f"{cadence_violations}, maximum={cadence_budget}"
            )
    if (
        telemetry_state is not None
        and maximum_capture_interval_violations is not None
        and cadence_violations > maximum_capture_interval_violations
    ):
        errors.append(
            f"telemetry cadence budget exceeded: {CADENCE_COUNTER}="
            f"{cadence_violations}, maximum={maximum_capture_interval_violations}"
        )

    return {
        "schema": "sentinel-pulse-feature-tail-health-v1",
        "valid": not errors,
        "path": str(path),
        "workload_key": newest.get("workload_key"),
        "window_end": end,
        "interval_seconds": interval,
        "feature_interval_seconds": feature_interval,
        "feature_age_seconds": age,
        "collector_max_drops": drops,
        "telemetry_degraded": degraded_interval or cadence_violations > 0,
        "collector_telemetry_availability": telemetry_state,
        "telemetry_availability_contract": {
            "nominal_interval_seconds": nominal_interval_seconds,
            "minimum_availability": minimum_telemetry_availability,
            "maximum_single_gap_seconds": maximum_single_gap_seconds,
            "maximum_capture_interval_violations": maximum_capture_interval_violations,
            "maximum_estimated_missing_snapshots": (
                maximum_estimated_missing_snapshots
            ),
        },
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--maximum-age-seconds", type=float, default=5.0)
    parser.add_argument("--interval-min-seconds", type=float, default=0.35)
    parser.add_argument("--interval-max-seconds", type=float, default=0.80)
    parser.add_argument("--maximum-single-gap-seconds", type=float)
    parser.add_argument("--maximum-capture-interval-violations", type=int)
    parser.add_argument("--nominal-interval-seconds", type=float, default=0.5)
    parser.add_argument("--minimum-telemetry-availability", type=float, default=1.0)
    parser.add_argument("--maximum-estimated-missing-snapshots", type=int)
    args = parser.parse_args()
    result = inspect(
        args.capture,
        maximum_age_seconds=args.maximum_age_seconds,
        interval_min_seconds=args.interval_min_seconds,
        interval_max_seconds=args.interval_max_seconds,
        maximum_single_gap_seconds=args.maximum_single_gap_seconds,
        maximum_capture_interval_violations=args.maximum_capture_interval_violations,
        nominal_interval_seconds=args.nominal_interval_seconds,
        minimum_telemetry_availability=args.minimum_telemetry_availability,
        maximum_estimated_missing_snapshots=(
            args.maximum_estimated_missing_snapshots
        ),
    )
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    raise SystemExit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
