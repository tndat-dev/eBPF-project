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


DROP_COUNTERS = (
    "count_insert_fail",
    "transition_insert_fail",
    "task_state_update_fail",
    "snapshot_consistency_retry_exhausted",
    "snapshot_total_mismatch",
    "target_snapshot_gap",
)


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
) -> dict:
    if maximum_age_seconds <= 0:
        raise ValueError("maximum feature age must be positive")
    if interval_min_seconds <= 0 or interval_max_seconds <= interval_min_seconds:
        raise ValueError("invalid capture interval bounds")

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
    interval = end - start
    if not interval_min_seconds <= interval <= interval_max_seconds:
        errors.append(f"invalid latest interval {interval:.6f}s")
    age = (time.time() if observed_at is None else observed_at) - emitted
    if not math.isfinite(age) or age < -1.0 or age > maximum_age_seconds:
        errors.append(f"latest feature age is invalid: {age:.6f}s")

    stats = newest.get("collector_stats", {})
    if not isinstance(stats, dict):
        errors.append("collector_stats is not an object")
        stats = {}
    drops = {}
    for name in DROP_COUNTERS:
        try:
            value = int(stats.get(name, 0))
        except (TypeError, ValueError):
            errors.append(f"invalid collector counter: {name}")
            continue
        drops[name] = value
        if value != 0:
            errors.append(f"collector loss: {name}={value}")

    return {
        "schema": "sentinel-pulse-feature-tail-health-v1",
        "valid": not errors,
        "path": str(path),
        "workload_key": newest.get("workload_key"),
        "window_end": end,
        "interval_seconds": interval,
        "feature_age_seconds": age,
        "collector_max_drops": drops,
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--maximum-age-seconds", type=float, default=5.0)
    parser.add_argument("--interval-min-seconds", type=float, default=0.35)
    parser.add_argument("--interval-max-seconds", type=float, default=0.80)
    args = parser.parse_args()
    result = inspect(
        args.capture,
        maximum_age_seconds=args.maximum_age_seconds,
        interval_min_seconds=args.interval_min_seconds,
        interval_max_seconds=args.interval_max_seconds,
    )
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    raise SystemExit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
