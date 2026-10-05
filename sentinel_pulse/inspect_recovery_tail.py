"""Bounded live watchdog for recovery journals; no terminal/PASS authority."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import time

from .inspect_feature_tail import _recent_lines
from .telemetry_recovery import (
    HARD_COUNTERS, REQUIRED_LOADER_COUNTERS, SNAPSHOT_SCHEMA,
    digest, load_profile, validate_profile,
)


def inspect(path: Path, profile: dict, now: float | None = None) -> dict:
    validate_profile(profile)
    now = time.time() if now is None else now
    result = {"schema": "sentinel-pulse-recovery-tail-health-v1",
              "profile_sha256": digest(profile), "valid": False,
              "status": "fatal", "errors": [], "terminal_pass": False}
    errors = result["errors"]
    try:
        # Inspect only the final complete snapshot batch, not an arbitrarily
        # old journal hidden behind a later unbounded stream of feature rows.
        features = []
        journal = None
        for raw in _recent_lines(path):
            row = json.loads(raw)
            if row.get("schema") == SNAPSHOT_SCHEMA:
                journal = row
                break
            if row.get("schema") == "sentinel-pulse-feature-v1":
                features.append(row)
            elif row.get("schema") != "sentinel-pulse-feature-schema-v1":
                raise ValueError("unsupported newest recovery row")
            if len(features) > 4096:
                raise ValueError("unbounded feature batch without recovery journal")
        if journal is None:
            raise ValueError("missing recovery journal")
        state = journal["recovery"]
        if state.get("profile_sha256") != result["profile_sha256"]:
            raise ValueError("recovery profile binding mismatch")
        if state.get("status") not in {"ready", "warming", "quarantined"}:
            raise ValueError("fatal or invalid recorded recovery state")
        stats = journal["collector_stats"]
        if any(key not in stats for key in REQUIRED_LOADER_COUNTERS):
            raise ValueError("missing loader integrity counters")
        if any(type(stats.get(key, 0)) is not int or stats.get(key, 0) != 0 for key in HARD_COUNTERS):
            raise ValueError("hard integrity failure")
        end, received = float(journal["observed_at"]), float(journal["received_at"])
        age = float(now) - end
        if not all(math.isfinite(v) for v in (end, received, age)) or age < -1:
            raise ValueError("invalid recovery clock/age")
        if age > profile["maximum_recoverable_gap_seconds"]:
            raise ValueError("stream stalled beyond registered recovery gap budget")
        for field, upper in (("incidents", profile["maximum_incidents"]),
                             ("excluded_seconds", profile["maximum_excluded_seconds"]),
                             ("maximum_snapshot_gap_seconds", profile["maximum_recoverable_gap_seconds"])):
            value = float(state[field])
            if not math.isfinite(value) or not 0 <= value <= upper:
                raise ValueError("recorded recovery budget exceeded: " + field)
        incident_start = state.get("incident_start")
        if incident_start is not None and float(now) - float(incident_start) > profile["maximum_incident_seconds"]:
            raise ValueError("incident recovery timeout")
        for row in features:
            meta = row["telemetry_recovery"]
            if (meta.get("profile_sha256") != result["profile_sha256"]
                    or meta.get("snapshot_sequence") != state["sequence"]
                    or meta.get("epoch") != state["epoch"]
                    or float(row["window_end"]) != end
                    or row.get("collector_stats") != stats):
                raise ValueError("tail feature/journal binding mismatch")
        result.update(valid=True, status="telemetry-degraded" if age > profile["interval_max_seconds"] else state["status"],
                      snapshot_age_seconds=age, recovery=state,
                      availability_floor_evaluated=False)
    except (ValueError, KeyError, TypeError, OSError, OverflowError) as error:
        errors.append(str(error))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--recovery-profile", type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.capture, load_profile(args.recovery_profile))
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
