"""Opt-in, replayable telemetry quarantine; never converts missing data to normal.

This contract is deliberately separate from the legacy formal telemetry gate.
Availability is evaluated at the end, not waived when an incident recovers.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

PROFILE_SCHEMA = "sentinel-pulse-telemetry-recovery-profile-v1"
SNAPSHOT_SCHEMA = "sentinel-pulse-recovery-snapshot-v1"
HARD_COUNTERS = (
    "count_insert_fail", "transition_insert_fail", "task_state_update_fail",
    "snapshot_consistency_retry_exhausted", "snapshot_projection_fail",
    "snapshot_total_mismatch", "target_snapshot_gap",
)
REQUIRED_LOADER_COUNTERS = (
    "task_state_update_fail", "snapshot_consistency_retry_exhausted",
    "snapshot_projection_fail",
)


def digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def validate_profile(profile: dict) -> dict:
    expected = {
        "schema", "nominal_interval_seconds", "interval_min_seconds",
        "interval_max_seconds", "maximum_recoverable_gap_seconds",
        "maximum_ingest_lag_seconds", "maximum_incident_seconds",
        "maximum_incidents", "maximum_excluded_seconds", "rolling_windows",
        "minimum_telemetry_availability", "maximum_wall_seconds",
        "minimum_scored_hours_per_workload", "automatic_promotion",
        "automatic_blind_evaluation",
    }
    if set(profile) != expected or profile.get("schema") != PROFILE_SCHEMA:
        raise ValueError("unsupported or incomplete recovery profile")
    for key in expected - {"schema", "automatic_promotion", "automatic_blind_evaluation"}:
        value = profile[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"invalid recovery field: {key}")
    if not (profile["interval_min_seconds"] < profile["nominal_interval_seconds"]
            < profile["interval_max_seconds"] < profile["maximum_recoverable_gap_seconds"]
            <= profile["maximum_incident_seconds"] <= profile["maximum_excluded_seconds"]):
        raise ValueError("invalid recovery interval/budget ordering")
    if not (.999 <= profile["minimum_telemetry_availability"] <= 1
            and profile["maximum_recoverable_gap_seconds"] <= 30
            and profile["maximum_incident_seconds"] <= 120
            and profile["maximum_excluded_seconds"] <= 900
            and profile["maximum_ingest_lag_seconds"] <= 1
            and profile["minimum_scored_hours_per_workload"] >= 24
            and 86400 <= profile["maximum_wall_seconds"] <= 90000):
        raise ValueError("recovery profile exceeds operational safety bounds")
    if any(type(profile[key]) is not int for key in ("rolling_windows", "maximum_incidents")):
        raise ValueError("recovery counts must be integers")
    if profile["rolling_windows"] != 10 or profile["maximum_incidents"] > 12:
        raise ValueError("unsupported rolling history or incident budget")
    if (profile["automatic_promotion"] is not False
            or profile["automatic_blind_evaluation"] is not False):
        raise ValueError("recovery must not open blind/promotion interlocks")
    return profile


def load_profile(path: Path) -> dict:
    return validate_profile(json.loads(path.read_text(encoding="utf-8")))


class RecoveryTracker:
    """One node's snapshot stream, including snapshots with no feature rows.

    Each step is reproduced by the detector and terminal validator. The input
    is retained in the capture, so an operator cannot omit a gap by relabeling
    a feature. Hard errors are sticky and never recoverable.
    """
    def __init__(self, profile: dict):
        self.profile = validate_profile(dict(profile))
        self.profile_sha256 = digest(self.profile)
        self.previous_end = None
        self.previous_received = None
        self.first_end = None
        self.sequence = 0
        self.epoch = 0
        self.clean_windows = 0
        self.incidents = 0
        self.incident_start = None
        self.excluded_seconds = 0.0
        self.missing = 0
        self.max_gap = 0.0
        self.hard_max = {name: 0 for name in HARD_COUNTERS}
        self.errors = []

    def step(self, observed_at: float, received_at: float, stats: dict,
             snapshot_read_seconds: float = 0.0) -> dict:
        p = self.profile
        end, received, read = map(float, (observed_at, received_at, snapshot_read_seconds))
        if not all(math.isfinite(v) for v in (end, received, read)) or read < 0:
            raise ValueError("non-finite or negative recovery timestamps")
        if not isinstance(stats, dict):
            raise ValueError("recovery collector stats must be an object")
        for key in REQUIRED_LOADER_COUNTERS:
            if key not in stats:
                self.errors.append(f"missing loader integrity counter: {key}")
        for key in HARD_COUNTERS:
            value = stats.get(key, 0)
            if type(value) is not int or value < 0:
                raise ValueError(f"invalid integrity counter: {key}")
            if value < self.hard_max[key]:
                self.errors.append(f"integrity counter regressed: {key}")
            self.hard_max[key] = max(self.hard_max[key], value)
            if value:
                self.errors.append(f"hard integrity failure: {key}={value}")
        interval = None if self.previous_end is None else end - self.previous_end
        if interval is not None and interval <= 0:
            raise ValueError("non-monotonic recovery snapshot timestamp")
        if self.previous_received is not None and received < self.previous_received:
            raise ValueError("capture receive clock moved backwards")
        lag = received - end
        if lag < -1:
            self.errors.append("capture clock precedes snapshot clock")
        if lag > p["maximum_incident_seconds"]:
            self.errors.append("ingest backlog exceeds recovery timeout")
        if self.first_end is None:
            self.first_end = end
        if end - self.first_end > p["maximum_wall_seconds"]:
            self.errors.append("registered wall time exhausted")
        bad_cadence = interval is not None and not (
            p["interval_min_seconds"] <= interval <= p["interval_max_seconds"])
        bad_lag = lag > p["maximum_ingest_lag_seconds"]
        if interval is not None:
            self.max_gap = max(self.max_gap, interval)
            if interval > p["interval_max_seconds"]:
                self.missing += max(1, round(interval / p["nominal_interval_seconds"]) - 1)
            if interval > p["maximum_recoverable_gap_seconds"]:
                self.errors.append("single gap exceeds recovery budget")
        bad = bad_cadence or bad_lag
        reset = False
        if bad:
            if self.incident_start is None:
                self.incident_start = self.previous_end if self.previous_end is not None else end
                self.incidents += 1
            # Every invalid snapshot starts a new baseline. Consecutive bad
            # snapshots belong to one incident but cannot reuse any history.
            self.epoch += 1
            self.clean_windows = 0
            reset = True
        elif interval is not None:
            self.clean_windows += 1
        if self.incident_start is not None:
            self.excluded_seconds += interval or 0.0
            if end - self.incident_start > p["maximum_incident_seconds"]:
                self.errors.append("incident recovery timeout")
        if self.incidents > p["maximum_incidents"]:
            self.errors.append("incident count budget exhausted")
        if self.excluded_seconds > p["maximum_excluded_seconds"]:
            self.errors.append("excluded time budget exhausted")
        ready = not bad and self.clean_windows > p["rolling_windows"]
        if ready:
            self.incident_start = None
        self.errors = list(dict.fromkeys(self.errors))
        status = ("fatal" if self.errors else "quarantined" if bad else
                  "ready" if ready else "warming")
        self.sequence += 1
        self.previous_end, self.previous_received = end, received
        return {
            "profile_sha256": self.profile_sha256, "sequence": self.sequence,
            "epoch": self.epoch, "status": status, "reset_required": reset,
            "can_score": status == "ready", "clean_windows": self.clean_windows,
            "incidents": self.incidents, "incident_start": self.incident_start,
            "excluded_seconds": self.excluded_seconds,
            "estimated_missing_snapshots": self.missing,
            "availability": self.sequence / (self.sequence + self.missing),
            "maximum_snapshot_gap_seconds": self.max_gap,
            "reasons": self.errors or (["cadence"] if bad_cadence else
                                       ["ingest_lag"] if bad_lag else []),
        }

    def replay(self, record: dict) -> dict:
        if record.get("schema") != SNAPSHOT_SCHEMA:
            raise ValueError("unsupported recovery snapshot schema")
        state = self.step(record["observed_at"], record["received_at"],
                          record["collector_stats"], record["snapshot_read_seconds"])
        if state != record.get("recovery"):
            raise ValueError("recovery journal differs from independent replay")
        return state


def feature_eligibility(state: dict, profile: dict, history_before: int,
                        start: float, end: float, emitted: float) -> tuple[bool, str]:
    if not all(math.isfinite(v) for v in (start, end, emitted)):
        raise ValueError("non-finite recovery feature timestamps")
    if not profile["interval_min_seconds"] <= end - start <= profile["interval_max_seconds"]:
        return False, "source_cadence"
    if emitted - end > profile["maximum_ingest_lag_seconds"] or emitted < end - 1:
        return False, "feature_ingest_lag"
    if not state["can_score"]:
        return False, "snapshot_" + state["status"]
    if history_before < profile["rolling_windows"]:
        return False, "rolling_history_fill"
    return True, "ready"
