"""Independent journal/rolling-feature replay for opt-in recovery captures.

Never emits legacy NORMAL_PASS or an operational soak PASS. All raw invalid
intervals remain visible; terminal availability includes their missing time.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
import json
import math
from pathlib import Path
import zlib

import numpy as np

from .encoding import decode_vector, schema_digest
from .features import PulseFeatureBuilder, TRACKED_SYSCALLS
from .integrity import sha256_file
from .telemetry_recovery import RecoveryTracker, SNAPSHOT_SCHEMA, feature_eligibility, load_profile


def validate(path: Path, profile: dict) -> dict:
    tracker = RecoveryTracker(profile)
    columns = list(PulseFeatureBuilder(rolling_windows=profile["rolling_windows"]).columns)
    expected_schema = schema_digest(columns)
    declared_schema = False
    state = None
    journal_stats = None
    histories, last_end = {}, {}
    workloads, eligible_rows, status_rows = Counter(), Counter(), Counter()
    errors, rows, journal_rows = [], 0, 0
    names = tuple(TRACKED_SYSCALLS.values())
    mean_indices = [columns.index("rolling_mean:" + name) for name in names]
    std_indices = [columns.index("rolling_std:" + name) for name in names]
    # Raw interval union, not row count * nominal cadence (replicas overlap).
    exposure, last_intervals = Counter(), {}
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            try:
                row = json.loads(line)
                schema = row.get("schema")
                if schema == SNAPSHOT_SCHEMA:
                    if state is not None and state["reset_required"]:
                        histories.clear()
                    state = tracker.replay(row)
                    journal_stats = row["collector_stats"]
                    journal_rows += 1
                    if state["status"] == "fatal":
                        errors.extend(state["reasons"])
                    continue
                if schema == "sentinel-pulse-feature-schema-v1":
                    if row.get("columns") != columns or row.get("feature_schema_sha256") != expected_schema:
                        raise ValueError("feature schema drift")
                    declared_schema = True
                    continue
                if schema != "sentinel-pulse-feature-v1" or not declared_schema:
                    raise ValueError("unsupported row or feature precedes schema")
                if state is None:
                    raise ValueError("feature precedes recovery journal")
                rows += 1
                meta = row["telemetry_recovery"]
                if (meta.get("profile_sha256") != tracker.profile_sha256
                        or meta.get("snapshot_sequence") != state["sequence"]
                        or meta.get("epoch") != state["epoch"]
                        or row.get("feature_schema_sha256") != expected_schema):
                    raise ValueError("feature/journal binding mismatch")
                start, end, emitted = map(float, (row["window_start"], row["window_end"], row["emitted_at"]))
                if end != tracker.previous_end or not all(math.isfinite(v) for v in (start, end, emitted)) or start >= end:
                    raise ValueError("invalid feature timestamps")
                if row.get("collector_stats") != journal_stats:
                    raise ValueError("feature integrity stats differ from journal")
                # Check cumulative hard counters on every feature too: a
                # forged clean journal must not mask loss in a workload row.
                stats = row.get("collector_stats", {})
                for name, maximum in tracker.hard_max.items():
                    if stats.get(name, 0) != maximum:
                        raise ValueError("feature integrity counters differ from journal")
                workload = row["workload_key"]
                if not isinstance(workload, str) or not workload:
                    raise ValueError("missing workload identity")
                identity = (row["node_name"], row["pod_uid"], row["container_name"], str(row["cgroup_id"]))
                if any(value is None or value == "" for value in identity):
                    raise ValueError("incomplete source identity")
                if end <= last_end.get(identity, -math.inf):
                    raise ValueError("non-monotonic feature timestamp")
                last_end[identity] = end
                counts = row["exact_counts"]
                if (not isinstance(counts, dict) or set(counts) != set(names) | {"other"}
                        or any(type(v) is not int or v < 0 for v in counts.values())
                        or sum(counts.values()) != row["exact_total"]):
                    raise ValueError("invalid exact syscall counts")
                vector = decode_vector(row)
                if len(vector) != len(columns) or not np.all(np.isfinite(vector)):
                    raise ValueError("invalid feature vector")
                history = histories.setdefault(identity, deque(maxlen=profile["rolling_windows"]))
                history_before = len(history)
                if type(meta.get("rolling_history_before")) is not int or meta["rolling_history_before"] != history_before:
                    raise ValueError("rolling history length differs from independent replay")
                eligible, reason = feature_eligibility(state, profile, history_before, start, end, emitted)
                if type(meta.get("eligible")) is not bool or (meta["eligible"], meta.get("reason")) != (eligible, reason):
                    raise ValueError("quarantine eligibility differs from replay")
                rates = np.asarray([counts[name] for name in names], dtype=np.float64) / (end - start)
                previous_rates = np.vstack(history) if history else rates.reshape(1, -1)
                if not (np.allclose(vector[mean_indices], np.log1p(previous_rates.mean(axis=0)), atol=1e-6, rtol=1e-6)
                        and np.allclose(vector[std_indices], np.log1p(previous_rates.std(axis=0)), atol=1e-6, rtol=1e-6)):
                    raise ValueError("rolling mean/std differs from independent rates")
                workloads[workload] += 1
                status_rows[reason] += 1
                if eligible:
                    eligible_rows[workload] += 1
                    previous_start, previous_finish = last_intervals.get(workload, (start, start))
                    if start < previous_start:
                        raise ValueError("out-of-order workload exposure")
                    exposure[workload] += max(0.0, end - max(start, previous_finish))
                    last_intervals[workload] = (start, max(end, previous_finish))
                if state["reset_required"] or reason in {"source_cadence", "feature_ingest_lag"}:
                    history.clear()
                else:
                    history.append(rates)
            except (ValueError, KeyError, TypeError, OverflowError, zlib.error) as error:
                errors.append(f"line {line_number}: {error}")
                # Without a trustworthy journal prefix, later recovery labels
                # cannot be accepted. Stop instead of skipping evidence.
                break
    if not journal_rows or not rows:
        errors.append("capture has no recovery journal/features")
    if tracker.incident_start is not None:
        errors.append("capture ended during an unrecovered telemetry incident")
    integrity_valid = not errors
    availability = tracker.sequence / (tracker.sequence + tracker.missing) if tracker.sequence else 0.0
    availability_valid = availability >= profile["minimum_telemetry_availability"]
    if not availability_valid:
        errors.append("terminal telemetry availability below registered floor")
    return {
        "schema": "sentinel-pulse-recovery-capture-validation-v1",
        "valid": not errors, "integrity_valid": integrity_valid,
        "availability_valid": availability_valid,
        "capture_sha256": sha256_file(path), "profile_sha256": tracker.profile_sha256,
        "journal_rows": journal_rows, "feature_rows": rows,
        "workloads": dict(workloads), "eligible_feature_rows": dict(eligible_rows),
        "feature_states": dict(status_rows),
        "eligible_feature_exposure_seconds": dict(exposure),
        "observed_snapshots": tracker.sequence,
        "estimated_missing_snapshots": tracker.missing,
        "availability": availability, "maximum_gap_seconds": tracker.max_gap,
        "incidents": tracker.incidents, "excluded_seconds": tracker.excluded_seconds,
        "hard_integrity_counters": tracker.hard_max, "errors": errors[:200],
        "legacy_normal_pass": False, "operational_soak_pass": False,
        "automatic_promotion": False, "automatic_blind_evaluation": False,
        "exposure_note": "feature-eligible exposure only; model warming and health exclusions still require decision/health evaluation",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--recovery-profile", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("refusing to overwrite recovery validation report")
    report = validate(args.capture, load_profile(args.recovery_profile))
    with args.output.open("x", encoding="utf-8") as target:
        target.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    raise SystemExit(0 if report["valid"] else 1)


if __name__ == "__main__":
    main()
