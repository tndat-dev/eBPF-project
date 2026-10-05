"""Convert the Pulse loader JSON stream into fixed-interval feature JSONL."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys
import time

from .features import PulseFeatureBuilder, PulseSnapshot
from .encoding import compact_record
from .telemetry_recovery import (
    RecoveryTracker, SNAPSHOT_SCHEMA, feature_eligibility, load_profile,
)


class SnapshotAssembler:
    def __init__(self) -> None:
        self.counts = defaultdict(dict)
        self.transitions = defaultdict(dict)
        self.syscall_bins = defaultdict(dict)
        self.transition_bins = defaultdict(dict)
        self.stats = {}
        self.compact = []

    def add(self, record: dict) -> None:
        kind = record.get("type")
        cgroup_id = int(record.get("cgroup_id", 0))
        if kind == "cgroup_snapshot":
            syscall_bins = record.get("syscall_bins", [])
            transition_bins = record.get("transition_bins", [])
            if (
                len(syscall_bins) != 64
                or len(transition_bins) != 64
                or sum(int(value) for value in syscall_bins) != int(record.get("total", -1))
            ):
                self.stats["snapshot_total_mismatch"] = self.stats.get("snapshot_total_mismatch", 0) + 1
            self.compact.append(record)
        elif kind == "count":
            self.counts[cgroup_id][int(record["syscall_id"])] = int(record["cumulative"])
        elif kind == "transition":
            if "bin" in record:
                self.transition_bins[cgroup_id][int(record["bin"])] = int(record["cumulative"])
            else:
                key = (int(record["previous_id"]), int(record["current_id"]))
                self.transitions[cgroup_id][key] = int(record["cumulative"])
        elif kind == "syscall_bin":
            self.syscall_bins[cgroup_id][int(record["bin"])] = int(record["cumulative"])
        elif kind == "stat":
            self.stats[str(record["name"])] = int(record["cumulative"])

    def snapshots(self, observed_at: float) -> tuple[list[PulseSnapshot], dict]:
        ids = set(self.counts) | set(self.transitions) | set(self.syscall_bins) | set(self.transition_bins)
        result = [
            PulseSnapshot(
                cgroup_id=value,
                observed_at=observed_at,
                counts=dict(self.counts.get(value, {})),
                transitions=dict(self.transitions.get(value, {})),
                syscall_bins=dict(self.syscall_bins.get(value, {})),
                transition_bins=dict(self.transition_bins.get(value, {})),
            )
            for value in ids
        ]
        for record in self.compact:
            result.append(
                PulseSnapshot(
                    cgroup_id=int(record["cgroup_id"]),
                    observed_at=observed_at,
                    counts={int(key): int(value) for key, value in record.get("counts", {}).items()},
                    transitions={},
                    syscall_bins={index: int(value) for index, value in enumerate(record.get("syscall_bins", []))},
                    transition_bins={index: int(value) for index, value in enumerate(record.get("transition_bins", []))},
                )
            )
        self.counts.clear()
        self.transitions.clear()
        self.syscall_bins.clear()
        self.transition_bins.clear()
        self.compact.clear()
        return result, dict(self.stats)


def read_metadata(path: Path) -> dict[str, dict]:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle).get("cgroups", {})
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def workload_key(metadata: dict) -> str:
    namespace = metadata.get("namespace", "unknown")
    workload = metadata.get("workload_name") or metadata.get("role", "unknown")
    container = metadata.get("container_name", "unknown")
    return f"{namespace}/{workload}:{container}"


def run(source, destination, metadata_file: Path, rolling_windows: int = 5,
        interval_min_seconds: float | None = None,
        interval_max_seconds: float | None = None,
        nominal_interval_seconds: float | None = None,
        recovery_profile: dict | None = None) -> dict:
    if (interval_min_seconds is None) != (interval_max_seconds is None):
        raise ValueError("both capture interval bounds must be provided")
    if interval_min_seconds is not None and not (
        0 < interval_min_seconds < interval_max_seconds
    ):
        raise ValueError("invalid capture interval bounds")
    if nominal_interval_seconds is not None and nominal_interval_seconds <= 0:
        raise ValueError("nominal capture interval must be positive")
    assembler = SnapshotAssembler()
    recovery = RecoveryTracker(recovery_profile) if recovery_profile is not None else None
    if recovery is not None and (
        rolling_windows != recovery.profile["rolling_windows"]
        or interval_min_seconds != recovery.profile["interval_min_seconds"]
        or interval_max_seconds != recovery.profile["interval_max_seconds"]
        or nominal_interval_seconds != recovery.profile["nominal_interval_seconds"]
    ):
        raise ValueError("capture configuration differs from recovery profile")
    builders: dict[tuple[str, str, str, str], PulseFeatureBuilder] = {}
    emitted = 0
    malformed = 0
    unresolved = 0
    written_schema_hashes = set()
    metadata: dict[str, dict] = {}
    metadata_mtime_ns: int | None = None
    previous_snapshot_observed_at: float | None = None
    observed_snapshots = 0
    estimated_missing_snapshots = 0
    maximum_snapshot_interval_seconds = 0.0
    minimum_snapshot_interval_seconds: float | None = None
    short_interval_events = 0
    for line in source:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            if recovery is not None:
                raise ValueError("malformed loader JSON in recovery mode")
            continue
        if record.get("type") != "snapshot_end":
            assembler.add(record)
            continue
        observed_at = float(record["observed_at"])
        snapshot_interval_seconds = (
            None
            if previous_snapshot_observed_at is None
            else observed_at - previous_snapshot_observed_at
        )
        previous_snapshot_observed_at = observed_at
        observed_snapshots += 1
        if "targets" in record and "snapshots" in record:
            gap = abs(int(record["targets"]) - int(record["snapshots"]))
            assembler.stats["target_snapshot_gap"] = max(
                int(assembler.stats.get("target_snapshot_gap", 0)), gap
            )
        snapshot_read_seconds = float(record.get("snapshot_read_seconds", 0.0))
        # The resolver replaces this file atomically every 15 seconds. Avoid a
        # filesystem open and JSON decode on every 500 ms snapshot, while still
        # observing each resolver generation. If stat/read fails transiently,
        # retain the last complete generation instead of dropping attribution.
        try:
            current_mtime_ns = metadata_file.stat().st_mtime_ns
        except OSError:
            current_mtime_ns = None
        if current_mtime_ns is not None and current_mtime_ns != metadata_mtime_ns:
            current_metadata = read_metadata(metadata_file)
            if current_metadata:
                metadata = current_metadata
                metadata_mtime_ns = current_mtime_ns
        interval_violation = bool(
            snapshot_interval_seconds is not None
            and interval_min_seconds is not None
            and not (
                interval_min_seconds
                <= snapshot_interval_seconds
                <= interval_max_seconds
            )
        )
        if snapshot_interval_seconds is not None:
            maximum_snapshot_interval_seconds = max(
                maximum_snapshot_interval_seconds, snapshot_interval_seconds
            )
            minimum_snapshot_interval_seconds = (
                snapshot_interval_seconds
                if minimum_snapshot_interval_seconds is None
                else min(minimum_snapshot_interval_seconds, snapshot_interval_seconds)
            )
        if interval_violation:
            # This cumulative counter is independent of workload cardinality.
            assembler.stats["capture_interval_violation"] = (
                assembler.stats.get("capture_interval_violation", 0) + 1
            )
            if (
                nominal_interval_seconds is not None
                and snapshot_interval_seconds is not None
                and snapshot_interval_seconds > interval_max_seconds
            ):
                estimated_missing_snapshots += max(
                    1,
                    int(round(snapshot_interval_seconds / nominal_interval_seconds))
                    - 1,
                )
            elif (
                snapshot_interval_seconds is not None
                and snapshot_interval_seconds < interval_min_seconds
            ):
                short_interval_events += 1
        snapshots, collector_stats = assembler.snapshots(observed_at)
        received_at = time.time()
        recovery_state = None
        if recovery is not None:
            recovery_state = recovery.step(
                observed_at, received_at, collector_stats, snapshot_read_seconds)
        expected_snapshots = observed_snapshots + estimated_missing_snapshots
        telemetry_availability = (
            observed_snapshots / expected_snapshots if expected_snapshots else 0.0
        )
        telemetry_state = {
            "schema": "sentinel-pulse-telemetry-availability-v1",
            "observed_snapshots": observed_snapshots,
            "estimated_missing_snapshots": estimated_missing_snapshots,
            "availability": telemetry_availability,
            "maximum_snapshot_interval_seconds": (
                maximum_snapshot_interval_seconds
            ),
            "minimum_snapshot_interval_seconds": (
                minimum_snapshot_interval_seconds
            ),
            "short_interval_events": short_interval_events,
            "cadence_violation_events": int(
                collector_stats.get("capture_interval_violation", 0)
            ),
        }
        prepared = []
        if recovery is not None:
            prepared.append({
                "schema": SNAPSHOT_SCHEMA, "observed_at": observed_at,
                "received_at": received_at, "snapshot_read_seconds": snapshot_read_seconds,
                "collector_stats": collector_stats, "recovery": recovery_state,
            })
        for snapshot in snapshots:
            item = metadata.get(str(snapshot.cgroup_id))
            if item is None:
                unresolved += 1
                continue
            key = workload_key(item)
            source_identity = (
                str(item.get("node_name", "unknown-node")),
                str(item.get("pod_uid", "unknown-pod")),
                str(item.get("container_name", "unknown-container")),
                str(snapshot.cgroup_id),
            )
            builder = builders.setdefault(
                source_identity, PulseFeatureBuilder(rolling_windows=rolling_windows)
            )
            history_before = builder.history_windows_available(snapshot.cgroup_id)
            feature = builder.ingest(snapshot, key)
            if feature is None:
                continue
            output, schema = compact_record(feature.as_record())
            schema_hash = schema["feature_schema_sha256"]
            if schema_hash not in written_schema_hashes:
                prepared.append(schema)
                written_schema_hashes.add(schema_hash)
            output["pod_name"] = item.get("pod_name")
            output["pod_uid"] = item.get("pod_uid")
            output["node_name"] = item.get("node_name")
            output["role"] = item.get("role")
            output["container_name"] = item.get("container_name")
            # This is provenance metadata, not an ML feature.  Keeping it out
            # of the vector prevents a deployment hash from becoming a learned
            # shortcut while allowing inference to reject an unapproved rollout.
            output["workload_revision"] = item.get("workload_revision", "unknown")
            output["emitted_at"] = time.time()
            output["collector_stats"] = collector_stats
            output["snapshot_read_seconds"] = snapshot_read_seconds
            output["collector_snapshot_interval_seconds"] = (
                snapshot_interval_seconds
            )
            output["collector_telemetry_availability"] = telemetry_state
            if recovery is not None:
                eligible, reason = feature_eligibility(
                    recovery_state, recovery.profile, history_before,
                    feature.window_start, feature.window_end, output["emitted_at"])
                output["telemetry_recovery"] = {
                    "profile_sha256": recovery.profile_sha256,
                    "snapshot_sequence": recovery_state["sequence"],
                    "epoch": recovery_state["epoch"],
                    "eligible": eligible, "reason": reason,
                    "rolling_history_before": history_before,
                }
                if reason in {"source_cadence", "feature_ingest_lag"}:
                    replacement = PulseFeatureBuilder(rolling_windows=rolling_windows)
                    replacement.ingest(snapshot, key)
                    builders[source_identity] = replacement
            prepared.append(output)
            emitted += 1
        if recovery is not None and recovery_state["reset_required"]:
            # Retain the bad delta as a quarantined diagnostic feature, but
            # never allow its rate into subsequent rolling features.
            builders.clear()
            for snapshot in snapshots:
                item = metadata.get(str(snapshot.cgroup_id))
                if item is None:
                    continue
                identity = (str(item.get("node_name", "unknown-node")),
                            str(item.get("pod_uid", "unknown-pod")),
                            str(item.get("container_name", "unknown-container")),
                            str(snapshot.cgroup_id))
                builder = PulseFeatureBuilder(rolling_windows=rolling_windows)
                builder.ingest(snapshot, workload_key(item))
                builders[identity] = builder
        if prepared:
            destination.write(
                "".join(
                    json.dumps(item, separators=(",", ":")) + "\n"
                    for item in prepared
                )
            )
            # One flush per BPF snapshot bounds visibility latency without
            # forcing one userspace write/flush per workload row.
            destination.flush()
        if recovery is not None and recovery_state["status"] == "fatal":
            raise ValueError("fatal recovery integrity error: " + "; ".join(recovery_state["reasons"]))
    return {"emitted": emitted, "malformed": malformed, "unresolved": unresolved}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rolling-windows", type=int, default=5)
    parser.add_argument("--interval-min-seconds", type=float)
    parser.add_argument("--interval-max-seconds", type=float)
    parser.add_argument("--nominal-interval-seconds", type=float)
    parser.add_argument("--recovery-profile", type=Path,
                        help="opt-in quarantine journal; not a legacy formal capture")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("a", encoding="utf-8") as destination:
        stats = run(sys.stdin, destination, args.metadata_file, args.rolling_windows,
                    args.interval_min_seconds, args.interval_max_seconds,
                    args.nominal_interval_seconds,
                    load_profile(args.recovery_profile) if args.recovery_profile else None)
    print(json.dumps(stats), file=sys.stderr)


if __name__ == "__main__":
    main()
