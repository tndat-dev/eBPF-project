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


def run(source, destination, metadata_file: Path, rolling_windows: int = 5) -> dict:
    assembler = SnapshotAssembler()
    builders: dict[tuple[str, str, str, str], PulseFeatureBuilder] = {}
    emitted = 0
    malformed = 0
    unresolved = 0
    written_schema_hashes = set()
    for line in source:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if record.get("type") != "snapshot_end":
            assembler.add(record)
            continue
        observed_at = float(record["observed_at"])
        if "targets" in record and "snapshots" in record:
            gap = abs(int(record["targets"]) - int(record["snapshots"]))
            assembler.stats["target_snapshot_gap"] = max(
                int(assembler.stats.get("target_snapshot_gap", 0)), gap
            )
        snapshot_read_seconds = float(record.get("snapshot_read_seconds", 0.0))
        metadata = read_metadata(metadata_file)
        snapshots, collector_stats = assembler.snapshots(observed_at)
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
            feature = builder.ingest(snapshot, key)
            if feature is None:
                continue
            output, schema = compact_record(feature.as_record())
            schema_hash = schema["feature_schema_sha256"]
            if schema_hash not in written_schema_hashes:
                destination.write(json.dumps(schema, separators=(",", ":")) + "\n")
                written_schema_hashes.add(schema_hash)
            output["pod_name"] = item.get("pod_name")
            output["pod_uid"] = item.get("pod_uid")
            output["node_name"] = item.get("node_name")
            output["role"] = item.get("role")
            output["container_name"] = item.get("container_name")
            output["emitted_at"] = time.time()
            output["collector_stats"] = collector_stats
            output["snapshot_read_seconds"] = snapshot_read_seconds
            destination.write(json.dumps(output, separators=(",", ":")) + "\n")
            destination.flush()
            emitted += 1
    return {"emitted": emitted, "malformed": malformed, "unresolved": unresolved}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rolling-windows", type=int, default=5)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("a", encoding="utf-8") as destination:
        stats = run(sys.stdin, destination, args.metadata_file, args.rolling_windows)
    print(json.dumps(stats), file=sys.stderr)


if __name__ == "__main__":
    main()
