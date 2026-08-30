"""Fail-closed Longhorn topology checks for formal Pulse campaigns."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
import sys


def duplicate_disk_uuids(payload: dict) -> list[dict]:
    """Return disk UUIDs advertised by more than one Longhorn node."""

    owners: dict[str, set[str]] = defaultdict(set)
    for node in payload.get("items", []):
        name = str(node.get("metadata", {}).get("name", "unknown"))
        for disk in node.get("status", {}).get("diskStatus", {}).values():
            disk_uuid = str(disk.get("diskUUID", "")).strip()
            if disk_uuid:
                owners[disk_uuid].add(name)
    return [
        {
            "reason": "duplicate_disk_uuid",
            "disk_uuid": disk_uuid,
            "nodes": sorted(nodes),
        }
        for disk_uuid, nodes in sorted(owners.items())
        if len(nodes) > 1
    ]


def colocated_running_replicas(payload: dict) -> list[dict]:
    """Find volumes whose running replicas share one physical manager."""

    placements: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for replica in payload.get("items", []):
        status = replica.get("status", {})
        if status.get("currentState") != "running":
            continue
        spec = replica.get("spec", {})
        volume = str(spec.get("volumeName", "")).strip()
        manager = str(status.get("instanceManagerName", "")).strip()
        name = str(replica.get("metadata", {}).get("name", "unknown"))
        if volume and manager:
            placements[volume].append((name, manager))

    issues = []
    for volume, replicas in sorted(placements.items()):
        if len(replicas) < 2:
            continue
        managers = {manager for _, manager in replicas}
        if len(managers) < len(replicas):
            issues.append(
                {
                    "reason": "colocated_running_replicas",
                    "volume": volume,
                    "replicas": [name for name, _ in replicas],
                    "instance_managers": sorted(managers),
                }
            )
    return issues


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resource", choices=("nodes", "replicas"), required=True)
    parser.add_argument("--count", action="store_true")
    args = parser.parse_args()
    payload = json.load(sys.stdin)
    issues = (
        duplicate_disk_uuids(payload)
        if args.resource == "nodes"
        else colocated_running_replicas(payload)
    )
    if args.count:
        print(len(issues))
    else:
        for issue in issues:
            print(json.dumps(issue, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
