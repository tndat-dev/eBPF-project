"""Age-aware Kubernetes pod health classification for capture campaigns."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import sys


def parse_timestamp(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def unhealthy_pods(payload: dict, now: float, grace_seconds: float = 300.0) -> list[dict]:
    unhealthy = []
    for pod in payload.get("items", []):
        metadata = pod.get("metadata", {})
        status = pod.get("status", {})
        namespace = str(metadata.get("namespace", "default"))
        name = str(metadata.get("name", "unknown"))
        phase = str(status.get("phase", "Unknown"))
        created = metadata.get("creationTimestamp")
        age = now - parse_timestamp(created) if created else float("inf")
        reason = None
        if phase == "Succeeded":
            continue
        if phase in {"Failed", "Unknown"}:
            reason = phase.lower()
        elif phase == "Pending" and age > grace_seconds:
            reason = "pending_beyond_grace"
        elif phase == "Running" and age > grace_seconds:
            statuses = status.get("containerStatuses", [])
            if not statuses or any(item.get("ready") is not True for item in statuses):
                reason = "container_unready_beyond_grace"
        elif phase not in {"Pending", "Running"} and age > grace_seconds:
            reason = f"unexpected_phase:{phase}"
        if reason is not None:
            unhealthy.append(
                {
                    "namespace": namespace,
                    "pod": name,
                    "phase": phase,
                    "age_seconds": max(0.0, age),
                    "reason": reason,
                }
            )
    return unhealthy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--grace-seconds", type=float, default=300.0)
    parser.add_argument("--count", action="store_true")
    args = parser.parse_args()
    if args.grace_seconds < 0:
        raise ValueError("pod health grace cannot be negative")
    payload = json.load(sys.stdin)
    bad = unhealthy_pods(payload, datetime.now(timezone.utc).timestamp(), args.grace_seconds)
    if args.count:
        print(len(bad))
    else:
        for item in bad:
            print(json.dumps(item, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
