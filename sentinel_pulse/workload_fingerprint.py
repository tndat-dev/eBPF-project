"""Create a rollout-aware production workload fingerprint for a normal soak."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .cgroup_resolver import EXCLUDED_MARKERS, infer_workload_name, workload_revision


def fingerprint(pods: dict) -> dict:
    """Return stable workload-to-template revisions, excluding test actors."""
    values: dict[str, set[str]] = {}
    for item in pods.get("items", []):
        metadata = item.get("metadata", {})
        status = item.get("status", {})
        name = metadata.get("name", "")
        namespace = metadata.get("namespace", "")
        if not name or not namespace or status.get("phase") not in {"Running", "Pending"}:
            continue
        if any(marker in name.lower() for marker in EXCLUDED_MARKERS):
            continue
        labels = metadata.get("labels", {})
        annotations = metadata.get("annotations", {})
        workload = labels.get("app.kubernetes.io/name") or infer_workload_name(name)
        key = f"{namespace}/{workload}"
        values.setdefault(key, set()).add(workload_revision(labels, annotations))
    return {
        "schema": "sentinel-pulse-workload-fingerprint-v1",
        "workloads": {key: sorted(value) for key, value in sorted(values.items())},
    }


def digest(document: dict) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = fingerprint(json.loads(args.input.read_text(encoding="utf-8")))
    document["sha256"] = digest(document)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
