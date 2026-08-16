"""Build workload-specific normal maxima for preregistered threat signals."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import tempfile
import time

from .integrity import sha256_file
from .train import load_dataset_manifest


SIGNAL_GROUPS = {
    "local_socket_beacon": ("socket", "connect"),
    "process_fanout": ("clone", "clone3"),
    "identity_transition": ("setuid", "setgid", "capset"),
    "credential_open": ("openat",),
    "namespace_probe": (
        "ptrace",
        "pivot_root",
        "mount",
        "unshare",
        "setns",
        "execveat",
    ),
}


def calibrate(dataset: Path) -> dict:
    manifest_path, manifest = load_dataset_manifest(dataset)
    maxima: dict[str, dict[str, int]] = {}
    workload_rows: Counter[str] = Counter()
    started = time.perf_counter()
    with dataset.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            record = json.loads(line)
            if record.get("schema") == "sentinel-pulse-feature-schema-v1":
                continue
            if record.get("schema") != "sentinel-pulse-feature-v1":
                raise ValueError(f"line {line_number}: unsupported feature schema")
            exact_counts = record.get("exact_counts")
            if not isinstance(exact_counts, dict):
                raise ValueError(f"line {line_number}: exact syscall counts are missing")
            workload = str(record["workload_key"])
            target = maxima.setdefault(
                workload, {name: 0 for name in SIGNAL_GROUPS}
            )
            workload_rows[workload] += 1
            for name, fields in SIGNAL_GROUPS.items():
                value = sum(int(exact_counts.get(field, 0)) for field in fields)
                if value < 0:
                    raise ValueError(f"line {line_number}: negative exact syscall count")
                target[name] = max(target[name], value)
    return {
        "schema": "sentinel-pulse-semantic-envelope-calibration-v1",
        "normal_only": True,
        "blind_outcome_used": False,
        "dataset": str(dataset),
        "dataset_sha256": manifest["dataset_sha256"],
        "dataset_manifest": str(manifest_path),
        "dataset_manifest_sha256": sha256_file(manifest_path),
        "rows": sum(workload_rows.values()),
        "workload_rows": dict(sorted(workload_rows.items())),
        "signal_groups": {
            name: list(fields) for name, fields in SIGNAL_GROUPS.items()
        },
        "workload_group_maxima": dict(sorted(maxima.items())),
        "elapsed_seconds": time.perf_counter() - started,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError(f"refusing to overwrite semantic calibration: {args.output}")
    report = calibrate(args.dataset)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=args.output.parent,
            prefix=f".{args.output.name}.",
            delete=False,
        ) as output:
            temporary_name = output.name
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, args.output)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    main()
