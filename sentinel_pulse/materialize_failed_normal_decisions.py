#!/usr/bin/env python3
"""Materialize checksum-bound decision streams from failed-soak tar archives."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import tarfile

from .audit_failed_normal_soak import load_json, sha256, verify_sha256_manifest


def materialize(root: Path, output: Path) -> dict:
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    if (root / "ACTIVE").exists() or not (root / "FAILED").is_file():
        raise ValueError("source must be a terminal failed soak")
    checksum_count = verify_sha256_manifest(root, root / "RAW_SHA256SUMS")
    marker = load_json(root / "SOAK_START.json")
    archives = sorted(
        (root / "infrastructure-failure" / "workers").glob("*/raw.tar.gz")
    )
    if not archives:
        raise ValueError("no worker archives found")

    output.mkdir(parents=True)
    sources = []
    try:
        for archive_path in archives:
            host = archive_path.parent.name
            with tarfile.open(archive_path, "r:gz") as archive:
                members = [
                    member
                    for member in archive.getmembers()
                    if member.isfile() and member.name.endswith("/decisions.jsonl")
                ]
                if len(members) != 1:
                    raise ValueError(
                        f"expected one decision stream in {archive_path}, got {len(members)}"
                    )
                source = archive.extractfile(members[0])
                if source is None:
                    raise ValueError(f"cannot read {members[0].name}")
                destination = output / f"{host}-decisions.jsonl"
                with destination.open("wb") as sink:
                    shutil.copyfileobj(source, sink, length=1024 * 1024)

            rows = 0
            with destination.open(encoding="utf-8") as stream:
                for number, line in enumerate(stream, start=1):
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(
                            f"invalid decision JSON at {destination}:{number}"
                        ) from exc
                    if any(
                        key in record
                        for key in ("injection_id", "attack_injected_at", "scenario_id")
                    ):
                        raise ValueError("attack-attributed row found in normal evidence")
                    rows += 1
            sources.append(
                {
                    "host": host,
                    "path": destination.name,
                    "rows": rows,
                    "sha256": sha256(destination),
                    "archive_sha256": sha256(archive_path),
                    "archive_member": members[0].name,
                }
            )

        binding = {
            "schema": "sentinel-pulse-materialized-normal-decisions-v1",
            "run_id": marker["run_id"],
            "model_manifest_sha256": marker["model_manifest_sha256"],
            "decision_policy_sha256": marker["decision_policy_sha256"],
            "raw_sha256sums_sha256": sha256(root / "RAW_SHA256SUMS"),
            "raw_manifest_entries_verified": checksum_count,
            "soak_start_sha256": sha256(root / "SOAK_START.json"),
            "attack_rows_allowed": False,
            "sources": sources,
        }
        binding_path = output / "SOURCE_BINDING.json"
        binding_path.write_text(
            json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        manifest_path = output / "DECISIONS_SHA256SUMS"
        indexed = [output / source["path"] for source in sources] + [binding_path]
        manifest_path.write_text(
            "".join(f"{sha256(path)}  {path.name}\n" for path in indexed),
            encoding="ascii",
        )
        for path in indexed + [manifest_path]:
            os.chmod(path, 0o444)
        return binding
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    binding = materialize(args.evidence_root.resolve(), args.output_dir.resolve())
    print(json.dumps({
        "run_id": binding["run_id"],
        "rows": sum(source["rows"] for source in binding["sources"]),
        "sources": len(binding["sources"]),
        "output_dir": str(args.output_dir.resolve()),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
