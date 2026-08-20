"""Verify that detector-side blind markers exactly equal the controller log."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .integrity import sha256_file


def load(path: Path) -> dict[str, dict]:
    records = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            record = json.loads(line)
            if record.get("schema") != "sentinel-pulse-injection-v1":
                raise ValueError(f"unexpected injection record at {path}:{line_number}")
            injection_id = str(record.get("injection_id", ""))
            if not injection_id or injection_id in records:
                raise ValueError(f"missing or duplicate injection ID at {path}:{line_number}")
            records[injection_id] = record
    return records


def verify(controller_path: Path, detector_paths: list[Path]) -> dict:
    if not detector_paths:
        raise ValueError("at least one detector marker source is required")
    controller = load(controller_path)
    distributed = {}
    sources = []
    duplicate_ids = []
    for path in detector_paths:
        records = load(path)
        duplicate_ids.extend(sorted(set(distributed) & set(records)))
        distributed.update(records)
        sources.append({"path": str(path), "sha256": sha256_file(path), "rows": len(records)})
    missing = sorted(set(controller) - set(distributed))
    unexpected = sorted(set(distributed) - set(controller))
    changed = sorted(
        injection_id for injection_id in set(controller) & set(distributed)
        if controller[injection_id] != distributed[injection_id]
    )
    valid = not duplicate_ids and not missing and not unexpected and not changed
    return {
        "schema": "sentinel-pulse-distributed-injection-verification-v1",
        "controller": {
            "path": str(controller_path),
            "sha256": sha256_file(controller_path),
            "rows": len(controller),
        },
        "detector_sources": sources,
        "distributed_rows": len(distributed),
        "duplicate_injection_ids": sorted(set(duplicate_ids)),
        "missing_injection_ids": missing,
        "unexpected_injection_ids": unexpected,
        "changed_injection_ids": changed,
        "valid": valid,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller", type=Path, required=True)
    parser.add_argument("--detector", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.controller, args.detector)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    raise SystemExit(0 if report["valid"] else 1)


if __name__ == "__main__":
    main()
