"""Freeze multiple validated detector captures into one canonical replay file."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from validate_feature_capture import sha256, validate_capture


KIND_ORDER = {"injection": 0, "feature_window": 1, "injection_end": 2}


def merge_captures(inputs: list[Path], output: Path,
                   *, require_injections: bool = False) -> dict:
    if len(inputs) < 1:
        raise ValueError("at least one capture is required")
    resolved = [path.resolve() for path in inputs]
    if len(set(resolved)) != len(resolved):
        raise ValueError("duplicate capture input")
    if output.resolve() in resolved:
        raise ValueError("output cannot overwrite an input capture")
    manifest_path = output.with_suffix(".manifest.json")
    if output.exists() or manifest_path.exists():
        if not output.is_file() or not manifest_path.is_file():
            raise FileExistsError("incomplete frozen capture output exists")
        manifest = json.loads(manifest_path.read_text())
        expected_hashes = [sha256(path) for path in resolved]
        recorded_hashes = [row.get("sha256") for row in manifest.get("sources", [])]
        validation = validate_capture(output)
        if (
            manifest.get("schema") != "sentinel-feature-capture-merge/v1"
            or recorded_hashes != expected_hashes
            or manifest.get("capture", {}).get("sha256") != sha256(output)
            or not validation["valid"]
            or (require_injections and validation["injection_intervals"] <= 0)
        ):
            raise ValueError("existing frozen capture does not match current sources")
        return manifest

    sources = []
    rows = []
    for source_index, path in enumerate(resolved):
        validation = validate_capture(path)
        if not validation["valid"]:
            raise ValueError(f"invalid source capture {path.name}: {validation['errors']}")
        sources.append({
            "source_id": source_index,
            "name": path.name,
            "sha256": sha256(path),
            "validation": validation,
        })
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            row = json.loads(line)
            rows.append((
                float(row["ts"]), KIND_ORDER[row["kind"]],
                source_index, line_number, row,
            ))

    rows.sort(key=lambda item: item[:4])
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + f".tmp-{os.getpid()}")
    try:
        temporary.write_text("".join(
            json.dumps(item[-1], sort_keys=True, separators=(",", ":")) + "\n"
            for item in rows
        ))
        merged_validation = validate_capture(temporary)
        if not merged_validation["valid"]:
            raise ValueError(
                f"merged capture violates contract: {merged_validation['errors']}"
            )
        if require_injections and merged_validation["injection_intervals"] <= 0:
            raise ValueError("merged attack capture has no injection intervals")
        temporary.replace(output)
    finally:
        if temporary.exists():
            temporary.unlink()

    # Revalidate after the atomic rename so the recorded source name/digest
    # describe the actual frozen artifact, not its temporary filename.
    final_validation = validate_capture(output)
    manifest = {
        "schema": "sentinel-feature-capture-merge/v1",
        "capture": {"name": output.name, "sha256": sha256(output)},
        "sources": sources,
        "source_count": len(sources),
        "row_count": len(rows),
        "validation": final_validation,
        "labels_used_for_training": False,
        "ordering": "event ts, row-kind rank, source index, source line",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--require-injections", action="store_true")
    args = parser.parse_args()
    merge_captures(
        args.inputs, args.output, require_injections=args.require_injections,
    )
    print(args.output.with_suffix(".manifest.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
