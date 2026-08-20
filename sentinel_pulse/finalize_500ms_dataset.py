"""Bind a frozen 500 ms node capture to a preregistered traffic contract."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import stat
import time

from .assemble_dataset import interval_for, load_contract
from .integrity import sha256_file


def finalize(
    capture: Path,
    contract_path: Path,
    node: str,
    final_report_path: Path,
    output: Path,
) -> dict:
    if output.exists():
        raise ValueError(f"refusing to overwrite node manifest: {output}")
    if not capture.is_file() or capture.stat().st_mode & (
        stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
    ):
        raise ValueError("capture must exist and be immutable/read-only")
    contract = load_contract(contract_path)
    if node not in set(map(str, contract["expected_nodes"])):
        raise ValueError(f"node is not in capture contract: {node}")
    final_report = json.loads(final_report_path.read_text(encoding="utf-8"))
    if (
        final_report.get("valid") is not True
        or final_report.get("capture_sha256") != sha256_file(capture)
    ):
        raise ValueError("500 ms final report is invalid or capture hash differs")

    campaign_start = min(float(item["start"]) for item in contract["intervals"])
    campaign_end = max(float(item["end"]) for item in contract["intervals"])
    rows = 0
    campaign_span_rows = 0
    first_end = None
    last_end = None
    nodes = set()
    max_integrity = defaultdict(int)
    rows_by_regime = Counter()
    with capture.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            record = json.loads(line)
            if record.get("schema") == "sentinel-pulse-feature-schema-v1":
                continue
            if record.get("schema") != "sentinel-pulse-feature-v1":
                raise ValueError(f"unsupported record at line {line_number}")
            rows += 1
            nodes.add(str(record.get("node_name", "")))
            window_start = float(record["window_start"])
            window_end = float(record["window_end"])
            first_end = window_end if first_end is None else min(first_end, window_end)
            last_end = window_end if last_end is None else max(last_end, window_end)
            if window_start >= campaign_start and window_end <= campaign_end:
                campaign_span_rows += 1
                for name, value in record.get("collector_stats", {}).items():
                    max_integrity[name] = max(max_integrity[name], int(value))
            interval = interval_for(record, contract["intervals"])
            if interval is not None:
                rows_by_regime[str(interval["regime"])] += 1

    if nodes != {node}:
        raise ValueError(f"capture node identity mismatch: expected={node}, rows={nodes}")
    if rows != int(final_report.get("rows", -1)):
        raise ValueError("capture row count differs from 500 ms final report")
    if first_end is None or first_end > campaign_start:
        raise ValueError("capture did not start before the registered campaign")
    if last_end is None or last_end < campaign_end:
        raise ValueError("capture ended before the registered campaign")
    if campaign_span_rows <= 0:
        raise ValueError("capture has no campaign-span rows")
    missing = [
        str(item["regime"])
        for item in contract["intervals"]
        if rows_by_regime[str(item["regime"])] <= 0
    ]
    if missing:
        raise ValueError(f"capture has no rows for regimes: {missing}")
    bad_integrity = {
        name: value for name, value in max_integrity.items() if int(value) != 0
    }
    if bad_integrity:
        raise ValueError(f"non-zero in-contract integrity counters: {bad_integrity}")

    manifest = {
        "schema": "sentinel-pulse-node-capture-manifest-v2",
        "capture_profile": "exact-ebpf-500ms-rolling-10",
        "campaign_id": contract["campaign_id"],
        "contract_sha256": sha256_file(contract_path),
        "node_name": node,
        "capture": str(capture),
        "capture_sha256": sha256_file(capture),
        "capture_bytes": capture.stat().st_size,
        "rows": rows,
        "campaign_span_rows": campaign_span_rows,
        "rows_by_regime": dict(sorted(rows_by_regime.items())),
        "first_window_end": first_end,
        "last_window_end": last_end,
        "campaign_start": campaign_start,
        "campaign_end": campaign_end,
        "collector_max_integrity": dict(sorted(max_integrity.items())),
        "source_final_report": str(final_report_path),
        "source_final_report_sha256": sha256_file(final_report_path),
        "frozen_at": time.time(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, output)
    output.chmod(0o444)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--final-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = finalize(
        args.capture, args.contract, args.node, args.final_report, args.output
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
