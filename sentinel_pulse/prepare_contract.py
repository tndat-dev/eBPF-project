"""Freeze an absolute four-regime capture schedule before collection starts."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .assemble_dataset import load_contract


REGIMES = ("steady", "toolmix", "burst", "recovery")


def prepare(
    output: Path,
    campaign_id: str,
    start: float,
    duration_seconds: int,
    transition_gap_seconds: int,
    nodes: list[str],
) -> dict:
    if output.exists():
        raise ValueError(f"refusing to overwrite capture contract: {output}")
    if not campaign_id or duration_seconds < 300 or transition_gap_seconds < 30:
        raise ValueError("campaign ID, >=300s duration and >=30s transition gap are required")
    intervals = []
    cursor = float(start)
    for regime in REGIMES:
        intervals.append({"regime": regime, "start": cursor, "end": cursor + duration_seconds})
        cursor += duration_seconds + transition_gap_seconds
    contract = {
        "schema": "sentinel-pulse-capture-contract-v1",
        "campaign_id": campaign_id,
        "normal_only": True,
        "expected_nodes": nodes,
        "intervals": intervals,
        "schedule": {
            "duration_seconds_per_regime": duration_seconds,
            "transition_gap_seconds": transition_gap_seconds,
            "regime_order": list(REGIMES),
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, output)
    return load_contract(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--start", type=float, required=True)
    parser.add_argument("--duration-seconds", type=int, default=21600)
    parser.add_argument("--transition-gap-seconds", type=int, default=180)
    parser.add_argument("--node", action="append", required=True)
    args = parser.parse_args()
    contract = prepare(
        args.output,
        args.campaign_id,
        args.start,
        args.duration_seconds,
        args.transition_gap_seconds,
        args.node,
    )
    print(json.dumps(contract, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
