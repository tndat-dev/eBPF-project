"""Label validated feature windows from explicit injection intervals."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from validate_feature_capture import validate_capture


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def injection_intervals(rows: list[dict]) -> list[dict]:
    starts = {}
    intervals = []
    for row in rows:
        kind = row.get("kind")
        injection_id = row.get("injection_id")
        if kind == "injection" and injection_id:
            if injection_id in starts:
                raise ValueError(f"duplicate injection start: {injection_id}")
            starts[injection_id] = row
        elif kind == "injection_end" and injection_id:
            start = starts.pop(injection_id, None)
            if start is None:
                raise ValueError(f"injection end without start: {injection_id}")
            if (
                row.get("pod_key") != start.get("pod_key")
                or row.get("attack_type") != start.get("attack_type")
                or float(row.get("ts", 0)) <= float(start.get("ts", 0))
            ):
                raise ValueError(f"inconsistent injection interval: {injection_id}")
            intervals.append({
                "injection_id": injection_id,
                "pod_key": start["pod_key"],
                "scenario": start["attack_type"],
                "start": float(start["ts"]),
                "end": float(row["ts"]),
                "rate": start.get("rate"),
                "seed": start.get("seed"),
                "attack_exit_code": row.get("attack_exit_code"),
            })
    if starts:
        raise ValueError(f"injection starts without end: {sorted(starts)}")
    return intervals


def label_windows(rows: list[dict], intervals: list[dict]) -> list[dict]:
    labelled = []
    for source_row in rows:
        if source_row.get("kind") != "feature_window":
            continue
        row = dict(source_row)
        overlaps = [
            interval for interval in intervals
            if interval["pod_key"] == row.get("pod_key")
            and float(row["window_end"]) > interval["start"]
            and float(row["window_start"]) < interval["end"]
        ]
        if len(overlaps) > 1:
            raise ValueError(
                f"feature window overlaps multiple injections: "
                f"{row.get('pod_key')}@{row.get('window_start')}"
            )
        row["label"] = "attack" if overlaps else "normal"
        if overlaps:
            interval = overlaps[0]
            row["scenario"] = interval["scenario"]
            row["injection_id"] = interval["injection_id"]
            row["trial_rate"] = interval["rate"]
            row["trial_seed"] = interval["seed"]
        else:
            row["scenario"] = None
            row["injection_id"] = None
            row["trial_rate"] = None
            row["trial_seed"] = None
        labelled.append(row)
    return labelled


def build_dataset(capture: Path, *, require_injections: bool = False
                  ) -> tuple[list[dict], dict]:
    validation = validate_capture(capture)
    if not validation["valid"]:
        raise ValueError(f"invalid feature capture: {validation['errors']}")
    source_rows = load_rows(capture)
    intervals = injection_intervals(source_rows)
    if require_injections and not intervals:
        raise ValueError("attack capture contains no complete injection intervals")
    if any(interval["attack_exit_code"] != 0 for interval in intervals):
        raise ValueError("attack capture contains a failed injection")
    rows = label_windows(source_rows, intervals)
    normal = sum(row["label"] == "normal" for row in rows)
    attack = len(rows) - normal
    manifest = {
        "schema": "sentinel-feature-replay-dataset/v1",
        "source": {"name": capture.name, "sha256": sha256(capture)},
        "capture_validation": validation,
        "feature_windows": len(rows),
        "normal_windows": normal,
        "attack_windows": attack,
        "injection_intervals": len(intervals),
        "scenarios": sorted({
            interval["scenario"] for interval in intervals
        }),
        "labelling_rule": "window interval intersects same-pod injection interval",
        "labels_used_for_training": False,
    }
    return rows, manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-injections", action="store_true")
    args = parser.parse_args()
    rows, manifest = build_dataset(
        args.capture, require_injections=args.require_injections,
    )
    args.output.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    )
    manifest["dataset"] = {
        "name": args.output.name,
        "sha256": sha256(args.output),
    }
    manifest_path = args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
