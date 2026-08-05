"""Validate privacy and integrity of paired feature-window replay evidence."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path


ALLOWED_KEYS = {
    "kind", "ts", "schema", "pod_key", "model_key", "node_name",
    "window_start", "window_end", "event_count", "vector_size",
    "sparse_vector", "syscall_counts", "contains_arguments_or_payloads",
    "capture_mode", "syscall_sequence",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_feature_row(row: dict, line_number: int) -> list[str]:
    prefix = f"line {line_number}"
    errors = []
    unknown = sorted(set(row) - ALLOWED_KEYS)
    if unknown:
        errors.append(f"{prefix}: unexpected/privacy-unsafe keys: {unknown}")
    if row.get("schema") != "sentinel-feature-window/v1":
        errors.append(f"{prefix}: schema mismatch")
    if row.get("capture_mode") not in ("aggregate", "sequence"):
        errors.append(f"{prefix}: invalid capture mode")
    if row.get("contains_arguments_or_payloads") is not False:
        errors.append(f"{prefix}: privacy exclusion is not explicit")
    for key in ("pod_key", "model_key", "node_name"):
        if not isinstance(row.get(key), str) or not row[key]:
            errors.append(f"{prefix}: invalid {key}")
    try:
        start = float(row["window_start"])
        end = float(row["window_end"])
        if not math.isfinite(start) or not math.isfinite(end) or end <= start:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        errors.append(f"{prefix}: invalid window interval")
    size = row.get("vector_size")
    events = row.get("event_count")
    if not isinstance(size, int) or size <= 0:
        errors.append(f"{prefix}: invalid vector size")
        size = 0
    if not isinstance(events, int) or events <= 0:
        errors.append(f"{prefix}: invalid event count")
    counts = row.get("syscall_counts")
    if not isinstance(counts, dict) or not counts:
        errors.append(f"{prefix}: syscall counts missing")
    elif any(
        not isinstance(name, str) or not name
        or not isinstance(count, int) or count <= 0
        for name, count in counts.items()
    ):
        errors.append(f"{prefix}: invalid syscall count entry")
    elif isinstance(events, int) and sum(counts.values()) != events:
        errors.append(f"{prefix}: syscall counts do not sum to event count")
    sparse = row.get("sparse_vector")
    if not isinstance(sparse, list):
        errors.append(f"{prefix}: sparse vector missing")
    else:
        indices = []
        for item in sparse:
            if (
                not isinstance(item, list) or len(item) != 2
                or not isinstance(item[0], int)
                or item[0] < 0 or item[0] >= size
                or not isinstance(item[1], (int, float))
                or not math.isfinite(float(item[1])) or float(item[1]) <= 0
            ):
                errors.append(f"{prefix}: invalid sparse vector entry")
                break
            indices.append(item[0])
        if indices != sorted(set(indices)):
            errors.append(f"{prefix}: sparse vector indices are not unique/sorted")
    sequence = row.get("syscall_sequence")
    if row.get("capture_mode") == "sequence":
        if not isinstance(sequence, list) or len(sequence) != events:
            errors.append(f"{prefix}: syscall sequence length mismatch")
        elif not all(isinstance(name, str) and name for name in sequence):
            errors.append(f"{prefix}: invalid syscall sequence entry")
        elif isinstance(counts, dict) and dict(Counter(sequence)) != counts:
            errors.append(f"{prefix}: sequence and syscall counts differ")
    elif sequence is not None:
        errors.append(f"{prefix}: aggregate capture unexpectedly has a sequence")
    return errors


def validate_capture(path: Path) -> dict:
    errors = []
    rows = 0
    non_feature_rows = 0
    modes = Counter()
    vector_sizes = Counter()
    pods = Counter()
    windows_by_pod = defaultdict(list)
    seen = set()
    minimum_start = None
    maximum_end = None
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        try:
            row = json.loads(line)
        except (TypeError, ValueError):
            errors.append(f"line {line_number}: invalid JSON")
            continue
        if row.get("kind") != "feature_window":
            non_feature_rows += 1
            continue
        rows += 1
        errors.extend(validate_feature_row(row, line_number))
        modes[str(row.get("capture_mode"))] += 1
        vector_sizes[str(row.get("vector_size"))] += 1
        pod = str(row.get("pod_key"))
        pods[pod] += 1
        try:
            start, end = float(row["window_start"]), float(row["window_end"])
        except (KeyError, TypeError, ValueError):
            continue
        key = (pod, start, end)
        if key in seen:
            errors.append(f"line {line_number}: duplicate pod window")
        seen.add(key)
        windows_by_pod[pod].append((start, end, line_number))
        minimum_start = start if minimum_start is None else min(minimum_start, start)
        maximum_end = end if maximum_end is None else max(maximum_end, end)
    if rows == 0:
        errors.append("capture contains no feature-window rows")
    if len(vector_sizes) > 1:
        errors.append(f"capture mixes vector sizes: {dict(vector_sizes)}")
    for pod, windows in windows_by_pod.items():
        ordered = sorted(windows)
        for previous, current in zip(ordered, ordered[1:]):
            if current[0] < previous[1]:
                errors.append(
                    f"line {current[2]}: overlapping window for {pod}"
                )
    return {
        "schema": "sentinel-feature-capture-validation/v1",
        "source": {"name": path.name, "sha256": sha256(path)},
        "feature_windows": rows,
        "non_feature_rows": non_feature_rows,
        "capture_modes": dict(sorted(modes.items())),
        "vector_sizes": dict(sorted(vector_sizes.items())),
        "pods": dict(sorted(pods.items())),
        "minimum_window_start": minimum_start,
        "maximum_window_end": maximum_end,
        "privacy_contract": {
            "arguments": False,
            "payloads": False,
            "file_contents": False,
            "network_contents": False,
        },
        "errors": errors,
        "valid": not errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = validate_capture(args.capture)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(args.output)
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
