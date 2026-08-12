"""Validate privacy and integrity of paired feature-window replay evidence."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path

from feature_capture_io import (
    FEATURE_SCHEMA, FEATURE_SCHEMA_V3, IDENTITY_FIELDS, INJECTION_SCHEMA,
    validate_v3_identity,
)


FEATURE_KEYS = {
    "kind", "ts", "schema", "pod_key", "model_key", "node_name",
    "window_start", "window_end", "event_count", "vector_size",
    "sparse_vector", "syscall_counts", "contains_arguments_or_payloads",
    "capture_mode", "syscall_sequence",
    "release_id", "run_id", "phase_id", "traffic_regime",
    "cluster_id", "workload_image_digest", "workload_version_id",
}
INJECTION_START_KEYS = {
    "kind", "ts", "schema", "injection_id", "pod_key", "attack_type",
    "rate", "seed",
    "release_id", "run_id", "phase_id", "traffic_regime",
}
INJECTION_END_KEYS = {
    "kind", "ts", "schema", "injection_id", "pod_key", "attack_type",
    "attack_exit_code",
    "release_id", "run_id", "phase_id", "traffic_regime",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_feature_row(row: dict, line_number: int) -> list[str]:
    prefix = f"line {line_number}"
    errors = []
    unknown = sorted(set(row) - FEATURE_KEYS)
    if unknown:
        errors.append(f"{prefix}: unexpected/privacy-unsafe keys: {unknown}")
    schema = row.get("schema")
    if schema not in (FEATURE_SCHEMA, FEATURE_SCHEMA_V3):
        errors.append(f"{prefix}: schema mismatch")
    identity_keys = IDENTITY_FIELDS & set(row)
    if schema == FEATURE_SCHEMA_V3:
        try:
            validate_v3_identity({key: row.get(key) for key in IDENTITY_FIELDS})
        except ValueError as exc:
            errors.append(f"{prefix}: {exc}")
    elif identity_keys:
        errors.append(f"{prefix}: V2 row unexpectedly carries V3 identity")
    if row.get("capture_mode") not in ("aggregate", "sequence"):
        errors.append(f"{prefix}: invalid capture mode")
    if row.get("contains_arguments_or_payloads") is not False:
        errors.append(f"{prefix}: privacy exclusion is not explicit")
    for key in (
        "pod_key", "model_key", "node_name", "release_id", "run_id",
        "phase_id", "traffic_regime",
    ):
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


def validate_injection_row(row: dict, line_number: int) -> list[str]:
    prefix = f"line {line_number}"
    kind = row.get("kind")
    allowed = (
        INJECTION_START_KEYS if kind == "injection" else INJECTION_END_KEYS
    )
    errors = []
    unknown = sorted(set(row) - allowed)
    missing = sorted(allowed - set(row))
    if unknown:
        errors.append(f"{prefix}: unexpected/privacy-unsafe keys: {unknown}")
    if missing:
        errors.append(f"{prefix}: missing injection keys: {missing}")
    if row.get("schema") != INJECTION_SCHEMA:
        errors.append(f"{prefix}: injection schema mismatch")
    for key in (
        "injection_id", "pod_key", "attack_type", "release_id", "run_id",
        "phase_id", "traffic_regime",
    ):
        if not isinstance(row.get(key), str) or not row[key]:
            errors.append(f"{prefix}: invalid {key}")
    try:
        timestamp = float(row["ts"])
        if not math.isfinite(timestamp) or timestamp <= 0:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        errors.append(f"{prefix}: invalid injection timestamp")
    if kind == "injection":
        if not isinstance(row.get("rate"), int) or row["rate"] <= 0:
            errors.append(f"{prefix}: invalid injection rate")
        if not isinstance(row.get("seed"), int):
            errors.append(f"{prefix}: invalid injection seed")
    elif not isinstance(row.get("attack_exit_code"), int):
        errors.append(f"{prefix}: invalid attack exit code")
    return errors


def validate_capture(path: Path) -> dict:
    errors = []
    rows = 0
    non_feature_rows = 0
    injection_rows = 0
    injection_intervals = 0
    modes = Counter()
    vector_sizes = Counter()
    pods = Counter()
    releases = Counter()
    runs = Counter()
    phases = Counter()
    regimes = Counter()
    schemas = Counter()
    clusters = Counter()
    image_digests = Counter()
    workload_versions = Counter()
    windows_by_pod = defaultdict(list)
    seen = set()
    injection_starts = {}
    minimum_start = None
    maximum_end = None
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        try:
            row = json.loads(line)
        except (TypeError, ValueError):
            errors.append(f"line {line_number}: invalid JSON")
            continue
        if not isinstance(row, dict):
            errors.append(f"line {line_number}: JSON row must be an object")
            continue
        kind = row.get("kind")
        if kind in ("injection", "injection_end"):
            injection_rows += 1
            non_feature_rows += 1
            errors.extend(validate_injection_row(row, line_number))
            injection_id = row.get("injection_id")
            if kind == "injection" and isinstance(injection_id, str):
                if injection_id in injection_starts:
                    errors.append(
                        f"line {line_number}: duplicate injection start: {injection_id}"
                    )
                else:
                    injection_starts[injection_id] = (row, line_number)
            elif kind == "injection_end" and isinstance(injection_id, str):
                start_item = injection_starts.pop(injection_id, None)
                if start_item is None:
                    errors.append(
                        f"line {line_number}: injection end without start: {injection_id}"
                    )
                else:
                    start, _ = start_item
                    try:
                        consistent = (
                            row.get("pod_key") == start.get("pod_key")
                            and row.get("attack_type") == start.get("attack_type")
                            and row.get("release_id") == start.get("release_id")
                            and row.get("run_id") == start.get("run_id")
                            and row.get("phase_id") == start.get("phase_id")
                            and row.get("traffic_regime")
                            == start.get("traffic_regime")
                            and float(row["ts"]) > float(start["ts"])
                        )
                    except (KeyError, TypeError, ValueError):
                        consistent = False
                    if not consistent:
                        errors.append(
                            f"line {line_number}: inconsistent injection interval: "
                            f"{injection_id}"
                        )
                    else:
                        injection_intervals += 1
            continue
        if kind != "feature_window":
            non_feature_rows += 1
            errors.append(
                f"line {line_number}: unsupported/privacy-unsafe row kind: {kind!r}"
            )
            continue
        rows += 1
        errors.extend(validate_feature_row(row, line_number))
        modes[str(row.get("capture_mode"))] += 1
        vector_sizes[str(row.get("vector_size"))] += 1
        pod = str(row.get("pod_key"))
        pods[pod] += 1
        releases[str(row.get("release_id"))] += 1
        runs[str(row.get("run_id"))] += 1
        phases[str(row.get("phase_id"))] += 1
        regimes[str(row.get("traffic_regime"))] += 1
        schemas[str(row.get("schema"))] += 1
        if row.get("schema") == FEATURE_SCHEMA_V3:
            clusters[str(row.get("cluster_id"))] += 1
            image_digests[str(row.get("workload_image_digest"))] += 1
            workload_versions[str(row.get("workload_version_id"))] += 1
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
    if injection_starts:
        errors.append(
            f"injection starts without end: {sorted(injection_starts)}"
        )
    if len(vector_sizes) > 1:
        errors.append(f"capture mixes vector sizes: {dict(vector_sizes)}")
    if len(releases) > 1:
        errors.append(f"capture mixes release IDs: {dict(releases)}")
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
        "injection_rows": injection_rows,
        "injection_intervals": injection_intervals,
        "capture_modes": dict(sorted(modes.items())),
        "vector_sizes": dict(sorted(vector_sizes.items())),
        "pods": dict(sorted(pods.items())),
        "release_ids": dict(sorted(releases.items())),
        "run_ids": dict(sorted(runs.items())),
        "phase_ids": dict(sorted(phases.items())),
        "traffic_regimes": dict(sorted(regimes.items())),
        "feature_schemas": dict(sorted(schemas.items())),
        "cluster_ids": dict(sorted(clusters.items())),
        "workload_image_digests": dict(sorted(image_digests.items())),
        "workload_version_ids": dict(sorted(workload_versions.items())),
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
