"""Reorder baseline rows into deterministic train/holdout phase strata.

The model trainer keeps the final 20% as holdout. This utility places a fixed
20% sample from every declared operating phase at the end, preventing either
training or validation from containing only one load regime.
"""

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import numpy as np


TARGETS = ("default/postgres", "production/nginx", "production/redis")


def split_segment(start: int, length: int, count: int):
    # Evenly spaced positions, avoiding a random split that cannot be exactly
    # reproduced from the paper's dataset manifest.
    local = np.linspace(0, length - 1, num=count, dtype=int)
    validation = [start + int(index) for index in sorted(set(local))]
    validation_set = set(validation)
    train = [index for index in range(start, start + length)
             if index not in validation_set]
    return train, validation


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--segments", required=True,
        help="comma-separated phase lengths, e.g. 31,14,14,13",
    )
    parser.add_argument("--validation-fraction", type=float, default=0.20)
    args = parser.parse_args()

    source = Path(args.input).resolve()
    output = Path(args.output).resolve()
    segments = [int(item) for item in args.segments.split(",")]
    if any(length < 5 for length in segments):
        raise ValueError("each phase needs at least five windows")
    if not 0.05 <= args.validation_fraction <= 0.40:
        raise ValueError("validation fraction outside [0.05, 0.40]")
    if output.exists():
        raise FileExistsError(output)

    total_rows = sum(segments)
    target_validation = max(3, int(round(total_rows * args.validation_fraction)))
    raw_counts = [length * args.validation_fraction for length in segments]
    validation_counts = [max(1, int(value)) for value in raw_counts]
    # Largest-remainder allocation makes per-phase counts add up to the exact
    # holdout size expected by PodModelBundle.train.
    remaining = target_validation - sum(validation_counts)
    order = sorted(
        range(len(segments)),
        key=lambda index: raw_counts[index] - int(raw_counts[index]),
        reverse=True,
    )
    if remaining < 0:
        order = list(reversed(order))
    for index in order[:abs(remaining)]:
        validation_counts[index] += 1 if remaining > 0 else -1

    train_indexes, validation_indexes, phases = [], [], []
    offset = 0
    for phase_id, (length, validation_count) in enumerate(
        zip(segments, validation_counts)
    ):
        train, validation = split_segment(
            offset, length, validation_count
        )
        train_indexes.extend(train)
        validation_indexes.extend(validation)
        phases.append({
            "phase": phase_id,
            "start": offset,
            "length": length,
            "validation_count": validation_count,
            "train_indexes": train,
            "validation_indexes": validation,
        })
        offset += length

    staging = output.with_name(f".{output.name}.staging-{os.getpid()}")
    staging.mkdir(parents=True, exist_ok=False)
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": str(source),
        "segments": segments,
        "validation_fraction": args.validation_fraction,
        "train_count": len(train_indexes),
        "validation_count": len(validation_indexes),
        "phases": phases,
        "row_order": train_indexes + validation_indexes,
    }
    expected_validation = target_validation
    if len(validation_indexes) != expected_validation:
        raise ValueError(
            f"stratified holdout has {len(validation_indexes)} rows but trainer "
            f"expects {expected_validation}; adjust segment boundaries"
        )

    for pod_key in TARGETS:
        filename = f"{pod_key.replace('/', '__')}.npy"
        array = np.load(source / filename, allow_pickle=False)
        if len(array) != offset:
            raise ValueError(
                f"{pod_key}: segments total {offset}, data has {len(array)}"
            )
        reordered = array[train_indexes + validation_indexes]
        np.save(staging / filename, reordered.astype(np.float32, copy=False))
    (staging / "stratification_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    os.replace(staging, output)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
