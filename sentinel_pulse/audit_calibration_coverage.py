"""Audit conformal calibration capacity before fitting Pulse models."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from .integrity import sha256_file
from .model import PulseExtraTrees
from .train import load_sequences


def audit(
    dataset: Path,
    history: int,
    alpha: float,
    window_seconds: float,
    train_fraction: float = 0.7,
) -> dict:
    if window_seconds not in (0.5, 1.0):
        raise ValueError("window_seconds must be 0.5 or 1.0")
    if not 0.0 < train_fraction < 1.0:
        raise ValueError("train_fraction must be between zero and one")
    model = PulseExtraTrees(history=history, alpha=alpha)
    sequences, columns = load_sequences(
        dataset, maximum_gap_seconds=window_seconds * 2.5
    )
    workloads = {}
    for workload, items in sorted(sequences.items()):
        rows = sum(len(item) for item in items)
        try:
            train_x, _, calibration_x, _, feature_dim = model._split_sequences(
                items, train_fraction
            )
            calibration_examples = int(len(calibration_x))
            eligible = calibration_examples >= model.minimum_calibration_examples
            workloads[workload] = {
                "status": "eligible" if eligible else "insufficient-calibration",
                "rows": rows,
                "sequences": len(items),
                "feature_dim": feature_dim,
                "train_examples": int(len(train_x)),
                "calibration_examples": calibration_examples,
                "minimum_calibration_examples": model.minimum_calibration_examples,
                "calibration_margin": (
                    calibration_examples - model.minimum_calibration_examples
                ),
            }
        except ValueError as error:
            workloads[workload] = {
                "status": "unusable",
                "rows": rows,
                "sequences": len(items),
                "calibration_examples": 0,
                "minimum_calibration_examples": model.minimum_calibration_examples,
                "calibration_margin": -model.minimum_calibration_examples,
                "reason": str(error),
            }
    eligible = sum(item["status"] == "eligible" for item in workloads.values())
    return {
        "schema": "sentinel-pulse-calibration-coverage-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset": str(dataset),
        "dataset_sha256": sha256_file(dataset),
        "history_windows": history,
        "alpha": alpha,
        "window_seconds": window_seconds,
        "train_fraction": train_fraction,
        "feature_columns": len(columns),
        "minimum_calibration_examples": model.minimum_calibration_examples,
        "workload_count": len(workloads),
        "eligible_workloads": eligible,
        "all_workloads_eligible": bool(workloads) and eligible == len(workloads),
        "workloads": workloads,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--history", type=int, default=3)
    parser.add_argument("--alpha", type=float, default=0.001)
    parser.add_argument(
        "--window-seconds", type=float, choices=(0.5, 1.0), default=0.5
    )
    parser.add_argument("--train-fraction", type=float, default=0.7)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit(
        args.dataset,
        args.history,
        args.alpha,
        args.window_seconds,
        args.train_fraction,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not report["all_workloads_eligible"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
