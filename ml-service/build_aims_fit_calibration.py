"""Build frozen runtime calibration from candidate-fit rows only.

This is a deployment state artifact, not an evaluation result. Validation and
blind trials must consume the same resulting hash and may never update it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from adaptive_threshold import StreamingThreshold, load_thresholds, save_calibrators
from graph_signals import evaluate_behavior
from ml_models import ModelManager


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--minimum-events", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--extreme-volume-factor", type=float, default=2.0)
    args = parser.parse_args()
    candidate = args.candidate.resolve()
    output = args.output.resolve()
    report_path = args.report.resolve()
    if output.exists() or report_path.exists():
        raise FileExistsError("refusing to replace frozen calibration artifact")

    training_path = candidate / "training_report.json"
    dataset_path = candidate / "dataset_manifest.json"
    training = json.loads(training_path.read_text())
    dataset = json.loads(dataset_path.read_text())
    if training.get("accepted_offline") is not True:
        raise ValueError("candidate did not pass development gate")
    if training.get("dataset_role") != "candidate_fit":
        raise ValueError("calibration source is not candidate_fit")
    if dataset.get("dataset_role") != "candidate_fit":
        raise ValueError("dataset manifest role mismatch")

    manager = ModelManager(str(candidate), str(candidate / "vocab.pkl"))
    manager.load_all()
    thresholds = load_thresholds(manager, minimum=0.80)
    calibrators = {
        target: StreamingThreshold(
            minimum=0.80, warmup=args.warmup,
            event_ceiling_factor=args.extreme_volume_factor,
        )
        for target in manager.list_models()
    }
    targets_report = {}
    for target in manager.list_models():
        target_spec = dataset["targets"][target]
        considered = accepted = startup_skipped = behavior_skipped = 0
        for phase in target_spec["phases"]:
            phase_dir = Path(phase["phase"])
            stem = target.replace("/", "__")
            array_path = phase_dir / f"{stem}.npy"
            metadata_path = phase_dir / f"{stem}_metadata.jsonl"
            if sha256(array_path) != phase["array_sha256"]:
                raise ValueError(f"{target}: fit array digest mismatch")
            if sha256(metadata_path) != phase["metadata_sha256"]:
                raise ValueError(f"{target}: fit metadata digest mismatch")
            array = np.load(array_path, allow_pickle=False)
            metadata = read_jsonl(metadata_path)
            if len(array) != len(metadata):
                raise ValueError(f"{target}: fit metadata alignment mismatch")
            for source_index in phase["source_indexes"]:
                vector = array[int(source_index)]
                row = metadata[int(source_index)]
                considered += 1
                event_count = int(row["event_count"])
                if event_count < args.minimum_events:
                    continue
                if row.get("startup_grace_eligible") is True:
                    startup_skipped += 1
                    continue
                result = manager.score(target, vector)
                behavior = evaluate_behavior(
                    row.get("syscall_counts", {}), event_count,
                    result.get("behavior_limits", {}),
                )
                if behavior["gate"] or float(result["ensemble_score"]) >= thresholds[target]:
                    behavior_skipped += 1
                    continue
                # Only the bounded final state is persisted. Appending first
                # and fitting once is mathematically identical to the final
                # StreamingThreshold state, while avoiding thousands of
                # repeated GPD fits during artifact construction.
                calibrators[target].scores.append(float(result["ensemble_score"]))
                calibrators[target].event_counts.append(event_count)
                accepted += 1
        calibrators[target].current = calibrators[target].estimator.fit(
            list(calibrators[target].scores)
        )
        if not calibrators[target].ready or not calibrators[target].event_guard_ready:
            raise ValueError(f"{target}: insufficient clean fit calibration rows")
        targets_report[target] = {
            "considered": considered,
            "accepted_clean": accepted,
            "startup_skipped": startup_skipped,
            "behavior_or_score_skipped": behavior_skipped,
            "retained_scores": len(calibrators[target].scores),
            "retained_event_counts": len(calibrators[target].event_counts),
            "threshold": thresholds[target],
            "streaming_threshold": calibrators[target].current,
            "minimum_event_count": calibrators[target].minimum_event_count,
            "maximum_event_count": calibrators[target].maximum_event_count,
        }

    output.parent.mkdir(parents=True, exist_ok=True)
    save_calibrators(output, calibrators)
    report = {
        "schema": "sentinel-aims-fit-calibration/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_role": "candidate_fit",
        "evaluation_data_used": False,
        "candidate": str(candidate),
        "training_report_sha256": sha256(training_path),
        "dataset_manifest_sha256": sha256(dataset_path),
        "calibration": str(output),
        "calibration_sha256": sha256(output),
        "minimum_events": args.minimum_events,
        "warmup": args.warmup,
        "extreme_volume_factor": args.extreme_volume_factor,
        "targets": targets_report,
    }
    temporary = report_path.with_suffix(report_path.suffix + f".tmp-{os.getpid()}")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    temporary.replace(report_path)
    print(json.dumps({
        "calibration": str(output), "sha256": report["calibration_sha256"],
        "targets": len(targets_report),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
