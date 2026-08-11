"""Fit one pooled V7 model from the frozen candidate-fit run only.

This is a paper ablation, never a promotion path.  It pools the already frozen
per-workload training partitions before the already frozen per-workload
development partitions.  Independent normal runs and blind attacks are never
opened by this program.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
import platform
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import sklearn
import torch

from ml_models import ModelManager, PodModelBundle, SharedWorkloadModelManager
from train_candidate import file_sha256, train_one


def directory_hashes(directory: Path) -> dict[str, str]:
    return {
        path.name: file_sha256(path)
        for path in sorted(directory.iterdir()) if path.is_file()
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fit-dataset", type=Path, required=True)
    parser.add_argument("--reference-candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--epochs", type=int, default=200)
    parser.add_argument("--batch-size", type=int, default=64)
    args = parser.parse_args()
    if args.epochs < 1 or args.batch_size < 1:
        raise ValueError("epochs and batch size must be positive")

    fit_dataset = args.fit_dataset.resolve()
    reference = args.reference_candidate.resolve()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(output)
    manifest_path = fit_dataset / "phase_dataset_manifest.json"
    vocab_path = fit_dataset / "vocab.pkl"
    manifest = json.loads(manifest_path.read_text())
    reference_report_path = reference / "training_report.json"
    reference_report = json.loads(reference_report_path.read_text())
    if manifest.get("dataset_role") != "candidate_fit":
        raise ValueError("shared model may only fit candidate_fit data")
    if reference_report.get("accepted_offline") is not True:
        raise ValueError("reference per-workload candidate was not accepted")
    if reference_report.get("dataset_manifest_sha256") != file_sha256(manifest_path):
        raise ValueError("reference candidate used a different fit dataset")
    targets = list(manifest.get("target_order", []))
    if not targets or set(manifest.get("targets", {})) != set(targets):
        raise ValueError("fit dataset target contract is invalid")

    with vocab_path.open("rb") as handle:
        vocab = pickle.load(handle)
    reference_manager = ModelManager(str(reference), str(reference / "vocab.pkl"))
    reference_manager.load_all()
    if set(reference_manager.list_models()) != set(targets):
        raise ValueError("reference model target set differs from fit dataset")

    train_parts, validation_parts = [], []
    train_startup, validation_startup, validation_events = [], [], []
    source_arrays = {}
    for target in targets:
        spec = manifest["targets"][target]
        path = fit_dataset / f"{target.replace('/', '__')}.npy"
        array = np.load(path, allow_pickle=False)
        if list(array.shape) != spec.get("shape") or file_sha256(path) != spec.get("sha256"):
            raise ValueError(f"{target}: frozen fit array mismatch")
        train_count = int(spec["train_count"])
        validation_count = int(spec["validation_count"])
        if train_count + validation_count != len(array):
            raise ValueError(f"{target}: invalid frozen development split")
        train_parts.append(array[:train_count])
        validation_parts.append(array[train_count:])
        startup = spec.get("startup_grace", {})
        train_startup.extend(startup.get("train_mask", []))
        validation_startup.extend(startup.get("validation_mask", []))
        validation_events.extend(spec.get("validation_event_counts", []))
        source_arrays[target] = {
            "path": str(path), "sha256": file_sha256(path),
            "train_count": train_count, "validation_count": validation_count,
        }

    pooled = np.concatenate(train_parts + validation_parts).astype(np.float32, copy=False)
    train_count = sum(len(item) for item in train_parts)
    validation_count = sum(len(item) for item in validation_parts)
    if (
        pooled.ndim != 2 or pooled.shape[1] != len(vocab)
        or train_count + validation_count != len(pooled)
        or len(train_startup) != train_count
        or len(validation_startup) != validation_count
        or len(validation_events) != validation_count
    ):
        raise ValueError("pooled fit split is not row aligned")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    staging = output.with_name(f".{output.name}.staging-{stamp}")
    staging.mkdir(parents=True, exist_ok=False)
    try:
        with tempfile.TemporaryDirectory(prefix="sentinel-shared-fit-") as temp:
            pooled_path = Path(temp) / "shared__workload.npy"
            np.save(pooled_path, pooled)
            pooled_spec = {
                "shape": list(pooled.shape),
                "sha256": file_sha256(pooled_path),
                "train_count": train_count,
                "validation_count": validation_count,
                "validation_event_counts": [int(value) for value in validation_events],
                "startup_grace": {
                    "seconds": float(manifest.get("startup_grace_seconds", 0.0)),
                    "train_mask": [bool(value) for value in train_startup],
                    "validation_mask": [bool(value) for value in validation_startup],
                    "validation_count": int(sum(validation_startup)),
                },
            }
            model_report = train_one(
                SharedWorkloadModelManager.SHARED_MODEL_KEY,
                pooled_path, staging, vocab, args.epochs, args.batch_size,
                PodModelBundle.MODEL_VERSION, pooled_spec,
            )

        behavior_limits = {
            target: dict(reference_manager.get_model(target).behavior_limits)
            for target in targets
        }
        behavior_doc = {
            "schema": SharedWorkloadModelManager.ROUTING_SCHEMA,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_candidate_sha256": directory_hashes(reference),
            "workloads": behavior_limits,
        }
        (staging / "workload_behavior_limits.json").write_text(
            json.dumps(behavior_doc, indent=2, sort_keys=True) + "\n"
        )
        shutil.copy2(vocab_path, staging / "vocab.pkl")
        shutil.copy2(manifest_path, staging / "dataset_manifest.json")
        report = {
            "schema": "sentinel-shared-workload-training/v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "python": platform.python_version(),
            "numpy": np.__version__, "torch": torch.__version__,
            "sklearn": sklearn.__version__,
            "model_routing": "shared_workload",
            "shared_model_key": SharedWorkloadModelManager.SHARED_MODEL_KEY,
            "targets": targets,
            "dataset_role": "candidate_fit",
            "split_semantics": manifest.get("split_semantics"),
            "dataset_manifest_sha256": file_sha256(manifest_path),
            "bundled_dataset_manifest_sha256": file_sha256(staging / "dataset_manifest.json"),
            "bundled_vocab_sha256": file_sha256(staging / "vocab.pkl"),
            "reference_candidate": str(reference),
            "reference_candidate_sha256": directory_hashes(reference),
            "pooled_rows": len(pooled),
            "pooled_train_count": train_count,
            "pooled_validation_count": validation_count,
            "source_arrays": source_arrays,
            "labels_used_for_training_or_tuning": False,
            "independent_evaluation_rows_used": False,
            "attack_rows_used": False,
            "models": {SharedWorkloadModelManager.SHARED_MODEL_KEY: model_report},
            "accepted_offline": bool(model_report["accepted_offline"]),
            "source_files": {
                name: file_sha256(Path(__file__).resolve().with_name(name))
                for name in ("train_shared_workload_candidate.py", "train_candidate.py", "ml_models.py")
            },
        }
        (staging / "training_report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n"
        )
        os.replace(staging, output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    print(json.dumps({
        "output": str(output), "accepted_offline": report["accepted_offline"],
        "pooled_rows": len(pooled), "targets": len(targets),
    }, indent=2, sort_keys=True))
    return 0 if report["accepted_offline"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
