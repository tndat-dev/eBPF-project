"""Train an isolated, reproducible model candidate and emit an audit report.

Production models are never overwritten by this command. Only the three
explicit deployment baselines are accepted; load-generator files cannot become
models accidentally.
"""

import argparse
import hashlib
import json
import logging
import os
import pickle
import platform
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import sklearn
import torch

from adaptive_threshold import POTThreshold
from graph_signals import (BEHAVIOR_SYSCALLS, evaluate_behavior,
                           fit_behavior_limits)
from ml_models import PodModelBundle


TARGETS = ("default/postgres", "production/nginx", "production/redis")
SUSPICIOUS = (
    "execve", "execveat", "clone", "clone3", "unshare", "mount",
    "ptrace", "setuid", "setgid", "capset", "connect",
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def quantiles(values, score_metric: bool = False) -> dict:
    x = np.asarray(values, dtype=float)
    result = {
        "count": int(x.size),
        "min": float(np.min(x)),
        "median": float(np.median(x)),
        "p95": float(np.quantile(x, 0.95)),
        "p99": float(np.quantile(x, 0.99)),
        "max": float(np.max(x)),
    }
    if score_metric:
        result["saturated_fraction"] = float(np.mean(x >= 0.995))
    return result


def holdout_actionable_pairs(X: np.ndarray, scores, threshold: float,
                             vocab: dict, behavior_limits: dict
                             ) -> tuple[int, list, list]:
    indexes = [vocab[name] for name in SUSPICIOUS if name in vocab]
    masses = np.sum(X[:, indexes], axis=1) if indexes else np.zeros(len(X))
    evidence = []
    for row in X:
        frequencies = {
            name: float(row[vocab[name]])
            for name in BEHAVIOR_SYSCALLS if name in vocab
        }
        evidence.append(evaluate_behavior(frequencies, 1, behavior_limits))
    candidates = [
        bool(score >= threshold and item["gate"])
        for score, item in zip(scores, evidence)
    ]
    pairs = sum(a and b for a, b in zip(candidates, candidates[1:]))
    return int(pairs), [float(x) for x in masses], evidence


def train_one(pod_key: str, data_path: Path, output_dir: Path, vocab: dict,
              epochs: int, model_version: int, dataset_spec: dict) -> dict:
    X = np.load(data_path, allow_pickle=False)
    if X.ndim != 2 or X.shape[1] != len(vocab):
        raise ValueError(
            f"{pod_key}: expected (n,{len(vocab)}) data, found {X.shape}"
        )
    if len(X) < 30 or not np.isfinite(X).all():
        raise ValueError(f"{pod_key}: baseline must contain >=30 finite windows")
    dataset_digest = file_sha256(data_path)
    if list(X.shape) != dataset_spec.get("shape"):
        raise ValueError(f"{pod_key}: dataset shape does not match manifest")
    if dataset_digest != dataset_spec.get("sha256"):
        raise ValueError(f"{pod_key}: dataset hash does not match manifest")
    expected_train = int(dataset_spec.get("train_count", -1))
    expected_validation = int(dataset_spec.get("validation_count", -1))
    trainer_validation = max(3, int(round(len(X) * 0.20)))
    trainer_validation = min(trainer_validation, len(X) - 2)
    if (
        expected_train + expected_validation != len(X)
        or expected_validation != trainer_validation
        or expected_train != len(X) - trainer_validation
    ):
        raise ValueError(
            f"{pod_key}: manifest split {expected_train}/{expected_validation} "
            f"does not match trainer split {len(X) - trainer_validation}/"
            f"{trainer_validation}"
        )

    model = PodModelBundle(
        pod_key=pod_key, input_dim=X.shape[1], model_version=model_version,
    )
    started = time.perf_counter()
    history = model.train(X, epochs=epochs)
    train_seconds = time.perf_counter() - started

    n_val = len(model.validation_scores)
    train_rows = X[:-n_val]
    holdout = X[-n_val:]
    model.behavior_limits = fit_behavior_limits(train_rows, vocab)
    model.save(str(output_dir))
    threshold = POTThreshold(minimum=model.ANOMALY_THRESHOLD).fit(
        model.baseline_scores
    )
    actionable_pairs, suspicious_masses, behavior_evidence = holdout_actionable_pairs(
        holdout, model.validation_scores, threshold, vocab,
        model.behavior_limits,
    )

    timings = []
    timing_rows = holdout[np.arange(max(200, len(holdout))) % len(holdout)]
    for row in timing_rows:
        tic = time.perf_counter()
        model.predict(row)
        timings.append((time.perf_counter() - tic) * 1000.0)

    holdout_summary = quantiles(model.validation_scores, score_metric=True)
    score_exceedance_fraction = float(
        np.mean(np.asarray(model.validation_scores) >= model.ANOMALY_THRESHOLD)
    )
    behavior_gate_count = sum(item["gate"] for item in behavior_evidence)
    behavior_max_ratio = max(
        (float(item["max_ratio"]) for item in behavior_evidence), default=0.0
    )
    accepted = bool(
        actionable_pairs == 0
        and behavior_gate_count == 0
        and holdout_summary["median"] <= 0.50
        and holdout_summary["p95"] <= model.ANOMALY_THRESHOLD
        and score_exceedance_fraction <= 0.10
        and holdout_summary["saturated_fraction"] <= 0.25
        and np.isfinite(history["val_loss"][-1])
    )
    return {
        "pod_key": pod_key,
        "dataset": str(data_path),
        "dataset_sha256": dataset_digest,
        "shape": list(X.shape),
        "model_version": model.model_version,
        "seed": model.seed,
        "epochs_completed": len(history["val_loss"]),
        "best_validation_loss": float(np.min(history["val_loss"])),
        "last_validation_loss": float(history["val_loss"][-1]),
        "training_seconds": train_seconds,
        "threshold": threshold,
        "train_scores": quantiles(model.baseline_scores, score_metric=True),
        "holdout_scores": holdout_summary,
        "holdout_score_exceedance_fraction": score_exceedance_fraction,
        "holdout_suspicious_mass": quantiles(suspicious_masses),
        "behavior_limits": model.behavior_limits,
        "holdout_behavior_gate_count": int(behavior_gate_count),
        "holdout_behavior_max_ratio": behavior_max_ratio,
        "holdout_actionable_pairs": actionable_pairs,
        "inference_ms": quantiles(timings),
        "accepted_offline": accepted,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--training-dir", default="training_data_candidate")
    parser.add_argument("--model-dir", default="models_candidate")
    parser.add_argument("--vocab", default="vocab.pkl")
    parser.add_argument("--epochs", type=int, default=200)
    parser.add_argument("--model-version", type=int,
                        default=PodModelBundle.MODEL_VERSION)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    training_dir = Path(args.training_dir).resolve()
    model_dir = Path(args.model_dir).resolve()
    vocab_path = Path(args.vocab).resolve()
    dataset_manifest_path = training_dir / "phase_dataset_manifest.json"
    if args.model_version >= 7 and not dataset_manifest_path.is_file():
        raise FileNotFoundError(
            f"V7 requires a phase dataset manifest: {dataset_manifest_path}"
        )
    dataset_manifest = (
        json.loads(dataset_manifest_path.read_text())
        if dataset_manifest_path.is_file() else {"targets": {}}
    )
    with vocab_path.open("rb") as handle:
        vocab = pickle.load(handle)
    if args.model_version >= 7:
        if dataset_manifest.get("vocabulary", {}).get(
            "output_sha256"
        ) != file_sha256(vocab_path):
            raise ValueError("training vocabulary does not match dataset manifest")
        if set(dataset_manifest.get("targets", {})) != set(TARGETS):
            raise ValueError("dataset manifest target set is not exact")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    staging = model_dir.with_name(f".{model_dir.name}.staging-{stamp}")
    staging.mkdir(parents=True, exist_ok=False)
    report = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "numpy": np.__version__,
        "torch": torch.__version__,
        "sklearn": sklearn.__version__,
        "vocab": str(vocab_path),
        "vocab_sha256": file_sha256(vocab_path),
        "model_version_requested": args.model_version,
        "dataset_manifest": (
            str(dataset_manifest_path) if dataset_manifest_path.is_file() else None
        ),
        "dataset_manifest_sha256": (
            file_sha256(dataset_manifest_path)
            if dataset_manifest_path.is_file() else None
        ),
        "source_files": {
            name: file_sha256(Path(__file__).resolve().with_name(name))
            for name in (
                "train_candidate.py", "ml_models.py", "adaptive_threshold.py",
                "graph_signals.py", "build_phase_dataset.py",
            )
        },
        "models": {},
    }

    try:
        for pod_key in TARGETS:
            path = training_dir / f"{pod_key.replace('/', '__')}.npy"
            if not path.is_file():
                raise FileNotFoundError(f"missing target baseline: {path}")
            report["models"][pod_key] = train_one(
                pod_key, path, staging, vocab, args.epochs, args.model_version,
                dataset_manifest["targets"][pod_key],
            )

        report["accepted_offline"] = all(
            item["accepted_offline"] for item in report["models"].values()
        )
        # A release must carry the exact feature mapping used during training.
        # Keeping it beside the checkpoints makes validation, promotion and
        # rollback dimension-safe instead of depending on mutable global state.
        bundled_vocab = staging / "vocab.pkl"
        shutil.copy2(vocab_path, bundled_vocab)
        report["bundled_vocab_sha256"] = file_sha256(bundled_vocab)
        if dataset_manifest_path.is_file():
            bundled_dataset_manifest = staging / "dataset_manifest.json"
            shutil.copy2(dataset_manifest_path, bundled_dataset_manifest)
            report["bundled_dataset_manifest_sha256"] = file_sha256(
                bundled_dataset_manifest
            )
        (staging / "training_report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n"
        )

        if model_dir.exists():
            backup = model_dir.with_name(f"{model_dir.name}.previous-{stamp}")
            os.replace(model_dir, backup)
            report["previous_candidate"] = str(backup)
        os.replace(staging, model_dir)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["accepted_offline"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
