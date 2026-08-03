"""Replay frozen AIMS normal splits through the production detector path.

The evaluator never trains, tunes, promotes, or changes the live detector. It
accepts only run roles frozen before candidate fitting and returns a distinct
"waiting_for_phases" status while the required evidence is incomplete.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

import anomaly_detector2
from adaptive_threshold import load_thresholds
from aims_matrix_validation import validate_matrix
from build_phase_dataset import phase_role_contract
from feature_engineering import FeatureVector
from ml_models import ModelManager


EVALUATION_ROLES = ("independent_validation", "blind_normal_test")
NON_ELIGIBLE_DECISIONS = {
    "calibrating", "low_event_skip", "collection_quality_skip",
    "pod_startup_grace",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def quantiles(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0}
    array = np.asarray(values, dtype=float)
    return {
        "count": int(array.size),
        "min": float(np.min(array)),
        "median": float(np.median(array)),
        "p95": float(np.quantile(array, 0.95)),
        "p99": float(np.quantile(array, 0.99)),
        "max": float(np.max(array)),
    }


def candidate_hashes(candidate: Path) -> dict[str, str]:
    files = sorted(path for path in candidate.iterdir() if path.is_file())
    if not files:
        raise ValueError(f"candidate contains no files: {candidate}")
    return {path.name: sha256(path) for path in files}


def provenance_sets(dataset_manifest: dict[str, Any]) -> dict[str, set[str]]:
    result = {
        "vocabulary": set(),
        "tetragon_policy": set(),
        "loadgen_manifest": set(),
    }
    for source in dataset_manifest.get("source_manifests", []):
        vocabulary = source.get("vocabulary") or {}
        artifacts = source.get("experiment_artifacts") or {}
        values = {
            "vocabulary": vocabulary.get("sha256"),
            "tetragon_policy": (artifacts.get("tetragon_policy") or {}).get("sha256"),
            "loadgen_manifest": (artifacts.get("loadgen_manifest") or {}).get("sha256"),
        }
        for name, value in values.items():
            if value:
                result[name].add(str(value))
    return result


def validate_blind_prerequisite(
    report_path: Path | None,
    expected_candidate_hashes: dict[str, str],
    expected_calibration_sha256: str,
) -> dict[str, Any]:
    if report_path is None:
        raise ValueError("blind normal test requires --prerequisite-report")
    report = json.loads(report_path.read_text())
    if report.get("role") != "independent_validation" or report.get("passed") is not True:
        raise ValueError("blind prerequisite is not a passed independent validation")
    if report.get("candidate_sha256") != expected_candidate_hashes:
        raise ValueError("blind prerequisite evaluated a different candidate")
    if report.get("initial_calibration_sha256") != expected_calibration_sha256:
        raise ValueError("blind prerequisite used a different calibration")
    return {"path": str(report_path.resolve()), "sha256": sha256(report_path)}


def load_phase_rows(
    phase_dir: Path,
    targets: list[str],
    vocab_size: int,
) -> tuple[list[tuple[float, str, np.ndarray, dict[str, Any]]], dict[str, Any]]:
    manifest_path = phase_dir / "collection_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    rows: list[tuple[float, str, np.ndarray, dict[str, Any]]] = []
    target_digests: dict[str, dict[str, str]] = {}
    for target in targets:
        stem = target.replace("/", "__")
        array_path = phase_dir / f"{stem}.npy"
        metadata_path = phase_dir / f"{stem}_metadata.jsonl"
        array = np.load(array_path, allow_pickle=False)
        metadata = read_jsonl(metadata_path)
        if array.ndim != 2 or array.shape[1] != vocab_size:
            raise ValueError(f"{phase_dir.name}/{target}: invalid feature shape {array.shape}")
        if len(array) != len(metadata):
            raise ValueError(f"{phase_dir.name}/{target}: metadata is not row aligned")
        target_spec = manifest["targets"][target]
        if sha256(array_path) != target_spec.get("sha256"):
            raise ValueError(f"{phase_dir.name}/{target}: array digest mismatch")
        metadata_digest = sha256(metadata_path)
        if (
            target_spec.get("metadata_sha256")
            and metadata_digest != target_spec["metadata_sha256"]
        ):
            raise ValueError(f"{phase_dir.name}/{target}: metadata digest mismatch")
        target_digests[target] = {
            "array_sha256": sha256(array_path),
            "metadata_sha256": metadata_digest,
        }
        for vector, metadata_row in zip(array, metadata):
            if metadata_row.get("phase") != manifest.get("phase"):
                raise ValueError(f"{phase_dir.name}/{target}: metadata phase mismatch")
            if not np.isfinite(vector).all():
                raise ValueError(f"{phase_dir.name}/{target}: non-finite feature vector")
            rows.append((
                float(metadata_row["window_end"]), target,
                vector.astype(np.float32, copy=False), metadata_row,
            ))
    rows.sort(key=lambda item: (item[0], item[3]["pod_key"], item[1]))
    return rows, {
        "manifest": str(manifest_path.resolve()),
        "manifest_sha256": sha256(manifest_path),
        "row_count": len(rows),
        "target_digests": target_digests,
    }


def evaluate_phase(
    phase_dir: Path,
    targets: list[str],
    manager: ModelManager,
    minimum_events: int,
    startup_grace_seconds: float,
    warmup_windows: int,
    initial_calibration: Path,
) -> dict[str, Any]:
    rows, source = load_phase_rows(phase_dir, targets, manager.vocab_size)
    creation_times: dict[str, float] = {}
    for _, _, _, row in rows:
        created = row.get("pod_creation_timestamp")
        if created is not None:
            key = str(row["pod_key"])
            value = float(created)
            if key in creation_times and creation_times[key] != value:
                raise ValueError(f"{phase_dir.name}: inconsistent creation time for {key}")
            creation_times[key] = value

    emissions: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    old_emit = anomaly_detector2.emit
    with tempfile.TemporaryDirectory(prefix="aims-normal-replay-") as temporary:
        calibration_path = Path(temporary) / "calibration.json"
        shutil.copy2(initial_calibration, calibration_path)
        environment = {
            "SENTINEL_CALIBRATION": str(calibration_path),
            "SENTINEL_WARMUP_WINDOWS": str(warmup_windows),
            "SENTINEL_MIN_EVENTS": str(minimum_events),
            "SENTINEL_POD_STARTUP_GRACE_SECONDS": str(startup_grace_seconds),
            "SENTINEL_CONFIRMATION_FLOOR_RATIO": "1.0",
            "SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR": "0.80",
            "SENTINEL_FAST_PATH_CONFIRMATION_FLOOR": "0.80",
            "SENTINEL_EXTREME_VOLUME_FACTOR": "2.0",
        }
        previous = {key: os.environ.get(key) for key in environment}
        os.environ.update(environment)
        anomaly_detector2.emit = lambda kind, **payload: emissions.append(
            {"kind": kind, **payload}
        )
        detector = anomaly_detector2.AnomalyDetector(
            manager,
            on_alert=lambda alert: alerts.append(alert.to_dict()),
            threshold=0.80,
            cooldown_seconds=0,
            early_warning_lookup=lambda _pod: None,
            pod_started_at_lookup=lambda pod: creation_times.get(pod),
        )
        try:
            for _, _, vector, row in rows:
                event_count = int(row["event_count"])
                feature = FeatureVector(
                    pod_name=str(row["pod_key"]).split("/", 1)[1],
                    pod_namespace=str(row["pod_key"]).split("/", 1)[0],
                    node_name=str(row.get("node_name", "captured")),
                    window_start=float(row["window_start"]),
                    window_end=float(row["window_end"]),
                    vector=vector,
                    raw_syscalls=["captured-event"] * event_count,
                    syscall_counts={
                        str(name): int(count)
                        for name, count in row.get("syscall_counts", {}).items()
                    },
                )
                detector.handle_feature_vector(feature)
        finally:
            anomaly_detector2.emit = old_emit
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    inference = [row for row in emissions if row["kind"] == "inference"]
    decisions = [row for row in emissions if row["kind"] == "decision"]
    detections = [row for row in emissions if row["kind"] == "detection"]
    decision_counts = Counter(row.get("decision", "unknown") for row in decisions)
    by_workload: dict[str, dict[str, Any]] = {}
    for target in targets:
        target_inference = [row for row in inference if row.get("model_key") == target]
        target_detections = [row for row in detections if row.get("model_key") == target]
        by_workload[target] = {
            "windows": len(target_inference),
            "detections": len(target_detections),
            "scores": quantiles([float(row["score"]) for row in target_inference]),
            "inference_ms": quantiles([
                float(row["inference_ms"]) for row in target_inference
            ]),
        }
    eligible = sum(
        count for decision, count in decision_counts.items()
        if decision not in NON_ELIGIBLE_DECISIONS
    )
    return {
        "phase": phase_dir.name,
        "source": source,
        "windows": len(inference),
        "eligible_decision_windows": eligible,
        "alerts": len(alerts),
        "detections": len(detections),
        "decision_counts": dict(sorted(decision_counts.items())),
        "scores": quantiles([float(row["score"]) for row in inference]),
        "inference_ms": quantiles([float(row["inference_ms"]) for row in inference]),
        "by_workload": by_workload,
        "passed": not alerts and not detections,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--role", choices=EVALUATION_ROLES, required=True)
    parser.add_argument("--split-contract", type=Path,
                        default=Path("aims_candidate_split_contract.json"))
    parser.add_argument("--release-contract", type=Path,
                        default=Path("aims_release_contract.json"))
    parser.add_argument("--prerequisite-report", type=Path)
    parser.add_argument("--initial-calibration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    evidence_root = args.evidence_root.resolve()
    candidate = args.candidate.resolve()
    split_path = args.split_contract.resolve()
    release_path = args.release_contract.resolve()
    output = args.output.resolve()
    initial_calibration = args.initial_calibration.resolve()
    split_contract = json.loads(split_path.read_text())
    release_contract = json.loads(release_path.read_text())
    expected_phases, _ = phase_role_contract(split_contract, args.role)

    report: dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "schema_version": 1,
        "role": args.role,
        "status": "initializing",
        "evidence_root": str(evidence_root),
        "candidate": str(candidate),
        "expected_phases": expected_phases,
        "split_contract": str(split_path),
        "split_contract_sha256": sha256(split_path),
        "release_contract": str(release_path),
        "release_contract_sha256": sha256(release_path),
        "initial_calibration": str(initial_calibration),
    }
    output.parent.mkdir(parents=True, exist_ok=True)

    matrix = validate_matrix(
        evidence_root, release_contract,
        runs_per_regime=int(
            release_contract["normal_protocol"]["independent_runs_per_regime"]
        ),
        minutes_per_run=72,
    )
    captures = {item["phase"]: item for item in matrix["captures"]}
    unavailable = [
        phase for phase in expected_phases
        if phase not in captures or captures[phase]["valid"] is not True
    ]
    if unavailable:
        report.update(status="waiting_for_phases", unavailable_phases=unavailable,
                      passed=False)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 4

    training_report_path = candidate / "training_report.json"
    dataset_manifest_path = candidate / "dataset_manifest.json"
    training_report = json.loads(training_report_path.read_text())
    dataset_manifest = json.loads(dataset_manifest_path.read_text())
    if training_report.get("accepted_offline") is not True:
        raise ValueError("candidate did not pass its development gate")
    if training_report.get("dataset_role") != "candidate_fit":
        raise ValueError("candidate was not fitted from candidate_fit data")
    experiment = dataset_manifest.get("experiment_contract") or {}
    if experiment.get("sha256") != sha256(split_path):
        raise ValueError("candidate split contract digest mismatch")
    if experiment.get("parent_release_contract_sha256") != sha256(release_path):
        raise ValueError("candidate parent release contract digest mismatch")

    hashes = candidate_hashes(candidate)
    report["candidate_sha256"] = hashes
    calibration_sha256 = sha256(initial_calibration)
    report["initial_calibration_sha256"] = calibration_sha256
    if args.role == "blind_normal_test":
        report["prerequisite"] = validate_blind_prerequisite(
            args.prerequisite_report, hashes, calibration_sha256
        )

    fit_provenance = provenance_sets(dataset_manifest)
    completed_provenance = {
        name: set(values) for name, values in matrix["artifact_digests"].items()
    }
    for name, values in fit_provenance.items():
        if len(values) != 1 or not values.issubset(completed_provenance[name]):
            raise ValueError(f"evaluation provenance drift for {name}")

    manager = ModelManager(str(candidate), str(candidate / "vocab.pkl"))
    manager.load_all()
    targets = list(release_contract["eligible_targets"])
    if set(manager.list_models()) != set(targets):
        raise ValueError("candidate model set does not match release targets")

    phase_reports = []
    started = time.perf_counter()
    for phase in expected_phases:
        phase_reports.append(evaluate_phase(
            evidence_root / phase, targets, manager,
            minimum_events=int(release_contract["minimum_events_per_window"]),
            startup_grace_seconds=float(
                training_report.get("startup_grace_seconds", 60.0)
            ),
            warmup_windows=10,
            initial_calibration=initial_calibration,
        ))
    report.update(
        status="complete",
        evaluation_seconds=time.perf_counter() - started,
        phases=phase_reports,
        windows=sum(item["windows"] for item in phase_reports),
        eligible_decision_windows=sum(
            item["eligible_decision_windows"] for item in phase_reports
        ),
        alerts=sum(item["alerts"] for item in phase_reports),
        detections=sum(item["detections"] for item in phase_reports),
        passed=all(item["passed"] for item in phase_reports),
        runtime_thresholds=load_thresholds(manager, minimum=0.80),
        methodology={
            "production_detector_path": True,
            "adaptive_threshold_algorithm_frozen": True,
            "cooldown_seconds": 0,
            "fast_path_warnings_replayed": False,
            "holdout_used_for_training_or_tuning": False,
        },
    )
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    temporary.replace(output)
    print(json.dumps({
        "status": report["status"], "passed": report["passed"],
        "windows": report["windows"], "alerts": report["alerts"],
        "output": str(output),
    }, indent=2, sort_keys=True))
    return 0 if report["passed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
