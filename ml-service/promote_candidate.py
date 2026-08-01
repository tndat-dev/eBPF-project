"""Atomically promote a candidate only after offline, normal and attack gates."""

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from artifact_integrity import model_release_hashes
from ml_models import ModelManager


TARGETS = {"default/postgres", "production/nginx", "production/redis"}
RUNTIME_FILES = (
    "adaptive_threshold.py", "anomaly_detector2.py", "feature_engineering.py",
    "graph_signals.py", "ml_models.py", "tetragon_consumer.py",
    "workload_identity.py", "sentinel/fast_path.py", "sentinel/telemetry.py",
)
REQUIRED_SENSOR_HEALTH_FIELDS = {
    "backpressure_events", "membership_failures", "coverage_failures",
    "stream_failures", "require_full_coverage", "coverage_healthy",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_code_hashes() -> dict:
    root = Path(__file__).resolve().parent
    return {name: sha256(root / name) for name in RUNTIME_FILES}


def load_json(path: Path) -> dict:
    with path.open() as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", default="models_candidate")
    parser.add_argument("--production", default="models")
    parser.add_argument("--vocab", default=None,
                        help="Defaults to the vocabulary bundled in the candidate")
    parser.add_argument("--normal-report", required=True)
    parser.add_argument("--attack-report", required=True)
    parser.add_argument("--calibration", default="calibration.json")
    parser.add_argument("--expected-version", type=int, default=7)
    parser.add_argument("--expected-attack-trials", type=int, default=15)
    parser.add_argument(
        "--expected-window", type=int,
        default=int(os.environ.get("SENTINEL_WINDOW_SECONDS", "10")),
        help=("Feature-window duration validated by both normal and attack "
              "evidence; prevents promoting evidence from another cadence"),
    )
    parser.add_argument(
        "--expected-startup-grace", type=float,
        default=float(os.environ.get(
            "SENTINEL_POD_STARTUP_GRACE_SECONDS", "60"
        )),
        help="Pod startup grace shared by training and live evidence",
    )
    parser.add_argument(
        "--expected-extreme-volume-factor", type=float,
        default=float(os.environ.get("SENTINEL_EXTREME_VOLUME_FACTOR", "2.0")),
        help="Clean upper event-volume multiplier validated by live evidence",
    )
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    candidate = Path(args.candidate).resolve()
    production = Path(args.production).resolve()
    vocab = (
        Path(args.vocab).resolve()
        if args.vocab else candidate / "vocab.pkl"
    )
    normal_path = Path(args.normal_report).resolve()
    attack_path = Path(args.attack_report).resolve()
    calibration = Path(args.calibration).resolve()

    training_path = candidate / "training_report.json"
    dataset_manifest_path = candidate / "dataset_manifest.json"
    training = load_json(training_path)
    dataset_manifest = (
        load_json(dataset_manifest_path) if dataset_manifest_path.is_file() else {}
    )
    normal = load_json(normal_path)
    attack = load_json(attack_path)
    validated_calibration = Path(normal.get("calibration", "")).resolve()
    failures = []
    vocab_digest = None
    current_runtime_hashes = runtime_code_hashes()
    current_release_hashes = model_release_hashes(candidate)
    if vocab != candidate / "vocab.pkl":
        failures.append("promotion vocabulary must be bundled inside candidate")
    if not training.get("accepted_offline"):
        failures.append("offline training gate failed")
    if not dataset_manifest_path.is_file():
        failures.append("candidate dataset manifest missing")
    else:
        dataset_digest = sha256(dataset_manifest_path)
        if training.get("dataset_manifest_sha256") != dataset_digest:
            failures.append("source dataset manifest hash mismatch")
        if training.get("bundled_dataset_manifest_sha256") != dataset_digest:
            failures.append("bundled dataset manifest hash mismatch")
        if set(dataset_manifest.get("targets", {})) != TARGETS:
            failures.append("dataset manifest target set is not exact")
        if dataset_manifest.get("window_seconds") != args.expected_window:
            failures.append("dataset manifest window does not match promotion window")
        if float(dataset_manifest.get("startup_grace_seconds", -1)) != (
                args.expected_startup_grace):
            failures.append(
                "dataset startup grace does not match promotion contract"
            )
        for item in dataset_manifest.get("source_manifests", []):
            health = item.get("sensor_health", {})
            missing_health = REQUIRED_SENSOR_HEALTH_FIELDS - set(health)
            if missing_health:
                failures.append(
                    "dataset source sensor-health schema incomplete: "
                    + ",".join(sorted(missing_health))
                )
            if health.get("backpressure_events", 0):
                failures.append("dataset manifest contains backpressured source")
            if (
                health.get("membership_failures", 0)
                or health.get("coverage_failures", 0)
                or health.get("stream_failures", 0)
            ):
                failures.append("dataset manifest contains sensor continuity failure")
            if (
                health.get("require_full_coverage")
                and health.get("coverage_healthy") is not True
            ):
                failures.append("dataset manifest contains incomplete sensor coverage")
    if not normal.get("passed"):
        failures.append("normal-control gate failed")
    if not attack.get("all_passed"):
        failures.append("kernel regression gate failed")
    if normal.get("window_seconds") != args.expected_window:
        failures.append(
            "normal report window does not match expected promotion window"
        )
    if attack.get("window_seconds") != args.expected_window:
        failures.append(
            "attack report window does not match expected promotion window"
        )
    if normal.get("confirmation_policy") != attack.get("confirmation_policy"):
        failures.append("normal/attack confirmation policy mismatch")
    normal_startup_grace = (normal.get("confirmation_policy") or {}).get(
        "pod_startup_grace_seconds"
    )
    attack_startup_grace = (attack.get("confirmation_policy") or {}).get(
        "pod_startup_grace_seconds"
    )
    normal_volume_factor = (normal.get("confirmation_policy") or {}).get(
        "extreme_volume_factor"
    )
    attack_volume_factor = (attack.get("confirmation_policy") or {}).get(
        "extreme_volume_factor"
    )
    if normal_startup_grace != args.expected_startup_grace:
        failures.append("normal report startup grace mismatch")
    if attack_startup_grace != args.expected_startup_grace:
        failures.append("attack report startup grace mismatch")
    if normal_volume_factor != args.expected_extreme_volume_factor:
        failures.append("normal report extreme-volume factor mismatch")
    if attack_volume_factor != args.expected_extreme_volume_factor:
        failures.append("attack report extreme-volume factor mismatch")
    if training.get("window_seconds") != args.expected_window:
        failures.append("training report window does not match promotion window")
    if float(training.get("startup_grace_seconds", -1)) != (
            args.expected_startup_grace):
        failures.append("training report startup grace mismatch")
    attack_workloads = attack.get("workloads", {})
    if set(attack_workloads) != TARGETS or not all(
        item.get("exit_code") == 0
        and item.get("report", {}).get("all_passed")
        and int(item.get("report", {}).get("detected", -1)) == 5
        and int(item.get("report", {}).get("total", -1)) == 5
        for item in attack_workloads.values()
    ):
        failures.append(
            "attack report does not contain three passing 5-trial workloads"
        )
    if Path(normal.get("candidate", "")).resolve() != candidate:
        failures.append("normal report belongs to a different candidate")
    expected_regimes = {
        "normal-1x", "in-cluster-burst", "high-mixed", "recovery-1x",
    }
    regimes = normal.get("regimes", {})
    if set(regimes) != expected_regimes or not all(
        item.get("passed") for item in regimes.values()
    ):
        failures.append("normal report does not contain four passing regimes")
    if Path(attack.get("model_dir", "")).resolve() != candidate:
        failures.append("attack report belongs to a different candidate")
    if (
        int(attack.get("total", -1)) != args.expected_attack_trials
        or int(attack.get("detected", -1)) != args.expected_attack_trials
    ):
        failures.append(
            f"expected {args.expected_attack_trials} successful attack trials"
        )
    if not vocab.is_file():
        failures.append(f"candidate vocabulary missing: {vocab}")
    else:
        vocab_digest = sha256(vocab)
        if training.get("vocab_sha256") != vocab_digest:
            failures.append("training report vocabulary hash mismatch")
        if training.get("bundled_vocab_sha256") != vocab_digest:
            failures.append("bundled vocabulary hash mismatch")
        if normal.get("vocab_sha256") != vocab_digest:
            failures.append("normal report vocabulary hash mismatch")
        if attack.get("vocab_sha256") != vocab_digest:
            failures.append("attack report vocabulary hash mismatch")
        if dataset_manifest.get("vocabulary", {}).get(
            "output_sha256"
        ) != vocab_digest:
            failures.append("dataset vocabulary hash mismatch")
    if not attack.get("runtime_binary_sha256"):
        failures.append("attack runtime binary hash missing")
    if attack.get("normal_calibration_sha256") != normal.get(
        "calibration_sha256"
    ):
        failures.append("attack calibration does not match normal validation")
    if normal.get("runtime_code_sha256") != current_runtime_hashes:
        failures.append("normal report runtime code hash mismatch")
    if attack.get("runtime_code_sha256") != current_runtime_hashes:
        failures.append("attack report runtime code hash mismatch")
    if normal.get("model_release_sha256") != current_release_hashes:
        failures.append("normal report model release hash mismatch")
    if attack.get("model_release_sha256") != current_release_hashes:
        failures.append("attack report model release hash mismatch")
    if not validated_calibration.is_file():
        failures.append("validated normal calibration artifact missing")
    elif sha256(validated_calibration) != normal.get("calibration_sha256"):
        failures.append("validated normal calibration hash mismatch")
    versions = {
        int(item.get("model_version", -1))
        for item in training.get("models", {}).values()
    }
    if versions != {args.expected_version}:
        failures.append(
            f"expected model version {args.expected_version}, found {sorted(versions)}"
        )

    manager = None
    if vocab.is_file():
        manager = ModelManager(str(candidate), str(vocab))
        try:
            manager.load_all()
        except RuntimeError as exc:
            failures.append(str(exc))
        if set(manager.list_models()) != TARGETS:
            failures.append(
                f"expected models {sorted(TARGETS)}, found {sorted(manager.list_models())}"
            )
        for pod_key in TARGETS & set(manager.list_models()):
            bundle = manager.get_model(pod_key)
            if bundle.model_version != args.expected_version:
                failures.append(f"{pod_key}: bundle version {bundle.model_version}")
            if bundle.input_dim != manager.vocab_size:
                failures.append(
                    f"{pod_key}: model dimension {bundle.input_dim} != "
                    f"vocabulary size {manager.vocab_size}"
                )
            shape = training.get("models", {}).get(pod_key, {}).get("shape", [])
            if len(shape) != 2 or int(shape[1]) != manager.vocab_size:
                failures.append(f"{pod_key}: training shape/vocabulary mismatch")

    manifest = {
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "candidate": str(candidate),
        "production": str(production),
        "expected_version": args.expected_version,
        "expected_window_seconds": args.expected_window,
        "expected_startup_grace_seconds": args.expected_startup_grace,
        "training_report": {"path": str(training_path), "sha256": sha256(training_path)},
        "normal_report": {"path": str(normal_path), "sha256": sha256(normal_path)},
        "attack_report": {"path": str(attack_path), "sha256": sha256(attack_path)},
        "vocab": {
            "path": str(vocab),
            "sha256": sha256(vocab) if vocab.is_file() else None,
        },
        "runtime_code_sha256": current_runtime_hashes,
        "model_release_sha256": current_release_hashes,
        "files": {},
        "evidence_files": {
            "normal_validation_report.json": sha256(normal_path),
            "attack_validation_report.json": sha256(attack_path),
            "validated_calibration.json": (
                sha256(validated_calibration)
                if validated_calibration.is_file() else None
            ),
        },
        "failures": failures,
    }
    for path in sorted(candidate.iterdir()):
        if path.is_file() and (
            path.name.endswith("_bundle.pkl")
            or path.name.endswith("_lstm.pt")
            or path.name == "vocab.pkl"
            or path.name == "dataset_manifest.json"
            or path.name == "training_report.json"
        ):
            manifest["files"][path.name] = sha256(path)
    # The systemd service loads this file from the atomically promoted model
    # directory. Missing vocabularies remain a reported gate failure instead
    # of raising while rendering the failure manifest.
    if vocab.is_file():
        manifest["files"]["vocab.pkl"] = sha256(vocab)

    if failures:
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 6
    if not args.apply:
        manifest["status"] = "validated-dry-run"
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    staging = production.with_name(f".{production.name}.staging-{stamp}")
    backup = production.with_name(f"{production.name}.backup-{stamp}")
    failed_release = production.with_name(
        f"{production.name}.failed-promotion-{stamp}"
    )
    calibration_backup = (
        calibration.with_name(f"{calibration.name}.backup-{stamp}")
        if calibration.exists() else None
    )
    calibration_staging = calibration.with_name(
        f".{calibration.name}.staging-{stamp}"
    )
    failed_calibration = calibration.with_name(
        f"{calibration.name}.failed-promotion-{stamp}"
    )
    if staging.exists() or backup.exists():
        raise FileExistsError("promotion staging/backup path already exists")
    if calibration_backup and calibration_backup.exists():
        raise FileExistsError(calibration_backup)
    if calibration_staging.exists() or failed_calibration.exists():
        raise FileExistsError("calibration staging/failed path already exists")
    staging.mkdir(parents=True)
    swapped = False
    calibration_installed = False
    try:
        # The independent four-regime normal run is the clean calibration
        # source for this exact release. Stage it before either atomic swap so
        # production never starts with an empty/ad-hoc threshold state.
        shutil.copy2(validated_calibration, calibration_staging)
        for filename in manifest["files"]:
            source = vocab if filename == "vocab.pkl" else candidate / filename
            shutil.copy2(source, staging / filename)
        shutil.copy2(normal_path, staging / "normal_validation_report.json")
        shutil.copy2(attack_path, staging / "attack_validation_report.json")
        shutil.copy2(
            validated_calibration, staging / "validated_calibration.json"
        )
        manifest["status"] = "promoted"
        manifest["promoted_at"] = datetime.now(timezone.utc).isoformat()
        manifest["backup"] = str(backup)
        if calibration_backup:
            manifest["calibration_backup"] = str(calibration_backup)
        (staging / "release_manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        if production.exists():
            os.replace(production, backup)
        os.replace(staging, production)
        swapped = True
        if calibration_backup:
            os.replace(calibration, calibration_backup)
        os.replace(calibration_staging, calibration)
        calibration_installed = True
        if sha256(calibration) != normal.get("calibration_sha256"):
            raise RuntimeError("installed calibration hash mismatch")
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        if calibration_staging.exists():
            calibration_staging.unlink()
        if calibration_installed and calibration.exists():
            if calibration_backup and calibration_backup.exists():
                os.replace(calibration, failed_calibration)
            else:
                calibration.unlink()
        if calibration_backup and calibration_backup.exists() and not calibration.exists():
            os.replace(calibration_backup, calibration)
        if swapped and production.exists() and backup.exists():
            os.replace(production, failed_release)
            os.replace(backup, production)
        elif not production.exists() and backup.exists():
            os.replace(backup, production)
        raise

    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
