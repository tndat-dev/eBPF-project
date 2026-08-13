"""Replay one frozen candidate policy on the canonical V8 blind capture.

Every scenario capture was produced by a fresh live detector.  Replay therefore
resets detector/calibration state for each injection group as well; carrying
adaptive state across trials would create an evaluation path that never ran in
the kernel experiment.  Labels are consulted only after decisions are frozen.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import shutil
import tempfile
import time
from types import SimpleNamespace
from typing import Any

import numpy as np

import anomaly_detector2
from build_feature_replay_dataset import build_dataset, injection_intervals, load_rows
from evaluate_aims_normal_split import (
    SCORE_COMPONENTS, ScoreComponentManager, candidate_hashes, quantiles,
    development_gate, sha256, validate_calibration_provenance, write_report,
)
from feature_engineering import FeatureVector
from ml_models import ModelManager, SharedWorkloadModelManager
from workload_identity import get_deployment_key


REPORT_SCHEMA = "sentinel-aims-attack-replay/v1"


def validate_release_identity(
    release: dict[str, Any], split: dict[str, Any],
    attack_contract: dict[str, Any], protocol: dict[str, Any],
) -> str:
    """Return the experiment release ID without conflating two contracts.

    The AIMS release contract predates V8 and identifies the frozen production
    model through ``production_release_frozen``/``release_track``.  The V8
    split, attack and evaluation protocol identify the paper experiment with
    ``release_id``.  Requiring the production contract to grow that later
    field would mutate a frozen parent artifact.
    """
    release_id = split.get("release_id")
    if not isinstance(release_id, str) or not release_id:
        raise ValueError("attack replay release contract mismatch")
    if any(
        document.get("release_id") != release_id
        for document in (attack_contract, protocol)
    ):
        raise ValueError("attack replay release contract mismatch")
    if not release.get("production_release_frozen") or not release.get(
        "release_track"
    ):
        raise ValueError("frozen production release identity is missing")
    return release_id


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> dict:
    if total < 1 or not 0 <= successes <= total:
        raise ValueError("invalid Wilson counts")
    proportion = successes / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    center = (proportion + z2 / (2.0 * total)) / denominator
    radius = z * math.sqrt(
        proportion * (1.0 - proportion) / total
        + z2 / (4.0 * total * total)
    ) / denominator
    lower = 0.0 if successes == 0 else max(0.0, center - radius)
    upper = 1.0 if successes == total else min(1.0, center + radius)
    return {
        "estimate": proportion,
        "lower": lower,
        "upper": upper,
        "confidence_level": 0.95,
        "method": "Wilson score interval",
    }


def dense_vector(row: dict[str, Any], expected_size: int) -> np.ndarray:
    if int(row.get("vector_size", -1)) != expected_size:
        raise ValueError("attack replay vector size mismatch")
    vector = np.zeros(expected_size, dtype=np.float32)
    seen = set()
    for item in row.get("sparse_vector", []):
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError("malformed sparse feature")
        index, value = int(item[0]), float(item[1])
        if index in seen or not 0 <= index < expected_size or not np.isfinite(value):
            raise ValueError("invalid sparse feature")
        seen.add(index)
        vector[index] = value
    return vector


def capture_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return deterministic one-injection groups bound by run/phase IDs."""
    intervals = {item["injection_id"]: item for item in injection_intervals(rows)}
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        run_id, phase_id = row.get("run_id"), row.get("phase_id")
        if not isinstance(run_id, str) or not isinstance(phase_id, str):
            raise ValueError("attack capture row lacks run/phase identity")
        grouped[(run_id, phase_id)].append(row)

    result = []
    seen = set()
    for (run_id, phase_id), group_rows in sorted(grouped.items()):
        starts = [row for row in group_rows if row.get("kind") == "injection"]
        ends = [row for row in group_rows if row.get("kind") == "injection_end"]
        if len(starts) != 1 or len(ends) != 1:
            raise ValueError(f"{run_id}/{phase_id}: expected one injection pair")
        injection_id = starts[0].get("injection_id")
        if injection_id not in intervals or ends[0].get("injection_id") != injection_id:
            raise ValueError(f"{run_id}/{phase_id}: injection identity mismatch")
        if injection_id in seen:
            raise ValueError(f"duplicate grouped injection: {injection_id}")
        seen.add(injection_id)
        features = [row for row in group_rows if row.get("kind") == "feature_window"]
        if not features:
            raise ValueError(f"{run_id}/{phase_id}: no feature windows")
        result.append({
            "run_id": run_id, "phase_id": phase_id,
            "interval": intervals[injection_id], "features": features,
            "workload_key": get_deployment_key(intervals[injection_id]["pod_key"]),
        })
    if seen != set(intervals):
        raise ValueError("some injection intervals are not represented by a group")
    result.sort(key=lambda item: (
        float(item["interval"]["start"]), item["interval"]["injection_id"]
    ))
    return result


def evaluate_group(
    group: dict[str, Any], manager, initial_calibration: Path,
    *, minimum_events: int, startup_grace_seconds: float,
    post_attack_horizon: float, require_behavior_gate: bool,
    enable_extreme_volume_gate: bool, enable_adaptive_threshold: bool,
    confirmation_windows: int,
) -> dict[str, Any]:
    interval = group["interval"]
    features = sorted(group["features"], key=lambda row: (
        float(row["window_end"]), str(row["pod_key"])
    ))
    creation_times = {
        str(row["pod_key"]): float(row["pod_creation_timestamp"])
        for row in features if row.get("pod_creation_timestamp") is not None
    }
    alerts, emissions = [], []
    old_emit = anomaly_detector2.emit
    detector_logger = anomaly_detector2.logger
    old_level = detector_logger.level
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="aims-attack-replay-") as temporary:
        calibration_path = Path(temporary) / "calibration.json"
        shutil.copy2(initial_calibration, calibration_path)
        environment = {
            "SENTINEL_CALIBRATION": str(calibration_path),
            "SENTINEL_WARMUP_WINDOWS": "10",
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
        detector_logger.setLevel("WARNING")
        try:
            detector = anomaly_detector2.AnomalyDetector(
                manager,
                on_alert=lambda alert: alerts.append({
                    **alert.to_dict(), "pod_key": alert.pod_key,
                    "window_start": alert.window_start,
                    "window_end": alert.window_end,
                }),
                threshold=0.80, cooldown_seconds=0,
                early_warning_lookup=lambda _pod: None,
                pod_started_at_lookup=lambda pod: creation_times.get(pod),
                persist_calibration=False,
                require_behavior_gate=require_behavior_gate,
                enable_extreme_volume_gate=enable_extreme_volume_gate,
                enable_adaptive_threshold=enable_adaptive_threshold,
                confirmation_windows=confirmation_windows,
            )
            for row in features:
                namespace, pod = str(row["pod_key"]).split("/", 1)
                event_count = int(row["event_count"])
                detector.handle_feature_vector(FeatureVector(
                    pod_name=pod, pod_namespace=namespace,
                    node_name=str(row.get("node_name", "captured")),
                    window_start=float(row["window_start"]),
                    window_end=float(row["window_end"]),
                    vector=dense_vector(row, manager.vocab_size),
                    raw_syscalls=["captured-event"] * event_count,
                    syscall_counts={
                        str(name): int(count)
                        for name, count in row.get("syscall_counts", {}).items()
                    },
                ))
        finally:
            anomaly_detector2.emit = old_emit
            detector_logger.setLevel(old_level)
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    target = interval["pod_key"]
    horizon_end = float(interval["end"]) + post_attack_horizon
    target_alerts = [row for row in alerts if row["pod_key"] == target]
    matched = [
        row for row in target_alerts
        if float(interval["start"]) <= float(row["window_end"]) <= horizon_end
    ]
    first = min(matched, key=lambda row: row["window_end"]) if matched else None
    inference = [
        float(row["inference_ms"]) for row in emissions
        if row.get("kind") == "inference"
    ]
    decisions = Counter(
        str(row.get("decision", "unknown")) for row in emissions
        if row.get("kind") == "decision"
    )
    return {
        **interval,
        "run_id": group["run_id"], "phase_id": group["phase_id"],
        "workload_key": group["workload_key"],
        "feature_windows": len(features),
        "detected": first is not None,
        "first_confirmation_window_end": (
            float(first["window_end"]) if first else None
        ),
        "first_confirmation_latency_seconds": (
            max(0.0, float(first["window_end"]) - float(interval["start"]))
            if first else None
        ),
        "matched_alerts": len(matched),
        "target_alerts_outside_horizon": len(target_alerts) - len(matched),
        "off_target_alerts": len(alerts) - len(target_alerts),
        "decision_counts": dict(sorted(decisions.items())),
        "inference_ms": quantiles(inference),
        "evaluation_seconds": time.perf_counter() - started,
    }


def aggregate_breakdown(trials: list[dict], field: str) -> dict[str, dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for trial in trials:
        grouped[str(trial[field])].append(trial)
    return {
        key: {
            "trials": len(items),
            "detected": sum(bool(item["detected"]) for item in items),
            "recall": wilson(sum(bool(item["detected"]) for item in items), len(items)),
        }
        for key, items in sorted(grouped.items())
    }


def validate_protocol_policy(
    protocol: dict[str, Any], method: str, policy: dict[str, Any]
) -> dict[str, Any]:
    methods = protocol.get("methods", {})
    if method not in methods:
        raise ValueError("experiment is not frozen in the syscall protocol")
    raw = dict(methods[method])
    parent = raw.pop("inherits", None)
    resolved = {**methods.get(parent, {}), **raw} if parent else raw
    expected = {
        "require_behavior_gate": bool(resolved.get("behavior_gate", False)),
        "enable_extreme_volume_gate": bool(
            resolved.get("extreme_volume_gate", False)
        ),
        "enable_adaptive_threshold": bool(
            resolved.get("adaptive_threshold", False)
        ),
        "confirmation_windows": int(resolved.get("confirmation_windows", 1)),
        "model_routing": (
            "shared_workload"
            if method == "shared_workload_model" else "per_workload"
        ),
    }
    expected["score_component"] = {
        "isolation_forest": "isolation_forest",
        "lstm_only": "lstm",
        "evt_pot": "lstm",
    }.get(method, "ensemble")
    mismatch = {
        key: {"expected": value, "observed": policy.get(key)}
        for key, value in expected.items() if policy.get(key) != value
    }
    if mismatch:
        raise ValueError(f"evaluation policy differs from frozen protocol: {mismatch}")
    if resolved.get("fast_path") is True and policy.get("fast_path_replayed") is not False:
        raise ValueError("feature replay cannot claim fast-path execution")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack-capture", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--initial-calibration", type=Path, required=True)
    parser.add_argument("--initial-calibration-report", type=Path, required=True)
    parser.add_argument("--release-contract", type=Path, required=True)
    parser.add_argument("--split-contract", type=Path, required=True)
    parser.add_argument("--attack-contract", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-trials", type=int, default=200)
    parser.add_argument("--post-attack-horizon", type=float, default=30.0)
    parser.add_argument("--disable-behavior-gate", action="store_true")
    parser.add_argument("--disable-extreme-volume-gate", action="store_true")
    parser.add_argument("--disable-adaptive-threshold", action="store_true")
    parser.add_argument("--confirmation-windows", type=int, choices=(1, 2), default=2)
    parser.add_argument("--score-component", choices=SCORE_COMPONENTS, default="ensemble")
    parser.add_argument("--model-routing", choices=("per_workload", "shared_workload"),
                        default="per_workload")
    parser.add_argument("--allow-rejected-shared-ablation", action="store_true")
    args = parser.parse_args()

    paths = {
        name: getattr(args, name).resolve() for name in (
            "attack_capture", "candidate", "initial_calibration",
            "initial_calibration_report", "release_contract", "split_contract",
            "attack_contract", "protocol", "output",
        )
    }
    release = json.loads(paths["release_contract"].read_text())
    split = json.loads(paths["split_contract"].read_text())
    attack_contract = json.loads(paths["attack_contract"].read_text())
    protocol = json.loads(paths["protocol"].read_text())
    training_path = paths["candidate"] / "training_report.json"
    dataset_path = paths["candidate"] / "dataset_manifest.json"
    training = json.loads(training_path.read_text())
    dataset = json.loads(dataset_path.read_text())
    method = args.experiment_id.removeprefix("syscall__")
    if args.experiment_id != f"syscall__{method}":
        raise ValueError("experiment ID is not canonical")
    if not args.experiment_id.startswith("syscall__"):
        raise ValueError("attack replay only supports the syscall track")
    release_id = validate_release_identity(
        release, split, attack_contract, protocol,
    )
    gate = development_gate(
        training, args.model_routing,
        args.allow_rejected_shared_ablation,
    )
    if training.get("dataset_role") != "candidate_fit":
        raise ValueError("candidate was not fitted from candidate_fit data")
    if training.get("dataset_manifest_sha256") != sha256(dataset_path):
        raise ValueError("candidate dataset provenance mismatch")
    if (dataset.get("experiment_contract") or {}).get("sha256") != sha256(paths["split_contract"]):
        raise ValueError("candidate split provenance mismatch")
    if training.get("model_routing", "per_workload") != args.model_routing:
        raise ValueError("candidate model-routing contract mismatch")

    raw_rows = load_rows(paths["attack_capture"])
    _, replay_manifest = build_dataset(paths["attack_capture"], require_injections=True)
    groups = capture_groups(raw_rows)
    if len(groups) != args.expected_trials:
        raise ValueError(f"attack trial count mismatch: {len(groups)}/{args.expected_trials}")
    if replay_manifest.get("release_id") != release_id:
        raise ValueError("attack capture release mismatch")
    frozen_seeds = list(attack_contract.get("trial_seeds", []))
    if sorted({item["interval"]["seed"] for item in groups}) != sorted(frozen_seeds):
        raise ValueError("attack capture seed set mismatch")
    expected_rates = dict(zip(
        frozen_seeds, attack_contract.get("trial_rates_per_second", [])
    ))
    if any(
        expected_rates.get(item["interval"]["seed"])
        != item["interval"]["rate"] for item in groups
    ):
        raise ValueError("attack capture seed/rate pairing mismatch")
    pair_counts = Counter(
        (item["workload_key"], item["interval"]["scenario"])
        for item in groups
    )
    expected_pairs = {
        (target, scenario)
        for target in release["eligible_targets"]
        for scenario in attack_contract["scenarios"]
    }
    required_repetitions = int(
        attack_contract["minimum_trials_per_scenario_per_workload"]
    )
    if set(pair_counts) != expected_pairs or any(
        count != required_repetitions for count in pair_counts.values()
    ):
        raise ValueError("attack workload/scenario matrix is incomplete")

    manager_class = (
        SharedWorkloadModelManager if args.model_routing == "shared_workload"
        else ModelManager
    )
    candidate_manager = manager_class(
        str(paths["candidate"]), str(paths["candidate"] / "vocab.pkl")
    )
    candidate_manager.load_all()
    targets = list(release["eligible_targets"])
    if set(candidate_manager.list_models()) != set(targets):
        raise ValueError("candidate target set mismatch")
    manager = ScoreComponentManager(
        candidate_manager, args.score_component,
        adaptive_threshold=not args.disable_adaptive_threshold,
    )
    calibration_provenance = validate_calibration_provenance(
        paths["initial_calibration_report"], paths["initial_calibration"],
        paths["candidate"],
    )
    policy = {
        "require_behavior_gate": not args.disable_behavior_gate,
        "enable_extreme_volume_gate": not args.disable_extreme_volume_gate,
        "enable_adaptive_threshold": not args.disable_adaptive_threshold,
        "confirmation_windows": args.confirmation_windows,
        "score_component": args.score_component,
        "model_routing": args.model_routing,
        "fast_path_replayed": False,
    }
    resolved_method = validate_protocol_policy(protocol, method, policy)
    identity = {
        "schema": REPORT_SCHEMA, "experiment_id": args.experiment_id,
        "release_id": release_id,
        "attack_capture_sha256": sha256(paths["attack_capture"]),
        "candidate_sha256": candidate_hashes(paths["candidate"]),
        "initial_calibration_sha256": sha256(paths["initial_calibration"]),
        "initial_calibration_report": calibration_provenance,
        "release_contract_sha256": sha256(paths["release_contract"]),
        "split_contract_sha256": sha256(paths["split_contract"]),
        "blind_attack_contract_sha256": sha256(paths["attack_contract"]),
        "evaluation_protocol_sha256": sha256(paths["protocol"]),
        "development_gate": gate,
        "evaluation_policy": policy,
        "resolved_protocol_method": resolved_method,
        "expected_trials": args.expected_trials,
        "post_attack_horizon_seconds": args.post_attack_horizon,
    }
    output = paths["output"]
    output.parent.mkdir(parents=True, exist_ok=True)
    trials: list[dict] = []
    if output.is_file():
        previous = json.loads(output.read_text())
        for key, value in identity.items():
            if previous.get(key) != value:
                raise ValueError(f"attack replay checkpoint identity mismatch: {key}")
        if previous.get("status") == "complete":
            print(json.dumps({"status": "complete", "output": str(output)}))
            return 0
        trials = list(previous.get("trials", []))
        expected_prefix = [
            item["interval"]["injection_id"] for item in groups[:len(trials)]
        ]
        if [item.get("injection_id") for item in trials] != expected_prefix:
            raise ValueError("attack replay checkpoint is not a trial prefix")

    report = {
        **identity, "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "evaluating", "trials": trials,
    }
    for group in groups[len(trials):]:
        trials.append(evaluate_group(
            group, manager, paths["initial_calibration"],
            minimum_events=int(release["minimum_events_per_window"]),
            startup_grace_seconds=float(training.get("startup_grace_seconds", 60.0)),
            post_attack_horizon=args.post_attack_horizon,
            require_behavior_gate=not args.disable_behavior_gate,
            enable_extreme_volume_gate=not args.disable_extreme_volume_gate,
            enable_adaptive_threshold=not args.disable_adaptive_threshold,
            confirmation_windows=args.confirmation_windows,
        ))
        report.update(
            trials=trials, completed_trials=len(trials),
            evaluation_seconds=sum(
                float(item["evaluation_seconds"]) for item in trials
            ),
        )
        write_report(output, report)

    detected = sum(bool(item["detected"]) for item in trials)
    latencies = [
        float(item["first_confirmation_latency_seconds"])
        for item in trials if item["first_confirmation_latency_seconds"] is not None
    ]
    inference = [
        float(item["inference_ms"]["median"])
        for item in trials if item["inference_ms"].get("count", 0)
    ]
    report.update(
        status="complete", completed_trials=len(trials), detected_trials=detected,
        recall=wilson(detected, len(trials)), latency_seconds=quantiles(latencies),
        trial_median_inference_ms=quantiles(inference),
        alerts_outside_horizon=sum(
            item["target_alerts_outside_horizon"] + item["off_target_alerts"]
            for item in trials
        ),
        by_scenario=aggregate_breakdown(trials, "scenario"),
        by_workload=aggregate_breakdown(trials, "workload_key"),
        labels_used_for_training_or_tuning=False,
        paired_replay=True,
        methodology={
            "fresh_detector_and_fit_calibration_per_injection_group": True,
            "production_confirmation_path": True,
            "latency_clock": "captured feature-window end minus injection acknowledgement",
            "fast_path_replayed": False,
            "automatic_promotion": False,
        },
    )
    write_report(output, report)
    print(json.dumps({
        "status": "complete", "trials": len(trials), "detected": detected,
        "output": str(output),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
