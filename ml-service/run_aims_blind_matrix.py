"""Run the frozen AIMS blind attack matrix after candidate training.

The script is deliberately separate from training and has no promotion path.
It verifies all frozen source/binary hashes before starting and writes a
partial aggregate after every trial so a long run remains auditable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from evaluate_aims_normal_split import candidate_hashes

TRIAL_TIMEOUT_SECONDS = 30 * 60


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def atomic_json(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def run_trial(command: list[str], timeout: int = TRIAL_TIMEOUT_SECONDS
              ) -> tuple[subprocess.CompletedProcess, bool]:
    """Bound one workload trial so a transport hang cannot consume the unit."""
    try:
        return subprocess.run(command, timeout=timeout), False
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            command, 124, exc.stdout, exc.stderr,
        ), True


def validate_normal_prerequisite(path: Path, model_hashes: dict,
                                 calibration_sha256: str,
                                 split_contract_sha256: str) -> dict:
    report = load_json(path)
    if (
        report.get("role") != "blind_normal_test"
        or report.get("status") != "complete"
        or report.get("passed") is not True
    ):
        raise ValueError("blind attack requires a passed blind-normal report")
    if report.get("candidate_sha256") != model_hashes:
        raise ValueError("blind-normal report evaluated a different candidate")
    if report.get("initial_calibration_sha256") != calibration_sha256:
        raise ValueError("blind-normal report used a different calibration")
    if report.get("split_contract_sha256") != split_contract_sha256:
        raise ValueError("blind-normal report used a different split contract")
    return {"path": str(path), "sha256": sha256(path)}


def validated_trials(root: Path, aggregate: dict) -> tuple[list[dict], set[tuple]]:
    """Return every complete hash-valid trial without mutating evidence."""
    retained = []
    completed = set()
    for row in aggregate.get("trials", []):
        key = (row.get("target"), row.get("trial"))
        report_value = row.get("report_path")
        report_path = Path(report_value).resolve() if report_value else None
        safe_path = bool(report_path and report_path.is_relative_to(root.resolve()))
        report = None
        if safe_path and report_path.is_file():
            try:
                report = load_json(report_path)
            except (OSError, ValueError):
                report = None
        report_total = int(report.get("total", 0)) if report else 0
        report_detected = int(report.get("detected", -1)) if report else -1
        valid = bool(
            row.get("exit_code") in (0, 4)
            and report is not None
            and row.get("report_sha256") == sha256(report_path)
            and report_total > 0
            and len(report.get("scenarios", {})) == report_total
            and int(row.get("total", -1)) == report_total
            and int(row.get("detected", -1)) == report_detected
            and bool(row.get("all_passed")) is bool(report.get("all_passed"))
            and ((row.get("exit_code") == 0) is bool(report.get("all_passed")))
        )
        if valid:
            retained.append(row)
            completed.add(key)
    return retained, completed


def resumable_trials(root: Path, aggregate: dict) -> tuple[list[dict], set[tuple]]:
    """Keep every complete hash-valid trial, including a detection failure.

    Re-running a healthy failed blind trial until it passes would cherry-pick
    environmental variance and inflate recall.  Only infrastructure-incomplete
    trials (no final report, invalid hash/path, or unexpected process exit) are
    eligible for quarantine and retry.
    """
    retained, completed = validated_trials(root, aggregate)
    rejected = root / "rejected"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    retained_dirs = {
        Path(row["report_path"]).resolve().parents[1] for row in retained
    }
    for directory in sorted(root.glob("*-trial-*")):
        if directory.resolve() not in retained_dirs:
            rejected.mkdir(exist_ok=True)
            destination = rejected / f"{directory.name}-{stamp}"
            suffix = 1
            while destination.exists():
                destination = rejected / f"{directory.name}-{stamp}-{suffix}"
                suffix += 1
            shutil.move(str(directory), destination)
    return retained, completed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--normal-calibration", required=True)
    parser.add_argument("--normal-prerequisite", required=True)
    parser.add_argument("--split-contract", default="aims_candidate_split_contract.json")
    parser.add_argument("--aims-contract", default="aims_release_contract.json")
    parser.add_argument("--attack-contract", default="aims_blind_attack_contract.json")
    parser.add_argument("--runtime-source", default="runtime_attack_blind.c")
    parser.add_argument("--runtime-binary", default="runtime_attack_blind")
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--output-root", default="aims-blind-matrix")
    parser.add_argument("--schedule-seed", type=int, default=20260801)
    parser.add_argument("--experiment-id", default=None)
    parser.add_argument(
        "--feature-capture-mode", choices=("off", "aggregate", "sequence"),
        default="off",
        help="Enable dedicated paired-replay evidence for a new frozen release",
    )
    parser.add_argument("--capture-release-id", default=None)
    args = parser.parse_args()

    aims_contract_path = Path(args.aims_contract).resolve()
    attack_contract_path = Path(args.attack_contract).resolve()
    source = Path(args.runtime_source).resolve()
    binary = Path(args.runtime_binary).resolve()
    model_dir = Path(args.model_dir).resolve()
    calibration = Path(args.normal_calibration).resolve()
    prerequisite = Path(args.normal_prerequisite).resolve()
    split_contract = Path(args.split_contract).resolve()
    for path in (aims_contract_path, attack_contract_path, source, binary,
                 model_dir, calibration, prerequisite, split_contract):
        if not path.exists():
            raise FileNotFoundError(path)

    aims = load_json(aims_contract_path)
    attack = load_json(attack_contract_path)
    if not attack.get("frozen_before_candidate_training"):
        raise ValueError("blind attack contract is not frozen")
    if attack.get("use_for_training_or_threshold_tuning") is not False:
        raise ValueError("blind set must be excluded from training/tuning")
    if sha256(source) != attack["source"]["sha256"]:
        raise ValueError("blind attack source hash mismatch")
    if sha256(binary) != attack["binary"]["sha256"]:
        raise ValueError("blind attack binary hash mismatch")
    if args.window != int(aims["window_seconds"]):
        raise ValueError("window does not match AIMS release contract")

    targets = list(aims["eligible_targets"])
    scenarios = list(attack["scenarios"])
    fast_expected = list(attack["fast_path_expected"])
    seeds = list(attack["trial_seeds"])
    rates = list(attack["trial_rates_per_second"])
    if len(seeds) != len(rates) or len(seeds) < 5:
        raise ValueError("blind trial seed/rate schedule is incomplete")

    schedule = [
        {"target": target, "trial": index + 1, "seed": seed, "rate": rate}
        for target in targets
        for index, (seed, rate) in enumerate(zip(seeds, rates))
    ]
    random.Random(args.schedule_seed).shuffle(schedule)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    experiment_id = args.experiment_id or stamp
    root = Path(args.output_root).resolve() / experiment_id
    model_hashes = candidate_hashes(model_dir)
    calibration_digest = sha256(calibration)
    split_digest = sha256(split_contract)
    prerequisite_spec = validate_normal_prerequisite(
        prerequisite, model_hashes, calibration_digest, split_digest
    )
    frozen_header = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "experiment_id": experiment_id,
        "method": "frozen blind binary; shuffled workload/seed/rate trials",
        "model_dir": str(model_dir),
        "model_sha256": model_hashes,
        "normal_calibration": str(calibration),
        "normal_calibration_sha256": calibration_digest,
        "normal_prerequisite": prerequisite_spec,
        "split_contract": {"path": str(split_contract), "sha256": split_digest},
        "window_seconds": args.window,
        "schedule_seed": args.schedule_seed,
        "aims_contract": {"path": str(aims_contract_path), "sha256": sha256(aims_contract_path)},
        "attack_contract": {"path": str(attack_contract_path), "sha256": sha256(attack_contract_path)},
        "runtime_source_sha256": sha256(source),
        "runtime_binary_sha256": sha256(binary),
        "expected_trials": len(schedule),
        "expected_scenario_trials": len(schedule) * len(scenarios),
        "schedule": schedule,
    }
    # Keep completed pre-V8 reports load-compatible. New capture campaigns bind
    # the mode into their immutable header and child command.
    if args.feature_capture_mode != "off":
        if not args.capture_release_id:
            raise ValueError(
                "--capture-release-id is required when capture is enabled"
            )
        frozen_header["feature_capture_mode"] = args.feature_capture_mode
        frozen_header["capture_release_id"] = args.capture_release_id
    root.mkdir(parents=True, exist_ok=True)
    partial = root / "report.partial.json"
    final = root / "report.json"
    if final.is_file():
        completed_report = load_json(final)
        for key, value in frozen_header.items():
            if key != "created_at" and completed_report.get(key) != value:
                raise ValueError(f"completed report header changed: {key}")
        retained, completed = validated_trials(root, completed_report)
        expected = int(completed_report.get("expected_trials", -1))
        if (
            len(retained) == expected
            and len(completed) == expected
            and int(completed_report.get("completed_trials", -1)) == expected
            and int(completed_report.get("total", -1))
            == int(completed_report.get("expected_scenario_trials", -2))
        ):
            # A complete failed blind matrix is just as immutable as a pass.
            # Timers must not update resumed_at and silently drift its digest.
            print(f"report={final}")
            return 0 if completed_report.get("all_passed") is True else 8
    if partial.is_file():
        aggregate = load_json(partial)
        for key, value in frozen_header.items():
            if key != "created_at" and aggregate.get(key) != value:
                raise ValueError(f"resume header changed: {key}")
        aggregate["trials"], completed = resumable_trials(root, aggregate)
        aggregate["resumed_at"] = datetime.now(timezone.utc).isoformat()
    else:
        aggregate = {**frozen_header, "trials": []}
        _, completed = resumable_trials(root, aggregate)
    atomic_json(partial, aggregate)

    for row in schedule:
        if (row["target"], row["trial"]) in completed:
            continue
        workload = row["target"].split("/", 1)[1]
        trial_dir = root / f"{workload}-trial-{row['trial']:02d}"
        command = [
            sys.executable, "run_kernel_regression.py",
            "--model-dir", str(model_dir),
            "--normal-calibration", str(calibration),
            "--runtime-binary", str(binary),
            "--namespace", "production",
            "--selector", f"app.kubernetes.io/name={workload}",
            "--window", str(args.window),
            "--minimum-events", str(aims["minimum_events_per_window"]),
            "--attack-seconds", str(attack["attack_seconds"]),
            "--post-attack-wait", str(attack["post_attack_wait_seconds"]),
            "--rate", str(row["rate"]),
            "--seed", str(row["seed"]),
            "--scenarios", ",".join(scenarios),
            "--fast-path-expected", ",".join(fast_expected),
            "--output-dir", str(trial_dir),
        ]
        if args.feature_capture_mode != "off":
            command.extend([
                "--feature-capture-mode", args.feature_capture_mode,
                "--capture-release-id", args.capture_release_id,
                "--capture-run-id",
                f"{experiment_id}:{workload}:trial-{row['trial']:02d}",
            ])
        result, timed_out = run_trial(command)
        reports = sorted(trial_dir.glob("*/report.json"))
        report_path = reports[-1] if reports else None
        report = load_json(report_path) if report_path else None
        aggregate["trials"].append({
            **row,
            "exit_code": result.returncode,
            "timed_out": timed_out,
            "trial_timeout_seconds": TRIAL_TIMEOUT_SECONDS,
            "report_path": str(report_path) if report_path else None,
            "report_sha256": sha256(report_path) if report_path else None,
            "all_passed": bool(report and report.get("all_passed")),
            "detected": report.get("detected") if report else 0,
            "total": report.get("total") if report else len(scenarios),
        })
        atomic_json(partial, aggregate)

    aggregate["completed_trials"] = len(aggregate["trials"])
    aggregate["detected"] = sum(int(row["detected"]) for row in aggregate["trials"])
    aggregate["total"] = sum(int(row["total"]) for row in aggregate["trials"])
    aggregate["all_passed"] = bool(
        aggregate["completed_trials"] == aggregate["expected_trials"]
        and aggregate["detected"] == aggregate["total"]
        == aggregate["expected_scenario_trials"]
        and all(row["exit_code"] == 0 and row["all_passed"]
                for row in aggregate["trials"])
    )
    atomic_json(final, aggregate)
    print(f"report={final}")
    return 0 if aggregate["all_passed"] else 8


if __name__ == "__main__":
    raise SystemExit(main())
