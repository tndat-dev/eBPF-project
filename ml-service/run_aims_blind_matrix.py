"""Run the frozen AIMS blind attack matrix after candidate training.

The script is deliberately separate from training and has no promotion path.
It verifies all frozen source/binary hashes before starting and writes a
partial aggregate after every trial so a long run remains auditable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--normal-calibration", required=True)
    parser.add_argument("--aims-contract", default="aims_release_contract.json")
    parser.add_argument("--attack-contract", default="aims_blind_attack_contract.json")
    parser.add_argument("--runtime-source", default="runtime_attack_blind.c")
    parser.add_argument("--runtime-binary", default="runtime_attack_blind")
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--output-root", default="aims-blind-matrix")
    parser.add_argument("--schedule-seed", type=int, default=20260801)
    args = parser.parse_args()

    aims_contract_path = Path(args.aims_contract).resolve()
    attack_contract_path = Path(args.attack_contract).resolve()
    source = Path(args.runtime_source).resolve()
    binary = Path(args.runtime_binary).resolve()
    model_dir = Path(args.model_dir).resolve()
    calibration = Path(args.normal_calibration).resolve()
    for path in (aims_contract_path, attack_contract_path, source, binary,
                 model_dir, calibration):
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
    root = Path(args.output_root).resolve() / stamp
    root.mkdir(parents=True, exist_ok=False)
    aggregate = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "method": "frozen blind binary; shuffled workload/seed/rate trials",
        "model_dir": str(model_dir),
        "normal_calibration": str(calibration),
        "window_seconds": args.window,
        "schedule_seed": args.schedule_seed,
        "aims_contract": {"path": str(aims_contract_path), "sha256": sha256(aims_contract_path)},
        "attack_contract": {"path": str(attack_contract_path), "sha256": sha256(attack_contract_path)},
        "runtime_source_sha256": sha256(source),
        "runtime_binary_sha256": sha256(binary),
        "expected_trials": len(schedule),
        "expected_scenario_trials": len(schedule) * len(scenarios),
        "schedule": schedule,
        "trials": [],
    }

    for row in schedule:
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
            "--attack-seconds", str(attack["attack_seconds"]),
            "--post-attack-wait", str(attack["post_attack_wait_seconds"]),
            "--rate", str(row["rate"]),
            "--seed", str(row["seed"]),
            "--scenarios", ",".join(scenarios),
            "--fast-path-expected", ",".join(fast_expected),
            "--output-dir", str(trial_dir),
        ]
        result = subprocess.run(command)
        reports = sorted(trial_dir.glob("*/report.json"))
        report_path = reports[-1] if reports else None
        report = load_json(report_path) if report_path else None
        aggregate["trials"].append({
            **row,
            "exit_code": result.returncode,
            "report_path": str(report_path) if report_path else None,
            "all_passed": bool(report and report.get("all_passed")),
            "detected": report.get("detected") if report else 0,
            "total": report.get("total") if report else len(scenarios),
        })
        (root / "report.partial.json").write_text(
            json.dumps(aggregate, indent=2, sort_keys=True) + "\n"
        )

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
    final = root / "report.json"
    final.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n")
    print(f"report={final}")
    return 0 if aggregate["all_passed"] else 8


if __name__ == "__main__":
    raise SystemExit(main())
