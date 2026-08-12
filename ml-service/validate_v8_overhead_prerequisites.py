"""Validate immutable V8 artifacts before a mutating overhead campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"JSON object required: {path}")
    return document


def candidate_hashes(candidate: Path) -> dict[str, str]:
    files = sorted(path for path in candidate.iterdir() if path.is_file())
    if not files:
        raise ValueError("candidate directory is empty")
    return {path.name: sha256(path) for path in files}


def validate(
    candidate: Path, calibration: Path, normal_report: Path,
    blind_report: Path, completion_marker: Path,
) -> dict[str, Any]:
    paths = (candidate, calibration, normal_report, blind_report, completion_marker)
    if any(not path.exists() for path in paths):
        missing = [str(path) for path in paths if not path.exists()]
        raise ValueError(f"V8 overhead prerequisites are missing: {missing}")
    if not completion_marker.is_file():
        raise ValueError("V8 terminal matrix marker is not a file")
    hashes = candidate_hashes(candidate)
    calibration_hash = sha256(calibration)
    normal, blind = read_json(normal_report), read_json(blind_report)
    if (
        normal.get("role") != "independent_evaluation"
        or normal.get("status") != "complete"
        or normal.get("passed") is not True
        or normal.get("candidate_sha256") != hashes
        or normal.get("initial_calibration_sha256") != calibration_hash
    ):
        raise ValueError("V8 independent normal prerequisite is invalid")
    expected_trials = int(blind.get("expected_trials", -1))
    expected_scenarios = int(blind.get("expected_scenario_trials", -1))
    paired = blind.get("paired_attack_evidence", {})
    if (
        expected_trials != 40
        or int(blind.get("completed_trials", -2)) != expected_trials
        or expected_scenarios != 200
        or int(blind.get("total", -2)) != expected_scenarios
        or blind.get("model_sha256") != hashes
        or blind.get("normal_calibration_sha256") != calibration_hash
        or int(paired.get("source_count", -1)) != expected_scenarios
        or int(paired.get("injection_intervals", -1)) != expected_scenarios
        or paired.get("labels_used_for_training") is not False
    ):
        raise ValueError("V8 blind evidence is incomplete or mismatched")
    return {
        "schema": "sentinel-v8-overhead-prerequisite/v1",
        "release_id": "v8-paired-replay-20260811",
        "candidate": {"path": str(candidate), "sha256": hashes},
        "calibration": {"path": str(calibration), "sha256": calibration_hash},
        "normal_report": {"path": str(normal_report), "sha256": sha256(normal_report)},
        "blind_report": {"path": str(blind_report), "sha256": sha256(blind_report)},
        "completion_marker": {
            "path": str(completion_marker), "sha256": sha256(completion_marker),
        },
        "normal_passed": True,
        "blind_infrastructure_complete": True,
        "blind_all_passed": bool(blind.get("all_passed")),
        "automatic_promotion": False,
        "valid": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--normal-report", type=Path, required=True)
    parser.add_argument("--blind-report", type=Path, required=True)
    parser.add_argument("--completion-marker", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = validate(
        args.candidate.resolve(), args.calibration.resolve(),
        args.normal_report.resolve(), args.blind_report.resolve(),
        args.completion_marker.resolve(),
    )
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    temporary.replace(args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
