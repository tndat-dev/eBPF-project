"""Validate that paper baselines and ablations are directly comparable."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SHARED_DIGESTS = (
    "dataset_sha256", "dataset_manifest_sha256", "capture_sha256",
    "capture_manifest_sha256", "vocab_sha256",
    "split_sha256",
    "blind_attack_contract_sha256",
    "evaluation_protocol_sha256",
    "environment_sha256",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_digest(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def expected_experiments(contract: dict, tracks: set[str] | None = None
                         ) -> dict[str, str]:
    expected = {}
    for track, track_contract in contract["tracks"].items():
        if tracks is not None and track not in tracks:
            continue
        for category in ("baselines", "ablations"):
            for name in track_contract[category]:
                experiment_id = f"{track}__{name}"
                if experiment_id in expected:
                    raise ValueError(f"duplicate experiment ID: {experiment_id}")
                expected[experiment_id] = track
    return expected


def validate_evaluation_matrix(root: Path, contract: dict,
                               tracks: set[str] | None = None) -> dict:
    root = root.resolve()
    unknown_tracks = sorted((tracks or set()) - set(contract["tracks"]))
    if unknown_tracks:
        raise ValueError(f"unknown evaluation tracks: {unknown_tracks}")
    expected = expected_experiments(contract, tracks)
    errors: list[str] = []
    results = []
    shared_by_track: dict[str, dict[str, set[str]]] = {
        track: {field: set() for field in SHARED_DIGESTS}
        for track in contract["tracks"] if tracks is None or track in tracks
    }
    expected_seeds = list(contract["trial_seeds"])

    discovered = {
        path.parent.name: path
        for path in root.glob("*/result.json")
    }
    missing = sorted(set(expected) - set(discovered))
    unexpected = sorted(set(discovered) - set(expected))
    if missing:
        errors.append(f"missing experiments: {','.join(missing)}")
    if unexpected:
        errors.append(f"unexpected experiments: {','.join(unexpected)}")

    for experiment_id in sorted(set(expected) & set(discovered)):
        path = discovered[experiment_id]
        item_errors = []
        try:
            result = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            errors.append(f"{experiment_id}: unreadable result: {exc}")
            continue
        track = expected[experiment_id]
        track_contract = contract["tracks"][track]
        if result.get("schema") != contract["result_schema"]:
            item_errors.append("result schema mismatch")
        if result.get("experiment_id") != experiment_id:
            item_errors.append("experiment ID mismatch")
        if result.get("track") != track:
            item_errors.append("track mismatch")
        if result.get("release_id") != contract.get("release_id"):
            item_errors.append("release ID mismatch")
        if result.get("feature_capture_schema") != contract.get(
            "feature_capture_schema"
        ):
            item_errors.append("feature capture schema mismatch")
        if result.get("injection_schema") != contract.get("injection_schema"):
            item_errors.append("injection schema mismatch")
        if result.get("completed") is not True:
            item_errors.append("experiment is incomplete")
        if result.get("blind_set_used_for_training") is not False:
            item_errors.append("blind-set training/tuning exclusion is not proven")
        if contract.get("paired_replay_required") and result.get(
            "paired_replay"
        ) is not True:
            item_errors.append("paired replay is not proven")
        if result.get("trial_seeds") != expected_seeds:
            item_errors.append("trial seeds differ from frozen contract")
        for field in (*SHARED_DIGESTS, "code_sha256"):
            value = result.get(field)
            if not _is_digest(value):
                item_errors.append(f"invalid {field}")
            elif field in SHARED_DIGESTS:
                shared_by_track[track][field].add(value)

        normal = result.get("normal", {})
        attack = result.get("attack", {})
        if int(normal.get("independent_runs", 0)) < int(
            track_contract["minimum_independent_normal_runs"]
        ):
            item_errors.append("insufficient independent normal runs")
        if int(normal.get("phases", 0)) < int(
            track_contract["minimum_normal_phases"]
        ):
            item_errors.append("insufficient normal traffic phases")
        if int(normal.get("windows", 0)) <= 0:
            item_errors.append("normal window count is missing")
        if int(normal.get("false_alerts", -1)) < 0:
            item_errors.append("normal false-alert count is missing")
        attack_trials = int(attack.get("trials", 0))
        detected = int(attack.get("detected", -1))
        if attack_trials < int(track_contract["minimum_attack_trials"]):
            item_errors.append("insufficient blind attack trials")
        if detected < 0 or detected > attack_trials:
            item_errors.append("invalid attack detection count")
        statistics = result.get("statistics", {})
        if float(statistics.get("confidence_level", 0)) != float(
            contract["confidence_level"]
        ):
            item_errors.append("confidence level mismatch")
        if not statistics.get("method"):
            item_errors.append("confidence-interval method is missing")
        latency = result.get("latency_seconds", {})
        if int(latency.get("sample_count", 0)) < detected:
            item_errors.append("latency samples do not cover detections")

        errors.extend(f"{experiment_id}: {message}" for message in item_errors)
        results.append(
            {
                "experiment_id": experiment_id,
                "track": track,
                "path": str(path.relative_to(root)),
                "sha256": _sha256(path),
                "valid": not item_errors,
            }
        )

    for track, fields in shared_by_track.items():
        for field, values in fields.items():
            if len(values) > 1:
                errors.append(
                    f"{track}: incomparable {field} values: {sorted(values)}"
                )

    return {
        "schema": "sentinel-evaluation-matrix-validation/v1",
        "contract_schema": contract.get("schema"),
        "release_id": contract.get("release_id"),
        "selected_tracks": sorted(tracks or contract["tracks"]),
        "root": str(root),
        "expected_experiments": sorted(expected),
        "completed_experiments": len(results),
        "results": results,
        "shared_digests": {
            track: {field: sorted(values) for field, values in fields.items()}
            for track, fields in shared_by_track.items()
        },
        "errors": errors,
        "valid": not errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--track", action="append", default=None)
    args = parser.parse_args()
    contract = json.loads(args.contract.read_text())
    report = validate_evaluation_matrix(
        args.root, contract, set(args.track) if args.track else None,
    )
    output = args.output or args.root / "evaluation_matrix_manifest.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
