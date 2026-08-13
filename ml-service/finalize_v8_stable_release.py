"""Create the terminal, non-promoting V8 release decision.

The finalizer runs only after the immutable syscall matrix and the
counterbalanced overhead campaign are complete.  A failed preregistered model
gate is a valid terminal research outcome, not a reason to mutate the model or
its contract after seeing blind labels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


EXPECTED_RELEASE_ID = "v8-paired-replay-20260811"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(path)
    return json.loads(path.read_text())


def verify_checksums(root: Path) -> None:
    checksum_path = root / "SHA256SUMS"
    if not checksum_path.is_file():
        raise ValueError(f"missing checksum manifest: {checksum_path}")
    for line in checksum_path.read_text().splitlines():
        expected, separator, relative = line.partition("  ")
        if not separator or not expected or not relative:
            raise ValueError(f"invalid checksum line: {line!r}")
        artifact = (root / relative).resolve()
        if not artifact.is_relative_to(root.resolve()) or not artifact.is_file():
            raise ValueError(f"checksum artifact escapes or is missing: {relative}")
        if sha256(artifact) != expected:
            raise ValueError(f"checksum mismatch: {relative}")


def recall_point(result: dict) -> float:
    recall = result.get("attack", {}).get("recall", {})
    value = recall.get("estimate", result.get("attack", {}).get("recall_point"))
    if value is None:
        raise ValueError("full detector result has no recall point estimate")
    return float(value)


def build_decision(
    contract_path: Path,
    matrix_root: Path,
    overhead_root: Path,
    release_id: str = EXPECTED_RELEASE_ID,
) -> dict:
    verify_checksums(matrix_root)
    verify_checksums(overhead_root)
    contract = read_json(contract_path)
    manifest_path = matrix_root / "evaluation_matrix_manifest.json"
    statistics_path = matrix_root / "paired_statistics.json"
    full_path = matrix_root / "syscall__full_v7" / "result.json"
    overhead_path = overhead_root / f"counterbalanced-{release_id}.json"
    matrix_marker = matrix_root.parent / "NORMAL_ABLATION_REPLAY_COMPLETE"
    overhead_marker = overhead_root / "V8_OVERHEAD_COMPLETE"
    for marker in (matrix_marker, overhead_marker):
        if not marker.is_file():
            raise ValueError(f"terminal marker is missing: {marker}")

    manifest = read_json(manifest_path)
    statistics = read_json(statistics_path)
    full = read_json(full_path)
    overhead = read_json(overhead_path)
    if manifest.get("valid") is not True or int(
        manifest.get("completed_experiments", 0)
    ) != 11:
        raise ValueError("terminal evaluation matrix is invalid or incomplete")
    if (
        int(statistics.get("methods", 0)) != 11
        or int(statistics.get("pairwise_comparisons", 0)) != 55
    ):
        raise ValueError("paired statistics are incomplete")
    if (
        full.get("experiment_id") != "syscall__full_v7"
        or full.get("release_id") != release_id
    ):
        raise ValueError("full detector result has the wrong release identity")
    if (
        overhead.get("schema")
        != "sentinel-aims-overhead-counterbalanced/v1"
        or overhead.get("campaign_prefix") != release_id
        or overhead.get("evidence_release") != "v8"
        or len(overhead.get("experiments", [])) != 6
    ):
        raise ValueError("counterbalanced overhead campaign is incomplete")

    normal = full.get("normal", {})
    attack = full.get("attack", {})
    observed_false_alerts = int(normal.get("false_alerts", -1))
    observed_recall = recall_point(full)
    required_false_alerts = int(
        contract["normal_protocol"]["promotion_false_positive_alerts"]
    )
    required_recall = float(contract["attack_protocol"]["promotion_recall"])
    gates = {
        "offline_candidate": bool(
            full.get("development_gate", {}).get("accepted", True)
        ),
        "independent_normal": bool(
            int(normal.get("independent_runs", 0)) == 5
            and int(normal.get("phases", 0)) == 20
            and observed_false_alerts <= required_false_alerts
        ),
        "blind_attack": bool(
            int(attack.get("trials", 0)) == 200
            and observed_recall >= required_recall
        ),
        "baseline_and_ablation_matrix": True,
        "paired_statistics": True,
        "counterbalanced_overhead": True,
    }
    failures = [name for name, passed in gates.items() if not passed]
    eligible = not failures
    status = (
        "eligible_for_manual_promotion"
        if eligible else "research_stable_dry_run_only"
    )
    return {
        "schema": "sentinel-v8-stable-release-decision/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "release_id": release_id,
        "status": status,
        "evidence_complete": True,
        "automatic_promotion": False,
        "manual_production_promotion_eligible": eligible,
        "failed_preregistered_gates": failures,
        "scope": {
            "eligible_targets": contract.get("eligible_targets", []),
            "excluded_targets": contract.get("excluded_targets", {}),
        },
        "observed": {
            "normal_windows": int(normal.get("windows", 0)),
            "normal_exposure_hours": float(normal.get("exposure_hours", 0)),
            "normal_false_alerts": observed_false_alerts,
            "attack_trials": int(attack.get("trials", 0)),
            "attack_detected": int(attack.get("detected", 0)),
            "attack_recall": observed_recall,
            "confirmation_latency_seconds": full.get("latency_seconds", {}),
            "inference_ms": full.get("inference_ms", {}),
        },
        "preregistered_requirements": {
            "maximum_normal_false_alerts": required_false_alerts,
            "minimum_attack_recall": required_recall,
            "automatic_promotion": contract.get("promotion", {}).get("automatic"),
        },
        "gates": gates,
        "overhead_effects": overhead.get("effects", {}),
        "source_sha256": {
            "release_contract": sha256(contract_path),
            "evaluation_matrix_manifest": sha256(manifest_path),
            "paired_statistics": sha256(statistics_path),
            "full_detector_result": sha256(full_path),
            "counterbalanced_overhead": sha256(overhead_path),
            "matrix_checksums": sha256(matrix_root / "SHA256SUMS"),
            "overhead_checksums": sha256(overhead_root / "SHA256SUMS"),
        },
        "interpretation": (
            "All terminal evidence is complete, but production promotion remains "
            "manual and is forbidden when a preregistered gate fails."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--matrix-root", type=Path, required=True)
    parser.add_argument("--overhead-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release-id", default=EXPECTED_RELEASE_ID)
    args = parser.parse_args()
    decision = build_decision(
        args.contract.resolve(), args.matrix_root.resolve(),
        args.overhead_root.resolve(), args.release_id,
    )
    if args.output.exists():
        existing = read_json(args.output)
        if existing.get("source_sha256") != decision["source_sha256"]:
            raise ValueError("existing release decision belongs to different evidence")
        print(args.output)
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(decision, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
