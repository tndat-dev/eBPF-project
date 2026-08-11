"""Fail-closed validation for the pre-evidence generalization protocol."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PARENT_FILES = (
    "aims_release_contract.json",
    "evaluation_matrix_contract.json",
    "syscall_evaluation_protocol.json",
    "v8_blind_attack_contract.json",
    "v8_capture_split_contract.json",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_contract(contract_path: Path, parent_root: Path) -> dict[str, Any]:
    contract = json.loads(contract_path.read_text())
    errors = []
    if contract.get("schema") != "sentinel-generalization-evaluation-contract/v1":
        errors.append("schema mismatch")
    if contract.get("status") != "protocol_only_no_generalization_evidence_yet":
        errors.append("protocol-only status is missing")
    boundary = contract.get("registration_boundary", {})
    if boundary.get("v8_blind_attack_started") is not False:
        errors.append("protocol was not frozen before the V8 blind attack")
    if boundary.get("v8_holdout_or_attack_results_inspected") is not False:
        errors.append("holdout-result exclusion is missing")

    parent_hashes = contract.get("parent_contracts", {})
    for name in PARENT_FILES:
        path = parent_root / name
        if not path.is_file() or parent_hashes.get(name) != sha256(path):
            errors.append(f"parent contract digest mismatch: {name}")

    release_path = parent_root / "aims_release_contract.json"
    if release_path.is_file():
        release = json.loads(release_path.read_text())
        targets = list(contract.get("eligible_targets", []))
        if targets != release.get("eligible_targets"):
            errors.append("eligible target order differs from the parent release")
    else:
        targets = list(contract.get("eligible_targets", []))

    capture = contract.get("capture_schema", {})
    if capture.get("schema") != "sentinel-feature-window/v3":
        errors.append("generalization capture is not schema v3")
    required_identity = set(capture.get("required_identity_fields", []))
    if required_identity != {
        "cluster_id", "workload_image_digest", "workload_version_id",
    }:
        errors.append("generalization identity fields are incomplete")
    if capture.get("image_digest_must_be_immutable") is not True:
        errors.append("immutable image identity is not required")
    if capture.get("raw_arguments_or_payloads_forbidden") is not True:
        errors.append("privacy exclusion is missing")

    tracks = contract.get("generalization_tracks", {})
    lowo = tracks.get("leave_one_workload_out", {})
    folds = lowo.get("folds", [])
    held_out = [item.get("held_out") for item in folds if isinstance(item, dict)]
    fold_ids = [item.get("fold") for item in folds if isinstance(item, dict)]
    if len(folds) != len(targets) or set(held_out) != set(targets):
        errors.append("leave-one-workload-out folds do not cover each target once")
    if len(set(fold_ids)) != len(fold_ids):
        errors.append("duplicate leave-one-workload-out fold ID")
    for field in (
        "held_out_rows_used_for_fit_or_calibration",
        "held_out_behavior_limits_used",
        "adaptive_threshold_on_held_out_data",
    ):
        if lowo.get(field) is not False:
            errors.append(f"zero-shot leakage guard is missing: {field}")
    if int(lowo.get("normal_test_runs", 0)) < 5:
        errors.append("leave-one-workload-out normal runs are insufficient")
    if int(lowo.get("attack_trials_per_fold", 0)) < 25:
        errors.append("leave-one-workload-out attack trials are insufficient")

    version = tracks.get("workload_version_shift", {})
    cross = tracks.get("cross_cluster", {})
    if version.get("source_and_target_image_digests_must_differ") is not True:
        errors.append("version-shift image separation is missing")
    if version.get("model_or_threshold_refit_on_target") is not False:
        errors.append("version-shift target refit is not forbidden")
    if int(version.get("minimum_independent_normal_runs", 0)) < 5:
        errors.append("version-shift normal runs are insufficient")
    if cross.get("cluster_id_must_not_equal_source") is not True:
        errors.append("cross-cluster identity separation is missing")
    if cross.get("model_or_threshold_refit_on_target") is not False:
        errors.append("cross-cluster target refit is not forbidden")
    if int(cross.get("minimum_distinct_target_clusters", 0)) < 1:
        errors.append("cross-cluster target count is insufficient")

    attack = json.loads((parent_root / "v8_blind_attack_contract.json").read_text()) \
        if (parent_root / "v8_blind_attack_contract.json").is_file() else {}
    seeds = list(contract.get("generalization_attack_seeds", []))
    if len(seeds) != 5 or len(set(seeds)) != 5:
        errors.append("generalization attack seeds are invalid")
    if set(seeds) & set(attack.get("trial_seeds", [])):
        errors.append("generalization attack seeds overlap V8")
    if contract.get("automatic_promotion") is not False:
        errors.append("automatic promotion is not forbidden")

    return {
        "schema": "sentinel-generalization-contract-validation/v1",
        "contract_sha256": sha256(contract_path),
        "parent_release_id": contract.get("parent_release_id"),
        "targets": len(targets),
        "folds": len(folds),
        "errors": errors,
        "valid": not errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=Path)
    parser.add_argument("--parent-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate_contract(args.contract.resolve(), args.parent_root.resolve())
    if args.output:
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
