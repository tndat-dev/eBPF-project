"""Build a checksum-bound same-window semantic policy from normal evidence."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from .decision_policy import load_decision_policy
from .integrity import sha256_file
from .train import source_git_provenance


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_policy(
    calibration_path: Path,
    model_manifest_path: Path,
    training_contract_path: Path,
    base_policy_path: Path,
    policy_name: str,
    evidence_class: str,
    source: dict | None = None,
) -> dict:
    if not policy_name.strip() or not evidence_class.strip():
        raise ValueError("policy_name and evidence_class must be non-empty")
    calibration = _read(calibration_path)
    model = _read(model_manifest_path)
    contract = _read(training_contract_path)
    base_policy, base_policy_sha256 = load_decision_policy(base_policy_path)
    if (
        calibration.get("schema")
        != "sentinel-pulse-semantic-envelope-calibration-v1"
        or calibration.get("normal_only") is not True
        or calibration.get("blind_outcome_used") is not False
    ):
        raise ValueError("semantic calibration is not normal-only evidence")
    if model.get("schema") != "sentinel-pulse-model-manifest-v2":
        raise ValueError("unsupported model manifest")
    if contract.get("schema") != "sentinel-pulse-training-contract-v2":
        raise ValueError("policy requires a v2 training contract")
    dataset_sha256 = calibration.get("dataset_sha256")
    if not dataset_sha256 or not (
        dataset_sha256 == model.get("dataset_sha256")
        == contract.get("dataset_sha256")
    ):
        raise ValueError("policy inputs do not bind the same dataset")
    maxima = calibration.get("workload_group_maxima", {})
    model_workloads = model.get("workloads", {})
    if not maxima or set(maxima) != set(model_workloads):
        raise ValueError("semantic calibration does not cover every model workload")
    if any(item.get("status") != "candidate" for item in model_workloads.values()):
        raise ValueError("semantic policy cannot include collect-only workloads")
    base_confirmation = base_policy["same_window_corroboration"]
    base_envelope = base_confirmation.get("workload_normal_envelope", {})
    groups = deepcopy(base_envelope.get("signal_groups", []))
    if not groups:
        raise ValueError("base policy has no semantic signal groups")
    expected_groups = {group["name"] for group in groups}
    if any(set(values) != expected_groups for values in maxima.values()):
        raise ValueError("semantic calibration groups differ from the base policy")
    provenance = source or source_git_provenance()
    return {
        "schema": "sentinel-pulse-decision-policy-v2",
        "name": policy_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evidence_class": evidence_class,
        "frozen_before_blind_evaluation": True,
        "blind_outcome_used": False,
        "automatic_promotion": False,
        "source_git_commit": provenance["source_git_commit"],
        "source_clean": provenance["source_clean"],
        "source_git_diff_sha256": provenance["source_git_diff_sha256"],
        "same_window_corroboration": {
            "requires_raw_model_anomaly": True,
            "additional_window_wait": 0,
            "minimum_security_activity_mass": int(
                base_confirmation["minimum_security_activity_mass"]
            ),
            "security_activity_fields": deepcopy(
                base_confirmation["security_activity_fields"]
            ),
            "workload_normal_envelope": {
                "signal_groups": groups,
                "workload_group_maxima": maxima,
            },
        },
        "score_corroboration": deepcopy(base_policy["score_corroboration"]),
        "suppressed_decision_status": base_policy["suppressed_decision_status"],
        "development_normal_evidence": {
            "dataset_sha256": dataset_sha256,
            "dataset_manifest_sha256": calibration["dataset_manifest_sha256"],
            "semantic_envelope_calibration_sha256": sha256_file(calibration_path),
            "model_manifest_sha256": sha256_file(model_manifest_path),
            "training_contract_sha256": sha256_file(training_contract_path),
            "base_policy_sha256": base_policy_sha256,
        },
        "claim_scope": (
            "Non-formal same-window pilot policy built only from checksum-bound "
            "normal calibration evidence; no blind outcome is used and no "
            "additional confirmation window is added"
        ),
    }


def write_policy(path: Path, policy: dict) -> None:
    if path.exists():
        raise ValueError(f"refusing to overwrite decision policy: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", delete=False,
        ) as output:
            temporary_name = output.name
            json.dump(policy, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_name, 0o444)
        os.replace(temporary_name, path)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--model-manifest", type=Path, required=True)
    parser.add_argument("--training-contract", type=Path, required=True)
    parser.add_argument("--base-policy", type=Path, required=True)
    parser.add_argument("--policy-name", required=True)
    parser.add_argument("--evidence-class", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    policy = build_policy(
        args.calibration,
        args.model_manifest,
        args.training_contract,
        args.base_policy,
        args.policy_name,
        args.evidence_class,
    )
    write_policy(args.output, policy)
    load_decision_policy(args.output)


if __name__ == "__main__":
    main()
