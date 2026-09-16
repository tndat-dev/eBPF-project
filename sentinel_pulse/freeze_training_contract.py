"""Freeze an immutable dataset, source and parameter contract before training."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from .blind_contract import load_contract
from .integrity import sha256_file
from .train import (
    controller_revisions,
    load_dataset_manifest,
    load_workload_revisions,
    source_git_provenance,
)


def bind_completed_fingerprint(
    workload_fingerprint: Path,
    approved_workload_revisions: dict[str, list[str]],
) -> dict:
    """Verify and summarize terminal observer evidence for training."""
    if workload_fingerprint.name != "APPROVED_FINGERPRINT.json":
        raise ValueError("workload fingerprint must be an approved observer artifact")
    fingerprint = json.loads(workload_fingerprint.read_text(encoding="utf-8"))
    if fingerprint.get("schema") != "sentinel-pulse-workload-fingerprint-v1":
        raise ValueError("unsupported workload fingerprint")
    observer_root = workload_fingerprint.parent
    observer_complete = observer_root / "COMPLETE"
    final_checksums = observer_root / "FINAL_SHA256SUMS"
    if not observer_complete.is_file() or not final_checksums.is_file():
        raise ValueError("workload revision observer is not complete")
    fingerprint_sha256 = sha256_file(workload_fingerprint)
    checksum_bound = False
    for line in final_checksums.read_text(encoding="utf-8").splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            continue
        checksum, filename = fields
        if checksum == fingerprint_sha256 and filename.lstrip("*").endswith(
            "/APPROVED_FINGERPRINT.json"
        ):
            checksum_bound = True
            break
    if not checksum_bound:
        raise ValueError("approved fingerprint is not bound by final checksums")
    observed_controller_revisions = controller_revisions(
        approved_workload_revisions
    )
    if fingerprint.get("workloads") != observed_controller_revisions:
        raise ValueError("dataset revisions differ from completed observer fingerprint")
    return {
        "workload_fingerprint_workloads": observed_controller_revisions,
        "workload_fingerprint_sha256": fingerprint_sha256,
        "observer_complete_sha256": sha256_file(observer_complete),
        "observer_final_checksums_sha256": sha256_file(final_checksums),
    }


def build_contract(
    dataset: Path,
    blind_attack_contract: Path,
    candidate_id: str,
    evidence_class: str,
    history: int,
    alpha: float,
    window_seconds: float,
    workload_fingerprint: Path,
    source: dict | None = None,
) -> dict:
    if not candidate_id.strip() or not evidence_class.strip():
        raise ValueError("candidate_id and evidence_class must be non-empty")
    if history < 1 or not 0.0 < alpha < 1.0:
        raise ValueError("invalid training parameters")
    if window_seconds not in (0.5, 1.0):
        raise ValueError("window_seconds must be 0.5 or 1.0")
    dataset_manifest_path, dataset_manifest = load_dataset_manifest(dataset)
    load_contract(blind_attack_contract)
    provenance = source or source_git_provenance()
    approved_workload_revisions = load_workload_revisions(
        dataset, require_known=True
    )
    fingerprint_binding = bind_completed_fingerprint(
        workload_fingerprint, approved_workload_revisions
    )
    return {
        "schema": "sentinel-pulse-training-contract-v3",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "candidate_id": candidate_id,
        "evidence_class": evidence_class,
        "frozen_before_training": True,
        "automatic_promotion": False,
        "normal_only": True,
        "blind_outcome_used": False,
        "require_workload_revision_provenance": True,
        "approved_workload_revisions": approved_workload_revisions,
        **fingerprint_binding,
        "dataset_sha256": dataset_manifest["dataset_sha256"],
        "dataset_manifest_sha256": sha256_file(dataset_manifest_path),
        "blind_attack_contract_sha256": sha256_file(blind_attack_contract),
        "history_windows": history,
        "alpha": alpha,
        "window_seconds": window_seconds,
        "source_git_commit": provenance["source_git_commit"],
        "source_clean": provenance["source_clean"],
        "source_git_diff_sha256": provenance["source_git_diff_sha256"],
        "source_git_status": provenance["source_git_status"],
        "source_untracked_files": provenance["source_untracked_files"],
    }


def freeze(path: Path, contract: dict) -> None:
    if path.exists():
        raise ValueError(f"refusing to overwrite training contract: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as output:
            temporary_name = output.name
            json.dump(contract, output, indent=2, sort_keys=True)
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
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--blind-attack-contract", type=Path, required=True)
    parser.add_argument("--workload-fingerprint", type=Path, required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--evidence-class", required=True)
    parser.add_argument("--history", type=int, default=3)
    parser.add_argument("--alpha", type=float, default=0.001)
    parser.add_argument(
        "--window-seconds", type=float, choices=(0.5, 1.0), default=0.5
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    contract = build_contract(
        args.dataset,
        args.blind_attack_contract,
        args.candidate_id,
        args.evidence_class,
        args.history,
        args.alpha,
        args.window_seconds,
        args.workload_fingerprint,
    )
    freeze(args.output, contract)


if __name__ == "__main__":
    main()
