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
from .train import load_dataset_manifest, source_git_provenance


def build_contract(
    dataset: Path,
    blind_attack_contract: Path,
    candidate_id: str,
    evidence_class: str,
    history: int,
    alpha: float,
    window_seconds: float,
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
    return {
        "schema": "sentinel-pulse-training-contract-v2",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "candidate_id": candidate_id,
        "evidence_class": evidence_class,
        "frozen_before_training": True,
        "automatic_promotion": False,
        "normal_only": True,
        "blind_outcome_used": False,
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
    )
    freeze(args.output, contract)


if __name__ == "__main__":
    main()
