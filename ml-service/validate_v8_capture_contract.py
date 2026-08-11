"""Validate the frozen V8 normal-capture split before collection starts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROLES = {"candidate_fit", "independent_evaluation"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_contract(contract: dict, evaluation: dict, vocab: Path) -> list[str]:
    errors = []
    if contract.get("schema") != "sentinel-v8-capture-split/v1":
        errors.append("capture split schema mismatch")
    if contract.get("frozen_before_capture") is not True:
        errors.append("capture split was not frozen before collection")
    if contract.get("release_id") != evaluation.get("release_id"):
        errors.append("capture/evaluation release ID mismatch")
    if contract.get("capture_mode") != "sequence":
        errors.append("ordered sequence capture is required")
    if contract.get("feature_schema") != evaluation.get("feature_capture_schema"):
        errors.append("feature schema mismatch")
    if contract.get("injection_schema") != evaluation.get("injection_schema"):
        errors.append("injection schema mismatch")
    if not vocab.is_file() or contract.get("vocab_sha256") != sha256(vocab):
        errors.append("frozen vocabulary digest mismatch")

    normal = contract.get("normal", {})
    regimes = normal.get("regimes", [])
    expected_phases = int(
        evaluation.get("tracks", {}).get("syscall", {}).get(
            "minimum_normal_phases", 0
        )
    )
    runs = normal.get("runs", [])
    run_ids = [row.get("run_id") for row in runs if isinstance(row, dict)]
    roles = [row.get("role") for row in runs if isinstance(row, dict)]
    if regimes != ["steady", "burst", "recovery", "toolmix"]:
        errors.append("normal traffic regimes/order mismatch")
    if len(run_ids) != len(set(run_ids)) or len(run_ids) != 6:
        errors.append("capture requires six unique whole-run IDs")
    if any(role not in ROLES for role in roles):
        errors.append("unknown normal run role")
    if roles.count("candidate_fit") != 1:
        errors.append("exactly one fit run is required")
    independent = roles.count("independent_evaluation")
    minimum_independent = int(
        evaluation.get("tracks", {}).get("syscall", {}).get(
            "minimum_independent_normal_runs", 0
        )
    )
    if independent < minimum_independent:
        errors.append("insufficient independent evaluation runs")
    if independent * len(regimes) < expected_phases:
        errors.append("insufficient independent evaluation phases")
    if int(normal.get("minutes_per_phase", 0)) < 1:
        errors.append("invalid phase duration")
    separation = contract.get("separation", {})
    if (
        separation.get("evaluation_runs_may_train_or_tune") is not False
        or separation.get("attack_windows_may_train_or_tune") is not False
        or separation.get("split_unit")
        != "whole run before feature-window construction"
    ):
        errors.append("fit/evaluation leakage exclusion is incomplete")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--evaluation-contract", required=True, type=Path)
    parser.add_argument("--vocab", required=True, type=Path)
    args = parser.parse_args()
    contract = json.loads(args.contract.read_text())
    evaluation = json.loads(args.evaluation_contract.read_text())
    errors = validate_contract(contract, evaluation, args.vocab)
    print(json.dumps({
        "contract_sha256": sha256(args.contract),
        "evaluation_contract_sha256": sha256(args.evaluation_contract),
        "vocab_sha256": sha256(args.vocab) if args.vocab.is_file() else None,
        "errors": errors,
        "valid": not errors,
    }, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
