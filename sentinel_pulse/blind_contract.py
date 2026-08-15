"""Validation and matrix expansion for the frozen Pulse blind-attack contract."""

from __future__ import annotations

import json
from pathlib import Path


SCHEMA = "sentinel-pulse-blind-attack-contract-v1"
REQUIRED_SAFETY = {
    "external_network": False,
    "persistent_write": False,
    "successful_mount": False,
    "successful_privilege_change": False,
    "target_namespace": "production",
}


def load_contract(path: Path) -> dict:
    contract = json.loads(path.read_text(encoding="utf-8"))
    if contract.get("schema") != SCHEMA:
        raise ValueError("unsupported Pulse blind-attack contract")
    if contract.get("frozen_before_candidate_training") is not True:
        raise ValueError("blind-attack contract was not frozen before candidate training")
    matrix = contract.get("matrix", {})
    scenarios = matrix.get("scenarios", [])
    workloads = matrix.get("workload_controllers", [])
    trials = matrix.get("trials", [])
    if not scenarios or len(scenarios) != len(set(scenarios)):
        raise ValueError("blind-attack scenarios must be non-empty and unique")
    if not workloads or len(workloads) != len(set(workloads)):
        raise ValueError("blind-attack workloads must be non-empty and unique")
    trial_keys = []
    for trial in trials:
        seed = int(trial.get("seed", 0))
        rate = int(trial.get("rate_per_second", 0))
        if seed <= 0 or rate <= 0:
            raise ValueError("blind-attack seed/rate must be positive")
        trial_keys.append((seed, rate))
    if not trial_keys or len(trial_keys) != len(set(trial_keys)):
        raise ValueError("blind-attack seed/rate pairs must be non-empty and unique")
    expected = len(scenarios) * len(workloads) * len(trials)
    if int(contract.get("expected_injections", -1)) != expected:
        raise ValueError("blind-attack expected injection count does not match matrix")
    safety = contract.get("safety_contract", {})
    if any(safety.get(key) != value for key, value in REQUIRED_SAFETY.items()):
        raise ValueError("blind-attack safety contract is incomplete or unsafe")
    selection = contract.get("selection_policy", {})
    if (
        selection.get("attack_outcomes_used_for_training_or_tuning") is not False
        or selection.get("misses_are_retained") is not True
        or selection.get("rerun_detection_misses") is not False
    ):
        raise ValueError("blind-attack selection policy permits test-set leakage")
    return contract


def expected_matrix(contract: dict) -> set[tuple[str, str, int, int]]:
    matrix = contract["matrix"]
    return {
        (workload, scenario, int(trial["seed"]), int(trial["rate_per_second"]))
        for workload in matrix["workload_controllers"]
        for scenario in matrix["scenarios"]
        for trial in matrix["trials"]
    }


def marker_matrix_key(marker: dict) -> tuple[str, str, int, int]:
    try:
        return (
            str(marker["workload_controller"]),
            str(marker["scenario"]),
            int(marker["seed"]),
            int(marker["rate_per_second"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("blind injection marker has incomplete matrix identity") from error
