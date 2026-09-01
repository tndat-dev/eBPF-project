"""Validation and matrix expansion for the frozen Pulse blind-attack contract."""

from __future__ import annotations

import json
import math
from pathlib import Path


SCHEMA = "sentinel-pulse-blind-attack-contract-v1"
SCHEMA_V2 = "sentinel-pulse-blind-attack-contract-v2"
REQUIRED_SAFETY = {
    "external_network": False,
    "persistent_write": False,
    "successful_mount": False,
    "successful_privilege_change": False,
    "target_namespace": "production",
}


def load_contract(path: Path) -> dict:
    contract = json.loads(path.read_text(encoding="utf-8"))
    schema = contract.get("schema")
    if schema not in {SCHEMA, SCHEMA_V2}:
        raise ValueError("unsupported Pulse blind-attack contract")
    excluded: list[str] = []
    if schema == SCHEMA:
        if contract.get("frozen_before_candidate_training") is not True:
            raise ValueError("blind-attack contract was not frozen before candidate training")
    else:
        if (
            contract.get("frozen_before_candidate_evaluation") is not True
            or contract.get("candidate_parameters_locked_before_contract_authoring") is not True
        ):
            raise ValueError("successor blind contract was not frozen before evaluation")
        binding = contract.get("candidate_binding", {})
        for field in ("model_manifest_sha256", "decision_policy_sha256"):
            digest = binding.get(field)
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise ValueError("successor blind contract candidate binding is invalid")
        runtime_commit = binding.get("runtime_source_git_commit")
        if runtime_commit is not None and (
            not isinstance(runtime_commit, str)
            or len(runtime_commit) != 40
            or any(character not in "0123456789abcdef" for character in runtime_commit)
        ):
            raise ValueError("successor blind contract runtime binding is invalid")
        independence = contract.get("independence", {})
        excluded = independence.get("excluded_predecessor_scenarios", [])
        if (
            independence.get("predecessor_outcomes_used_to_select_these_scenarios") is not False
            or not excluded
            or len(excluded) != len(set(excluded))
        ):
            raise ValueError("successor blind contract independence controls are invalid")
        predecessor_digest = independence.get(
            "derived_from_unused_contract_sha256"
        )
        predecessor_started = independence.get(
            "predecessor_contract_candidate_evaluation_started"
        )
        if predecessor_digest is not None or predecessor_started is not None:
            if (
                not isinstance(predecessor_digest, str)
                or len(predecessor_digest) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in predecessor_digest
                )
                or predecessor_started is not False
            ):
                raise ValueError(
                    "successor blind contract predecessor binding is invalid"
                )
    matrix = contract.get("matrix", {})
    scenarios = matrix.get("scenarios", [])
    workloads = matrix.get("workload_controllers", [])
    trials = matrix.get("trials", [])
    if not scenarios or len(scenarios) != len(set(scenarios)):
        raise ValueError("blind-attack scenarios must be non-empty and unique")
    if schema == SCHEMA_V2 and set(scenarios) & set(excluded):
        raise ValueError("successor blind contract reuses a predecessor scenario")
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
        workload_controller = str(marker["workload_controller"])
        workload_key = str(marker["workload_key"])
        cgroup_id = int(marker["cgroup_id"])
        injected_at = float(marker["injected_at"])
        scenario = str(marker["scenario"])
        seed = int(marker["seed"])
        rate = int(marker["rate_per_second"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("blind injection marker has incomplete matrix identity") from error
    namespace_controller, separator, container = workload_key.partition(":")
    namespace, slash, observed_controller = namespace_controller.partition("/")
    if (
        separator != ":"
        or slash != "/"
        or namespace != "production"
        or observed_controller != workload_controller
        or not container
        or cgroup_id <= 0
        or not math.isfinite(injected_at)
    ):
        raise ValueError("blind injection marker target identity is inconsistent")
    return (
        workload_controller,
        scenario,
        seed,
        rate,
    )
