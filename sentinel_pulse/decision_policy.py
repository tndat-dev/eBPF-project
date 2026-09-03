"""Checksum-bound same-window decision policy for Sentinel Pulse."""

from __future__ import annotations

import json
import math
from pathlib import Path

from .integrity import sha256_file


SCHEMA = "sentinel-pulse-decision-policy-v1"
SCHEMA_V2 = "sentinel-pulse-decision-policy-v2"
SCHEMA_V3 = "sentinel-pulse-decision-policy-v3"
ALLOWED_SECURITY_FIELDS = frozenset(
    {
        "connect",
        "socket",
        "clone",
        "clone3",
        "execve",
        "execveat",
        "mprotect",
        "openat",
        "ptrace",
        "setuid",
        "setgid",
        "capset",
        "pivot_root",
        "mount",
        "unshare",
        "setns",
        "seccomp",
    }
)


def load_decision_policy(path: Path) -> tuple[dict, str]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    schema = policy.get("schema")
    if schema not in {SCHEMA, SCHEMA_V2, SCHEMA_V3}:
        raise ValueError("unsupported Sentinel Pulse decision policy")
    if policy.get("frozen_before_blind_evaluation") is not True:
        raise ValueError("decision policy was not frozen before blind evaluation")
    confirmation = policy.get("same_window_corroboration", {})
    fields = confirmation.get("security_activity_fields", [])
    if (
        not fields
        or len(fields) != len(set(fields))
        or not set(fields).issubset(ALLOWED_SECURITY_FIELDS)
    ):
        raise ValueError("decision policy security fields are invalid")
    minimum_mass = int(confirmation.get("minimum_security_activity_mass", 0))
    if minimum_mass < 1:
        raise ValueError("decision policy minimum security activity must be positive")
    if confirmation.get("requires_raw_model_anomaly") is not True:
        raise ValueError("decision policy can alert without an ML anomaly")
    if confirmation.get("additional_window_wait") != 0:
        raise ValueError("decision policy violates the one-window latency contract")
    score_confirmation = policy.get("score_corroboration", {})
    minimum_score_excess = float(
        score_confirmation.get("minimum_excess_over_calibration_max", 0.0)
    )
    if not math.isfinite(minimum_score_excess) or minimum_score_excess < 0.0:
        raise ValueError("decision policy score excess must be finite and non-negative")
    if score_confirmation and score_confirmation.get("reference") != "per_workload_calibration_max":
        raise ValueError("decision policy score reference is unsupported")
    envelope = confirmation.get("workload_normal_envelope")
    if envelope is not None:
        groups = envelope.get("signal_groups", [])
        maxima = envelope.get("workload_group_maxima", {})
        names = [group.get("name") for group in groups if isinstance(group, dict)]
        if not groups or len(names) != len(groups) or len(names) != len(set(names)):
            raise ValueError("decision policy semantic signal groups are invalid")
        for group in groups:
            group_fields = group.get("fields", [])
            minimum_excess = group.get("minimum_excess")
            if (
                not group_fields
                or len(group_fields) != len(set(group_fields))
                or not set(group_fields).issubset(fields)
                or isinstance(minimum_excess, bool)
                or not isinstance(minimum_excess, int)
                or minimum_excess < 1
            ):
                raise ValueError("decision policy semantic signal group is invalid")
        if not isinstance(maxima, dict) or not maxima:
            raise ValueError("decision policy workload semantic maxima are missing")
        for workload, workload_maxima in maxima.items():
            if not isinstance(workload, str) or not workload or not isinstance(workload_maxima, dict):
                raise ValueError("decision policy workload semantic maximum is invalid")
            if set(workload_maxima) != set(names):
                raise ValueError("decision policy workload semantic groups are incomplete")
            if any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in workload_maxima.values()
            ):
                raise ValueError("decision policy workload semantic maximum is invalid")
    development = policy.get("development_normal_evidence", {})
    if schema == SCHEMA:
        required_hashes = (
            "failed_model_manifest_sha256",
            "canary_report_sha256",
            "alert_context_sha256",
        )
    else:
        required_hashes = (
            "dataset_sha256",
            "dataset_manifest_sha256",
            "semantic_envelope_calibration_sha256",
            "model_manifest_sha256",
            "training_contract_sha256",
            "base_policy_sha256",
        )
        if schema == SCHEMA_V3:
            required_hashes += ("temporal_calibration_sha256",)
        if (
            policy.get("blind_outcome_used") is not False
            or policy.get("automatic_promotion") is not False
            or not isinstance(policy.get("evidence_class"), str)
            or not policy["evidence_class"]
        ):
            raise ValueError("decision policy v2 evidence controls are incomplete")
        source_commit = policy.get("source_git_commit")
        source_diff = policy.get("source_git_diff_sha256")
        if (
            not isinstance(source_commit, str)
            or len(source_commit) not in (40, 64)
            or any(character not in "0123456789abcdef" for character in source_commit)
            or not isinstance(source_diff, str)
            or len(source_diff) != 64
            or any(character not in "0123456789abcdef" for character in source_diff)
        ):
            raise ValueError("decision policy v2 source provenance is incomplete")
    if schema == SCHEMA_V3:
        temporal = policy.get("bounded_event_time_corroboration", {})
        maximum_age = float(temporal.get("maximum_evidence_age_seconds", 0.0))
        if (
            temporal.get("mode") != "bounded_model_semantic_join"
            or not math.isfinite(maximum_age)
            or maximum_age <= 0.0
            or maximum_age > 2.0
            or temporal.get("requires_raw_model_anomaly") is not True
            or temporal.get("requires_score_corroboration") is not True
            or temporal.get("requires_semantic_corroboration") is not True
            or temporal.get("consume_on_alert") is not True
            or temporal.get("normal_only_calibration") is not True
        ):
            raise ValueError("bounded event-time corroboration contract is invalid")
        eligible_groups = temporal.get("eligible_semantic_signal_groups")
        if eligible_groups is not None and (
            not isinstance(eligible_groups, list)
            or not eligible_groups
            or len(eligible_groups) != len(set(eligible_groups))
            or envelope is None
            or not set(eligible_groups).issubset(set(names))
        ):
            raise ValueError("bounded event-time eligible semantic groups are invalid")
    confirmation = policy.get("temporal_confirmation")
    if confirmation is not None:
        required_windows = confirmation.get("required_consecutive_windows")
        per_group_windows = confirmation.get(
            "required_consecutive_windows_by_group", {}
        )
        maximum_gap = float(confirmation.get("maximum_gap_seconds", 0.0))
        bypass_groups = confirmation.get("immediate_bypass_signal_groups")
        if (
            schema != SCHEMA_V3
            or confirmation.get("mode") != "consecutive_same_group"
            or isinstance(required_windows, bool)
            or not isinstance(required_windows, int)
            or required_windows < 2
            or required_windows > 4
            or not math.isfinite(maximum_gap)
            or maximum_gap <= 0.0
            or maximum_gap > 2.0
            or confirmation.get("normal_only_calibration") is not True
            or confirmation.get("consume_on_alert") is not True
            or not isinstance(bypass_groups, list)
            or not bypass_groups
            or len(bypass_groups) != len(set(bypass_groups))
            or envelope is None
            or not isinstance(per_group_windows, dict)
            or any(
                not isinstance(group, str)
                or group not in set(names)
                or group in set(bypass_groups)
                or isinstance(value, bool)
                or not isinstance(value, int)
                or value < 2
                or value > 4
                for group, value in per_group_windows.items()
            )
            or not set(bypass_groups).issubset(set(names))
        ):
            raise ValueError("temporal confirmation contract is invalid")
        required_hashes += ("temporal_confirmation_calibration_sha256",)
    if not all(
        isinstance(development.get(field), str)
        and len(development[field]) == 64
        and all(character in "0123456789abcdef" for character in development[field])
        for field in required_hashes
    ):
        raise ValueError("decision policy development evidence is incomplete")
    return policy, sha256_file(path)


def corroboration_details(
    policy: dict, exact_counts: object, workload_key: str | None = None
) -> dict:
    if not isinstance(exact_counts, dict):
        raise ValueError("same-window decision policy requires exact syscall counts")
    confirmation = policy["same_window_corroboration"]
    observed = {}
    mass = 0
    for field in confirmation["security_activity_fields"]:
        value = int(exact_counts.get(field, 0))
        if value < 0:
            raise ValueError("exact syscall count cannot be negative")
        if value:
            observed[field] = value
            mass += value
    envelope = confirmation.get("workload_normal_envelope")
    if envelope is None:
        return {
            "confirmed": mass >= int(confirmation["minimum_security_activity_mass"]),
            "mass": mass,
            "observed_fields": observed,
            "signal_groups": {},
        }
    if workload_key is None:
        raise ValueError("workload semantic envelope requires a workload key")
    workload_maxima = envelope["workload_group_maxima"].get(workload_key)
    if workload_maxima is None:
        raise ValueError(f"workload semantic envelope is missing for {workload_key}")
    group_details = {}
    confirmed = False
    for group in envelope["signal_groups"]:
        name = group["name"]
        observed_mass = sum(int(exact_counts.get(field, 0)) for field in group["fields"])
        baseline_max = int(workload_maxima[name])
        excess = observed_mass - baseline_max
        triggered = excess >= int(group["minimum_excess"])
        confirmed = confirmed or triggered
        group_details[name] = {
            "observed": observed_mass,
            "normal_max": baseline_max,
            "excess": excess,
            "minimum_excess": int(group["minimum_excess"]),
            "triggered": triggered,
        }
    return {
        "confirmed": confirmed,
        "mass": mass,
        "observed_fields": observed,
        "signal_groups": group_details,
    }


def corroborate(
    policy: dict, exact_counts: object, workload_key: str | None = None
) -> tuple[bool, int, dict[str, int]]:
    details = corroboration_details(policy, exact_counts, workload_key)
    return details["confirmed"], details["mass"], details["observed_fields"]
