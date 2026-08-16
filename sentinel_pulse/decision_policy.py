"""Checksum-bound same-window decision policy for Sentinel Pulse."""

from __future__ import annotations

import json
import math
from pathlib import Path

from .integrity import sha256_file


SCHEMA = "sentinel-pulse-decision-policy-v1"
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
    if policy.get("schema") != SCHEMA:
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
    if not all(
        isinstance(development.get(field), str)
        and len(development[field]) == 64
        and all(character in "0123456789abcdef" for character in development[field])
        for field in ("failed_model_manifest_sha256", "canary_report_sha256", "alert_context_sha256")
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
