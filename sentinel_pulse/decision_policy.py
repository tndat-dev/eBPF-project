"""Checksum-bound same-window decision policy for Sentinel Pulse."""

from __future__ import annotations

import json
from pathlib import Path

from .integrity import sha256_file


SCHEMA = "sentinel-pulse-decision-policy-v1"
ALLOWED_SECURITY_FIELDS = frozenset(
    {
        "connect",
        "clone",
        "clone3",
        "execve",
        "execveat",
        "mprotect",
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
    development = policy.get("development_normal_evidence", {})
    if not all(
        isinstance(development.get(field), str)
        and len(development[field]) == 64
        and all(character in "0123456789abcdef" for character in development[field])
        for field in ("failed_model_manifest_sha256", "canary_report_sha256", "alert_context_sha256")
    ):
        raise ValueError("decision policy development evidence is incomplete")
    return policy, sha256_file(path)


def corroborate(policy: dict, exact_counts: object) -> tuple[bool, int, dict[str, int]]:
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
    return mass >= int(confirmation["minimum_security_activity_mass"]), mass, observed
