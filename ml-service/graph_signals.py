"""Workload-conditioned kernel behavior gates and explainability helpers."""
from collections import Counter
from math import sqrt

import numpy as np


BEHAVIOR_SYSCALLS = (
    "execve", "execveat", "clone", "clone3", "unshare", "mount",
    "ptrace", "setuid", "setgid", "capset", "connect",
)
SUSPICIOUS = set(BEHAVIOR_SYSCALLS)
DEFAULT_LIMITS = {
    # One incidental privileged/process event must not isolate a pod. The
    # attack regressions emit sustained behavior well above these floors.
    **{name: 0.02 for name in (
        "execve", "execveat", "unshare", "mount", "ptrace",
        "setuid", "setgid", "capset",
    )},
    "clone": 0.05,
    "clone3": 0.05,
    "connect": 0.05,
}
BEHAVIOR_CONFIDENCE_Z = 1.6448536269514722  # one-sided 95%


def wilson_lower(count, total, z=BEHAVIOR_CONFIDENCE_Z):
    """One-sided Wilson lower bound for a syscall proportion.

    Runtime windows can contain only a few sampled events. A raw rate such as
    2/14 must not be treated as stronger evidence than the same rate measured
    over hundreds of events. Fractional ``count`` is accepted so the offline
    frequency vectors can be reconstructed with their recorded event totals.
    """
    n = max(float(total), 1.0)
    successes = min(max(float(count), 0.0), n)
    proportion = successes / n
    z2 = z * z
    denominator = 1.0 + z2 / n
    center = proportion + z2 / (2.0 * n)
    radius = z * sqrt(
        max(proportion * (1.0 - proportion) + z2 / (4.0 * n), 0.0) / n
    )
    return float(max(0.0, (center - radius) / denominator))


def fit_behavior_limits(vectors, vocab, quantile=0.995, margin=0.02):
    """Fit robust per-syscall frequency limits on training-only vectors."""
    matrix = np.asarray(vectors, dtype=float)
    if matrix.ndim != 2:
        raise ValueError(f"expected 2-D behavior baseline, got {matrix.shape}")
    limits = {}
    for name in BEHAVIOR_SYSCALLS:
        index = vocab.get(name)
        values = (
            matrix[:, index] if index is not None
            else np.zeros(len(matrix), dtype=float)
        )
        values = values[np.isfinite(values)]
        if not len(values):
            values = np.zeros(1, dtype=float)
        median = float(np.median(values))
        mad = float(np.median(np.abs(values - median))) * 1.4826
        empirical = float(np.quantile(values, quantile))
        # Eight robust deviations plus an absolute 2%-of-window margin keeps
        # ordinary DB connection/fork activity inside its own workload gate.
        limit = max(
            DEFAULT_LIMITS[name],
            empirical + max(margin, 8.0 * mad),
        )
        limits[name] = float(np.clip(limit, DEFAULT_LIMITS[name], 0.95))
    return limits


def evaluate_behavior(syscall_counts, total, limits=None):
    """Return independent behavior evidence for the model-score gate."""
    total = max(int(total), 1)
    frequencies = {
        name: float(syscall_counts.get(name, 0)) / total
        for name in BEHAVIOR_SYSCALLS
    }
    if limits:
        confidence_lowers = {
            name: wilson_lower(syscall_counts.get(name, 0), total)
            for name in BEHAVIOR_SYSCALLS
        }
        ratios = {
            name: confidence_lowers[name] / max(float(limits.get(
                name, DEFAULT_LIMITS[name]
            )), 1e-9)
            for name in BEHAVIOR_SYSCALLS
        }
        syscall = max(ratios, key=ratios.get)
        return {
            "gate": bool(ratios[syscall] > 1.0),
            "syscall": syscall,
            "frequency": frequencies[syscall],
            "confidence_lower": confidence_lowers[syscall],
            "confidence_level": 0.95,
            "limit": float(limits.get(syscall, DEFAULT_LIMITS[syscall])),
            "max_ratio": float(ratios[syscall]),
            "method": "workload-conditioned-wilson",
            "suspicious_mass": float(sum(frequencies.values())),
        }

    # Backward compatibility for V1–V6 bundles. New candidates always persist
    # conditioned limits in their bundle.
    mass = float(sum(frequencies.values()))
    return {
        "gate": bool(mass >= 0.10),
        "syscall": max(frequencies, key=frequencies.get),
        "frequency": max(frequencies.values()),
        "limit": 0.10,
        "max_ratio": mass / 0.10,
        "method": "legacy-aggregate",
        "suspicious_mass": mass,
    }


def behavior_signals(syscall_counts, total, limits=None):
    total = max(int(total), 1)
    rows = []
    for name, count in Counter(syscall_counts).most_common(8):
        frequency = count / total
        confidence_lower = wilson_lower(count, total)
        limit = (limits or {}).get(name)
        rows.append({
            "name": name,
            "freq": frequency,
            "confidence_lower": confidence_lower,
            "signal": (
                "suspicious" if name in SUSPICIOUS and (
                    limit is None or confidence_lower > limit
                ) else "normal"
            ),
            "behavior_limit": limit,
        })
    return rows
