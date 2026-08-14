"""Feature construction for the one-second Sentinel Pulse ML path.

Tetragon's event rate limiting is useful for detailed event export, but its
sampled event counts cannot represent the true syscall distribution.  Pulse
therefore consumes cumulative eBPF map snapshots, computes exact deltas, and
uses Tetragon only as a sparse semantic channel.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Mapping, Sequence, Tuple
import math

import numpy as np


# Stable x86_64 syscall identifiers used for explicit, interpretable features.
# Every other syscall remains represented by total/other and transition bins.
TRACKED_SYSCALLS: Mapping[int, str] = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    9: "mmap",
    10: "mprotect",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    56: "clone",
    59: "execve",
    90: "chmod",
    101: "ptrace",
    105: "setuid",
    106: "setgid",
    126: "capset",
    155: "pivot_root",
    165: "mount",
    257: "openat",
    272: "unshare",
    288: "accept4",
    299: "recvmmsg",
    307: "sendmmsg",
    308: "setns",
    317: "seccomp",
    322: "execveat",
    435: "clone3",
}

SENSITIVE_IDS = frozenset({10, 59, 101, 105, 106, 126, 155, 165, 272, 308, 317, 322})


@dataclass(frozen=True)
class PulseSnapshot:
    """One cumulative map snapshot for a single cgroup."""

    cgroup_id: int
    observed_at: float
    counts: Mapping[int, int]
    transitions: Mapping[Tuple[int, int], int]
    syscall_bins: Mapping[int, int] = field(default_factory=dict)
    transition_bins: Mapping[int, int] = field(default_factory=dict)
    seccomp_denied: int = 0


@dataclass(frozen=True)
class PulseFeature:
    cgroup_id: int
    workload_key: str
    window_start: float
    window_end: float
    columns: Tuple[str, ...]
    vector: np.ndarray
    exact_counts: Mapping[str, int]
    exact_total: int

    @property
    def telemetry_latency_seconds(self) -> float:
        return max(0.0, self.window_end - self.window_start)

    def as_record(self) -> dict:
        return {
            "schema": "sentinel-pulse-feature-v1",
            "cgroup_id": self.cgroup_id,
            "workload_key": self.workload_key,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "columns": list(self.columns),
            "vector": self.vector.astype(float).tolist(),
            "exact_counts": dict(self.exact_counts),
            "exact_total": self.exact_total,
        }


class PulseFeatureBuilder:
    """Convert cumulative snapshots into exact one-second rolling features.

    Counter resets are treated as a new baseline rather than negative traffic.
    No feature is emitted for the first snapshot because it has no valid delta.
    """

    def __init__(
        self, rolling_windows: int = 5, syscall_bins: int = 64, transition_bins: int = 64
    ):
        if rolling_windows < 2:
            raise ValueError("rolling_windows must be >= 2")
        if transition_bins < 8:
            raise ValueError("transition_bins must be >= 8")
        if syscall_bins < 8:
            raise ValueError("syscall_bins must be >= 8")
        if syscall_bins & (syscall_bins - 1) or transition_bins & (transition_bins - 1):
            raise ValueError("hash bin counts must be powers of two")
        self.rolling_windows = rolling_windows
        self.syscall_bins = syscall_bins
        self.transition_bins = transition_bins
        self._previous: Dict[int, PulseSnapshot] = {}
        self._history: Dict[int, Deque[np.ndarray]] = {}
        names = tuple(TRACKED_SYSCALLS.values())
        self.columns = (
            tuple(f"log_count:{name}" for name in names)
            + tuple(f"ratio:{name}" for name in names)
            + ("log_count:other", "ratio:other", "log_total", "sensitive_ratio", "seccomp_denied")
            + tuple(f"syscall_bin:{index}" for index in range(syscall_bins))
            + tuple(f"transition_bin:{index}" for index in range(transition_bins))
            + tuple(f"rolling_mean:{name}" for name in names)
            + tuple(f"rolling_std:{name}" for name in names)
        )

    @staticmethod
    def _delta(current: Mapping, previous: Mapping) -> Dict:
        result = {}
        for key, value in current.items():
            old = int(previous.get(key, 0))
            value = int(value)
            result[key] = value - old if value >= old else value
        return result

    def _transition_bin(self, previous_id: int, current_id: int) -> int:
        value = ((previous_id * 31 + current_id) * 2654435761) & 0xFFFFFFFF
        return value >> (32 - int(math.log2(self.transition_bins)))

    def _syscall_bin(self, syscall_id: int) -> int:
        value = (syscall_id * 2654435761) & 0xFFFFFFFF
        return value >> (32 - int(math.log2(self.syscall_bins)))

    def ingest(self, snapshot: PulseSnapshot, workload_key: str) -> PulseFeature | None:
        previous = self._previous.get(snapshot.cgroup_id)
        self._previous[snapshot.cgroup_id] = snapshot
        if previous is None or snapshot.observed_at <= previous.observed_at:
            return None

        interval = snapshot.observed_at - previous.observed_at
        count_delta = self._delta(snapshot.counts, previous.counts)
        transition_delta = self._delta(snapshot.transitions, previous.transitions)
        syscall_bin_delta = self._delta(snapshot.syscall_bins, previous.syscall_bins)
        transition_bin_delta = self._delta(snapshot.transition_bins, previous.transition_bins)
        denied_delta = self._delta({0: snapshot.seccomp_denied}, {0: previous.seccomp_denied})[0]
        total = sum(syscall_bin_delta.values()) if syscall_bin_delta else sum(count_delta.values())
        if total <= 0:
            return None

        names = tuple(TRACKED_SYSCALLS.values())
        selected = np.asarray([count_delta.get(number, 0) for number in TRACKED_SYSCALLS], dtype=np.float64)
        selected_total = int(selected.sum())
        other = max(0, total - selected_total)
        denominator = float(max(total, 1))
        rates = selected / interval

        history = self._history.setdefault(
            snapshot.cgroup_id, deque(maxlen=self.rolling_windows)
        )
        historical = np.vstack(history) if history else rates.reshape(1, -1)
        rolling_mean = historical.mean(axis=0)
        rolling_std = historical.std(axis=0)

        bins = np.zeros(self.transition_bins, dtype=np.float64)
        transition_total = sum(transition_bin_delta.values()) if transition_bin_delta else sum(transition_delta.values())
        if transition_bin_delta:
            for index, count in transition_bin_delta.items():
                bins[int(index) % self.transition_bins] += count
            bins /= float(transition_total)
        elif transition_total:
            for (left, right), count in transition_delta.items():
                bins[self._transition_bin(left, right)] += count
            bins /= float(transition_total)

        syscall_bins = np.zeros(self.syscall_bins, dtype=np.float64)
        if syscall_bin_delta:
            for index, count in syscall_bin_delta.items():
                syscall_bins[int(index) % self.syscall_bins] += count
        else:
            for syscall_id, count in count_delta.items():
                syscall_bins[self._syscall_bin(int(syscall_id))] += count
        syscall_bins /= denominator

        sensitive = sum(count_delta.get(number, 0) for number in SENSITIVE_IDS)
        vector = np.concatenate(
            (
                np.log1p(selected),
                selected / denominator,
                np.asarray(
                    [math.log1p(other), other / denominator, math.log1p(total), sensitive / denominator, denied_delta],
                    dtype=np.float64,
                ),
                syscall_bins,
                bins,
                np.log1p(rolling_mean),
                np.log1p(rolling_std),
            )
        ).astype(np.float32)
        history.append(rates)
        exact = {name: int(count_delta.get(number, 0)) for number, name in TRACKED_SYSCALLS.items()}
        exact["other"] = other
        return PulseFeature(
            cgroup_id=snapshot.cgroup_id,
            workload_key=workload_key,
            window_start=previous.observed_at,
            window_end=snapshot.observed_at,
            columns=self.columns,
            vector=vector,
            exact_counts=exact,
            exact_total=total,
        )
