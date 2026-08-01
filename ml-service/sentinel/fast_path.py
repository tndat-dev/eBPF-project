"""High-specificity syscall sequences for sub-second early warnings.

This module intentionally does *not* replace the ML detector.  It emits an
early-warning only for short, ordered sequences that are unlikely during the
three baseline workloads.  The existing windowed ML path remains the only
confirmation path and the only path connected to the responder.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import threading
import time
from typing import Callable, Optional

from sentinel.telemetry import detection_latency, emit


EXEC_SYSCALLS = frozenset({"execve", "execveat"})
PRIVILEGE_SYSCALLS = frozenset({
    "unshare", "mount", "setuid", "capset", "ptrace",
})
# Daemons commonly execute then drop their group before entering the request
# loop.  ``execve -> setgid`` is therefore a lifecycle transition, not a
# sufficiently specific early-warning signal.  Consume the remembered exec so
# a following benign ``setuid`` in the same initialization sequence cannot be
# paired with it either.  A fresh exec followed by setuid (the attack harness
# pattern) remains covered by the privilege-transition rule.
DAEMON_INITIALIZATION_SYSCALLS = frozenset({"setgid"})
NETWORK_EXEC_TOKENS = (
    "/sh", "/bash", "/dash", "/zsh", "/ksh", "/busybox",
    "/curl", "/wget", "/nc", "/ncat", "/socat",
)


def event_time(event) -> float:
    """Use Tetragon event time when valid, otherwise use receipt time."""
    raw = getattr(event, "timestamp", None)
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str) and raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return time.time()


def network_exec_candidate(event) -> bool:
    """Only a shell/network utility may open the exec-to-network rule."""
    binary = str(getattr(getattr(event, "process", None), "binary", "")).lower()
    return any(binary.endswith(token) for token in NETWORK_EXEC_TOKENS)


@dataclass(frozen=True)
class EarlyWarning:
    pod_key: str
    model_key: str
    rule: str
    first_syscall: str
    second_syscall: str
    first_event_ts: float
    detected_ts: float

    @property
    def sequence_seconds(self) -> float:
        return max(0.0, self.detected_ts - self.first_event_ts)

    def to_dict(self) -> dict:
        return {
            "pod_key": self.pod_key,
            "model_key": self.model_key,
            "rule": self.rule,
            "first_syscall": self.first_syscall,
            "second_syscall": self.second_syscall,
            "sequence_seconds": self.sequence_seconds,
            "severity": "early-warning",
        }


class FastPathDetector:
    """Thread-safe, bounded sequence detector for an early-warning lane."""

    def __init__(self, resolve_model: Callable[[str], Optional[str]], *,
                 sequence_seconds: float = 2.0, cooldown_seconds: float = 60.0,
                 confirmation_ttl_seconds: float = 180.0,
                 on_warning: Optional[Callable[[EarlyWarning], None]] = None):
        if sequence_seconds <= 0 or cooldown_seconds < 0:
            raise ValueError("invalid fast-path timing configuration")
        self.resolve_model = resolve_model
        self.sequence_seconds = sequence_seconds
        self.cooldown_seconds = cooldown_seconds
        self.confirmation_ttl_seconds = confirmation_ttl_seconds
        self.on_warning = on_warning or (lambda warning: None)
        # The latest exec is sufficient for the two-event grammar.  Keeping
        # only this tuple makes event handling O(1) even under attack bursts.
        self._last_exec = {}
        self._last_warning = {}
        self._warnings = {}
        self._lock = threading.Lock()

    def handle_event(self, event) -> Optional[EarlyWarning]:
        started = time.perf_counter()
        pod = getattr(event, "pod", None)
        namespace = getattr(pod, "namespace", None)
        name = getattr(pod, "name", None)
        syscall = str(getattr(event, "syscall_name", "")).lower()
        if not namespace or not name or not syscall:
            return None
        pod_key = f"{namespace}/{name}"
        model_key = self.resolve_model(pod_key)
        if model_key is None:
            return None

        timestamp = event_time(event)
        warning = None
        with self._lock:
            # The first event must be an exec.  The second event has to be a
            # privilege/namespace transition or a network connection. Network
            # additionally requires an interactive shell/network utility as
            # the exec binary; generic service execs are not enough.
            prior_exec = self._last_exec.get(pod_key)
            sequence_age = (
                timestamp - prior_exec[0] if prior_exec is not None else None
            )
            if (
                prior_exec and 0.0 <= sequence_age <= self.sequence_seconds
                and (
                    syscall in PRIVILEGE_SYSCALLS
                    or (syscall == "connect" and prior_exec[2])
                )
            ):
                rule = (
                    "exec_to_privilege_transition"
                    if syscall in PRIVILEGE_SYSCALLS else "exec_to_network"
                )
                last = self._last_warning.get((pod_key, rule), float("-inf"))
                if timestamp - last >= self.cooldown_seconds:
                    warning = EarlyWarning(
                        pod_key=pod_key, model_key=model_key, rule=rule,
                        first_syscall=prior_exec[1], second_syscall=syscall,
                        first_event_ts=prior_exec[0], detected_ts=timestamp,
                    )
                    self._last_warning[(pod_key, rule)] = timestamp
                    self._warnings[pod_key] = warning
            elif (
                prior_exec and syscall in DAEMON_INITIALIZATION_SYSCALLS
                and 0.0 <= sequence_age <= self.sequence_seconds
            ):
                self._last_exec.pop(pod_key, None)
            if syscall in EXEC_SYSCALLS:
                self._last_exec[pod_key] = (
                    timestamp, syscall, network_exec_candidate(event)
                )

        if warning is not None:
            emitted_at = time.time()
            emit(
                "early_warning", **warning.to_dict(),
                detection_latency=detection_latency(pod_key),
                event_to_warning_seconds=round(
                    max(0.0, emitted_at - warning.detected_ts), 6
                ),
                processing_ms=round((time.perf_counter() - started) * 1000.0, 4),
            )
            self.on_warning(warning)
        return warning

    def recent_warning(self, pod_key: str, now: Optional[float] = None) -> Optional[dict]:
        """Return warning context for ML confirmation without changing ML gates."""
        now = time.time() if now is None else now
        with self._lock:
            warning = self._warnings.get(pod_key)
            if warning is None or now - warning.detected_ts > self.confirmation_ttl_seconds:
                return None
            return warning.to_dict()
