"""High-specificity syscall sequences for sub-second early warnings.

This mirror supports running ``anomaly_detector2.py`` from the repository root.
The deployed source of truth is ``ml-service/sentinel/fast_path.py``.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import threading
import time
from typing import Callable, Optional

from sentinel.telemetry import detection_latency, emit

EXEC_SYSCALLS = frozenset({"execve", "execveat"})
PRIVILEGE_SYSCALLS = frozenset({
    "unshare", "mount", "setuid", "capset", "ptrace",
})
DAEMON_INITIALIZATION_SYSCALLS = frozenset({"setgid"})
NETWORK_EXEC_TOKENS = ("/sh", "/bash", "/dash", "/zsh", "/ksh", "/busybox",
                       "/curl", "/wget", "/nc", "/ncat", "/socat")


def event_time(event) -> float:
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
        return {"pod_key": self.pod_key, "model_key": self.model_key,
                "rule": self.rule, "first_syscall": self.first_syscall,
                "second_syscall": self.second_syscall,
                "sequence_seconds": self.sequence_seconds,
                "severity": "early-warning"}


class FastPathDetector:
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
        self._last_exec, self._last_warning, self._warnings = {}, {}, {}
        self._lock = threading.Lock()

    def handle_event(self, event) -> Optional[EarlyWarning]:
        started = time.perf_counter()
        pod = getattr(event, "pod", None)
        namespace, name = getattr(pod, "namespace", None), getattr(pod, "name", None)
        syscall = str(getattr(event, "syscall_name", "")).lower()
        if not namespace or not name or not syscall:
            return None
        pod_key, model_key = f"{namespace}/{name}", self.resolve_model(f"{namespace}/{name}")
        if model_key is None:
            return None
        timestamp, warning = event_time(event), None
        with self._lock:
            prior_exec = self._last_exec.get(pod_key)
            sequence_age = timestamp - prior_exec[0] if prior_exec else None
            if prior_exec and 0.0 <= sequence_age <= self.sequence_seconds and (syscall in PRIVILEGE_SYSCALLS or (syscall == "connect" and prior_exec[2])):
                rule = "exec_to_privilege_transition" if syscall in PRIVILEGE_SYSCALLS else "exec_to_network"
                if timestamp - self._last_warning.get((pod_key, rule), float("-inf")) >= self.cooldown_seconds:
                    warning = EarlyWarning(pod_key, model_key, rule, prior_exec[1], syscall, prior_exec[0], timestamp)
                    self._last_warning[(pod_key, rule)] = timestamp
                    self._warnings[pod_key] = warning
            elif (
                prior_exec and syscall in DAEMON_INITIALIZATION_SYSCALLS
                and 0.0 <= sequence_age <= self.sequence_seconds
            ):
                self._last_exec.pop(pod_key, None)
            if syscall in EXEC_SYSCALLS:
                self._last_exec[pod_key] = (timestamp, syscall, network_exec_candidate(event))
        if warning:
            emitted_at = time.time()
            emit("early_warning", **warning.to_dict(), detection_latency=detection_latency(pod_key),
                 event_to_warning_seconds=round(max(0.0, emitted_at - warning.detected_ts), 6),
                 processing_ms=round((time.perf_counter() - started) * 1000.0, 4))
            self.on_warning(warning)
        return warning

    def recent_warning(self, pod_key: str, now: Optional[float] = None) -> Optional[dict]:
        now = time.time() if now is None else now
        with self._lock:
            warning = self._warnings.get(pod_key)
            if warning is None or now - warning.detected_ts > self.confirmation_ttl_seconds:
                return None
            return warning.to_dict()
