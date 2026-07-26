"""Low-overhead JSONL telemetry for reproducible Sentinel experiments."""
from __future__ import annotations

import json
import os
import threading
import time


_lock = threading.Lock()
_injections = {}


def _metrics_path():
    return os.environ.get("SENTINEL_METRICS", "metrics.jsonl")


def inject(pod_key, attack_type):
    timestamp = time.time()
    _injections[pod_key] = timestamp
    emit("injection", pod_key=pod_key, attack_type=attack_type, ts=timestamp)
    return timestamp


def _latest_external_injection(pod_key):
    """Read the newest orchestrator injection from the shared JSONL tail."""
    try:
        with open(_metrics_path(), "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 64 * 1024))
            lines = handle.read().decode("utf-8", errors="ignore").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            row = json.loads(line)
        except (TypeError, ValueError):
            continue
        if row.get("kind") == "injection" and row.get("pod_key") == pod_key:
            try:
                return float(row["ts"])
            except (KeyError, TypeError, ValueError):
                return None
    return None


def detection_latency(pod_key):
    now = time.time()
    start = _injections.get(pod_key)
    if start is None:
        start = _latest_external_injection(pod_key)
    if start is None or start > now:
        return None
    return now - start


def emit(kind, **data):
    row = {"kind": kind, "ts": time.time(), **data}
    with _lock:
        with open(_metrics_path(), "a") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
