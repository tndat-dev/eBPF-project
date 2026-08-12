"""Append-only writer for privacy-minimised paired-replay evidence.

The capture is deliberately separate from general detector telemetry.  A
single ``os.write`` to an ``O_APPEND`` descriptor keeps rows intact when the
detector and attack orchestrator append to the same file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import time


FEATURE_SCHEMA = "sentinel-feature-window/v2"
INJECTION_SCHEMA = "sentinel-injection-interval/v2"
CAPTURE_KINDS = frozenset({"feature_window", "injection", "injection_end"})


def feature_window_evidence(fv, mode: str) -> dict:
    """Convert a feature vector to a privacy-minimised replay row."""
    if mode not in ("aggregate", "sequence"):
        raise ValueError(f"invalid feature capture mode: {mode}")
    payload = {
        "schema": FEATURE_SCHEMA,
        "pod_key": fv.pod_key,
        "node_name": fv.node_name,
        "window_start": float(fv.window_start),
        "window_end": float(fv.window_end),
        "event_count": fv.total_events(),
        "vector_size": len(fv.vector),
        "sparse_vector": [
            [index, round(float(value), 8)]
            for index, value in enumerate(fv.vector)
            if float(value) != 0.0
        ],
        "syscall_counts": {
            name: int(count)
            for name, count in sorted(fv.syscall_counts.items())
        },
        "contains_arguments_or_payloads": False,
        "capture_mode": mode,
    }
    if mode == "sequence":
        payload["syscall_sequence"] = list(fv.raw_syscalls)
    return payload


def append_capture_row(path: str | Path, kind: str, **data) -> None:
    """Append one compact JSON row without routing through metrics telemetry."""
    if kind not in CAPTURE_KINDS:
        raise ValueError(f"unsupported feature-capture row kind: {kind}")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    row = {"kind": kind, "ts": time.time(), **data}
    encoded = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(
        target, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600,
    )
    try:
        written = os.write(descriptor, encoded)
        if written != len(encoded):
            raise OSError(f"short feature-capture write: {written}/{len(encoded)}")
    finally:
        os.close(descriptor)
