"""Extract checksumable kernel event evidence for one blind injection.

Only Tetragon ``process_exec`` records for the frozen static attack binary are
accepted.  This module does not decide whether an attack was detected; it only
establishes an independently timestamped kernel origin for latency evaluation.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import math
import shlex


SCHEMA = "sentinel-pulse-kernel-event-v1"
EXEC_PROVENANCE_POLICY = "sentinel-pulse-exec-provenance"


def timestamp(value: str) -> float:
    """Parse RFC3339 timestamps including nanosecond fractions."""
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # datetime supports microseconds. Truncate only excess fractional digits,
    # retaining the timezone and a deterministic epoch representation.
    if "." in text:
        prefix, suffix = text.split(".", 1)
        digits = ""
        while suffix and suffix[0].isdigit():
            digits += suffix[0]
            suffix = suffix[1:]
        text = f"{prefix}.{digits[:6]}{suffix}"
    return datetime.fromisoformat(text).timestamp()


def _candidate(
    record: dict,
    marker: dict,
    *,
    expected_binary: str,
    maximum_delay_seconds: float,
) -> dict | None:
    event = record.get("process_exec")
    if not isinstance(event, dict):
        return None
    process = event.get("process")
    if not isinstance(process, dict) or process.get("binary") != expected_binary:
        return None
    pod = process.get("pod")
    if not isinstance(pod, dict):
        return None
    if (
        pod.get("namespace") != "production"
        or pod.get("uid") != marker.get("pod_uid")
        or pod.get("name") != marker.get("pod_name")
        or record.get("node_name") != marker.get("node_name")
    ):
        return None
    arguments = shlex.split(str(process.get("arguments", "")))
    expected_arguments = [
        str(marker["scenario"]),
        str(marker["duration_seconds"]),
        str(marker["rate_per_second"]),
        str(marker["seed"]),
    ]
    if arguments != expected_arguments:
        return None
    event_at = timestamp(str(record.get("time") or process.get("start_time")))
    injected_at = float(marker["injected_at"])
    if (
        not math.isfinite(event_at)
        or event_at < injected_at - 0.050
        or event_at > injected_at + maximum_delay_seconds
    ):
        return None
    return {
        "schema": SCHEMA,
        "injection_id": marker["injection_id"],
        "kernel_event_at": event_at,
        "kernel_event_rfc3339": record.get("time") or process.get("start_time"),
        "source": "tetragon_process_exec",
        "exec_id": process.get("exec_id"),
        "pid": process.get("pid"),
        "node_name": marker["node_name"],
        "pod_name": marker["pod_name"],
        "pod_uid": marker["pod_uid"],
        "workload_key": marker["workload_key"],
        "workload_controller": marker["workload_controller"],
        "scenario": marker["scenario"],
        "seed": int(marker["seed"]),
        "rate_per_second": int(marker["rate_per_second"]),
        "binary": expected_binary,
        "raw_event_sha256": hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "raw_event": record,
    }


def find_exec_event(
    lines,
    marker: dict,
    *,
    expected_binary: str,
    maximum_delay_seconds: float = 10.0,
) -> dict:
    """Return exactly one matching event or fail the trial as infrastructure."""
    matches = []
    for line in lines:
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        item = _candidate(
            record,
            marker,
            expected_binary=expected_binary,
            maximum_delay_seconds=maximum_delay_seconds,
        )
        if item is not None:
            matches.append(item)
    identities = {item.get("exec_id") for item in matches}
    if len(matches) != 1 or len(identities) != 1 or None in identities:
        raise ValueError(
            f"expected exactly one Tetragon exec event, observed {len(matches)}"
        )
    return matches[0]


def find_execve_kprobe_event(
    lines,
    marker: dict,
    *,
    expected_binary: str,
    policy_name: str = EXEC_PROVENANCE_POLICY,
    maximum_delay_seconds: float = 10.0,
) -> dict:
    """Find the exact execve entry event from a live Tetragon gRPC capture.

    ``process_exec`` is useful enrichment but can be absent from the stdout
    exporter for short-lived container-exec tasks.  This path consumes the
    dedicated, exact-path ``sys_execve`` tracing policy directly from gRPC.
    Trials remain serialized, so one exact binary event is required.
    """
    matches = []
    for line in lines:
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        event = record.get("process_kprobe")
        if not isinstance(event, dict):
            continue
        if (
            event.get("policy_name") != policy_name
            or str(event.get("function_name", "")).split("__x64_")[-1] != "sys_execve"
            or record.get("node_name") != marker.get("node_name")
        ):
            continue
        paths = [
            str(item.get("string_arg"))
            for item in event.get("args", [])
            if isinstance(item, dict) and item.get("string_arg") is not None
        ]
        if paths != [expected_binary]:
            continue
        event_at = timestamp(str(record.get("time")))
        injected_at = float(marker["injected_at"])
        if (
            not math.isfinite(event_at)
            or event_at < injected_at - 0.050
            or event_at > injected_at + maximum_delay_seconds
        ):
            continue
        process = event.get("process") if isinstance(event.get("process"), dict) else {}
        matches.append({
            "schema": SCHEMA,
            "injection_id": marker["injection_id"],
            "kernel_event_at": event_at,
            "kernel_event_rfc3339": record.get("time"),
            "source": "tetragon_execve_kprobe_grpc",
            "policy_name": policy_name,
            "exec_id": process.get("exec_id"),
            "pid": process.get("pid"),
            "node_name": marker["node_name"],
            "pod_name": marker["pod_name"],
            "pod_uid": marker["pod_uid"],
            "workload_key": marker["workload_key"],
            "workload_controller": marker["workload_controller"],
            "scenario": marker["scenario"],
            "seed": int(marker["seed"]),
            "rate_per_second": int(marker["rate_per_second"]),
            "binary": expected_binary,
            "identity_scope": "serialized_node_exact_binary",
            "raw_event_sha256": hashlib.sha256(
                json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "raw_event": record,
        })
    identities = {item.get("raw_event_sha256") for item in matches}
    if len(matches) != 1 or len(identities) != 1:
        raise ValueError(
            f"expected exactly one Tetragon execve kprobe event, observed {len(matches)}"
        )
    return matches[0]
