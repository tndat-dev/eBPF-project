"""Summarize blind detection and independently timestamped kernel-to-alert latency.

The live detector uses a pre-exec injection marker only to associate an alert
with a frozen blind trial.  Paper latency is recomputed here from a separate
Tetragon kernel event record; a userspace launch timestamp is never promoted
to a kernel-to-alert claim.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable
import hashlib
import json
import math
from pathlib import Path

import numpy as np

from .blind_contract import expected_matrix, load_contract, marker_matrix_key
from .integrity import sha256_file
from .tetragon_evidence import (
    EXEC_PROVENANCE_POLICY,
    timestamp as tetragon_timestamp,
)


def injection_markers(path: Path) -> dict[str, dict]:
    result = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            record = json.loads(line)
            if record.get("schema") != "sentinel-pulse-injection-v1":
                continue
            injection_id = str(record["injection_id"])
            if injection_id in result:
                raise ValueError(f"duplicate injection ID at line {line_number}: {injection_id}")
            result[injection_id] = record
    if not result:
        raise ValueError("injection marker file has no valid ID")
    return result


def injection_ids(path: Path) -> set[str]:
    return set(injection_markers(path))


def kernel_events(path: Path) -> dict[str, dict]:
    """Load one immutable Tetragon event identity for every injection."""
    result = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            record = json.loads(line)
            if record.get("schema") != "sentinel-pulse-kernel-event-v1":
                continue
            injection_id = str(record.get("injection_id", ""))
            if not injection_id or injection_id in result:
                raise ValueError(
                    f"missing or duplicate kernel event identity at line {line_number}"
                )
            try:
                timestamp = float(record["kernel_event_at"])
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(
                    f"invalid kernel event timestamp at line {line_number}"
                ) from error
            source = record.get("source")
            if (
                not math.isfinite(timestamp)
                or source not in {
                    "tetragon_process_exec",
                    "tetragon_execve_kprobe_grpc",
                }
                or not record.get("exec_id")
                or not record.get("node_name")
                or not record.get("pod_uid")
            ):
                raise ValueError(
                    f"incomplete kernel event provenance at line {line_number}"
                )
            raw = record.get("raw_event")
            if not isinstance(raw, dict):
                raise ValueError(f"missing raw Tetragon event at line {line_number}")
            canonical = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
            if hashlib.sha256(canonical).hexdigest() != record.get("raw_event_sha256"):
                raise ValueError(f"raw Tetragon event checksum mismatch at line {line_number}")
            if source == "tetragon_process_exec":
                event = raw.get("process_exec")
                process = event.get("process") if isinstance(event, dict) else None
                pod = process.get("pod") if isinstance(process, dict) else None
                if (
                    not isinstance(pod, dict)
                    or process.get("exec_id") != record.get("exec_id")
                    or process.get("binary") != record.get("binary")
                    or raw.get("node_name") != record.get("node_name")
                    or pod.get("name") != record.get("pod_name")
                    or pod.get("uid") != record.get("pod_uid")
                    or pod.get("namespace") != "production"
                ):
                    raise ValueError(
                        f"raw Tetragon event identity mismatch at line {line_number}"
                    )
                raw_time = raw.get("time") or process.get("start_time")
            else:
                event = raw.get("process_kprobe")
                process = event.get("process") if isinstance(event, dict) else None
                arguments = event.get("args") if isinstance(event, dict) else None
                paths = [
                    str(item.get("string_arg"))
                    for item in arguments or []
                    if isinstance(item, dict) and item.get("string_arg") is not None
                ]
                function = str(event.get("function_name", "")) if isinstance(event, dict) else ""
                if (
                    not isinstance(process, dict)
                    or record.get("identity_scope") != "serialized_node_exact_binary"
                    or record.get("policy_name") != EXEC_PROVENANCE_POLICY
                    or event.get("policy_name") != EXEC_PROVENANCE_POLICY
                    or function.split("__x64_")[-1] != "sys_execve"
                    or paths != [record.get("binary")]
                    or process.get("exec_id") != record.get("exec_id")
                    or process.get("pid") != record.get("pid")
                    or raw.get("node_name") != record.get("node_name")
                ):
                    raise ValueError(
                        f"raw Tetragon execve provenance mismatch at line {line_number}"
                    )
                raw_time = raw.get("time")
            raw_timestamp = tetragon_timestamp(str(raw_time))
            if abs(raw_timestamp - timestamp) > 1e-6:
                raise ValueError(f"raw Tetragon event timestamp mismatch at line {line_number}")
            result[injection_id] = record
    if not result:
        raise ValueError("kernel event file has no valid Tetragon event")
    return result


def _decision_paths(path: Path | Iterable[Path]) -> list[Path]:
    if isinstance(path, Path):
        return [path]
    paths = list(path)
    if not paths:
        raise ValueError("at least one blind decision source is required")
    return paths


def evaluate(
    path: Path | Iterable[Path],
    expected_injections: int | None = None,
    injection_path: Path | None = None,
    attack_contract_path: Path | None = None,
    kernel_event_path: Path | None = None,
    expected_run_id: str | None = None,
) -> dict:
    by_injection = {}
    processing = []
    inference = []
    model_identities = set()
    decision_policy_identities = set()
    run_identities = set()
    paths = _decision_paths(path)
    for decision_path in paths:
        with decision_path.open(encoding="utf-8") as handle:
            for line in handle:
                record = json.loads(line)
                if record.get("schema") != "sentinel-pulse-decision-v1":
                    continue
                model_identities.add(str(record.get("model_manifest_sha256", "")))
                policy_identity = record.get("decision_policy_sha256")
                if policy_identity is not None:
                    decision_policy_identities.add(str(policy_identity))
                run_identities.add(str(record.get("run_id", "")))
                if "post_window_processing_seconds" in record:
                    processing.append(float(record["post_window_processing_seconds"]))
                if "inference_ms" in record:
                    inference.append(float(record["inference_ms"]))
                injection_id = record.get("injection_id")
                alerted_at = record.get("alerted_at")
                if injection_id is not None and alerted_at is not None:
                    injection_id = str(injection_id)
                    timestamp = float(alerted_at)
                    previous = by_injection.get(injection_id)
                    if previous is None or timestamp < float(previous["alerted_at"]):
                        by_injection[injection_id] = record

    def summary(values):
        if not values:
            return {}
        return {
            "min": float(np.min(values)),
            "p50": float(np.quantile(values, 0.50)),
            "p95": float(np.quantile(values, 0.95)),
            "p99": float(np.quantile(values, 0.99)),
            "max": float(np.max(values)),
        }

    markers = injection_markers(injection_path) if injection_path is not None else None
    events = kernel_events(kernel_event_path) if kernel_event_path is not None else None
    expected_ids = set(markers) if markers is not None else None
    contract = load_contract(attack_contract_path) if attack_contract_path is not None else None
    contract_matrix = expected_matrix(contract) if contract is not None else None
    observed_matrix = None
    missing_matrix = []
    unknown_matrix = []
    if contract_matrix is not None:
        if markers is None:
            raise ValueError("blind-attack contract requires an immutable marker file")
        marker_keys = [marker_matrix_key(marker) for marker in markers.values()]
        if len(marker_keys) != len(set(marker_keys)):
            raise ValueError("duplicate blind-attack matrix row in marker file")
        observed_matrix = set(marker_keys)
        missing_matrix = sorted(contract_matrix - observed_matrix)
        unknown_matrix = sorted(observed_matrix - contract_matrix)
        contract_expected = int(contract["expected_injections"])
        if expected_injections is not None and expected_injections != contract_expected:
            raise ValueError("CLI expected injection count differs from blind-attack contract")
        expected_injections = contract_expected
    if expected_ids is not None and expected_injections is not None and len(expected_ids) != expected_injections:
        raise ValueError("expected injection count does not match immutable marker set")
    observed_ids = set(by_injection)
    unknown_ids = sorted(observed_ids - expected_ids) if expected_ids is not None else []
    valid_ids = observed_ids & expected_ids if expected_ids is not None else observed_ids
    missing_ids = sorted(expected_ids - observed_ids) if expected_ids is not None else []
    event_ids = set(events) if events is not None else set()
    missing_kernel_ids = sorted(expected_ids - event_ids) if expected_ids is not None else []
    unknown_kernel_ids = sorted(event_ids - expected_ids) if expected_ids is not None else []
    invalid_kernel_order = []
    invalid_detection_identity = []
    injection_latency = []
    kernel_latency = []
    for injection_id in sorted(valid_ids):
        detection = by_injection[injection_id]
        alert_time = float(detection["alerted_at"])
        marker_time = float(markers[injection_id]["injected_at"]) if markers else None
        if markers is not None and "workload_key" in markers[injection_id]:
            marker = markers[injection_id]
            expected_container = str(marker["workload_key"]).split(":", 1)[1]
            if not (
                str(detection.get("workload_key")) == str(marker.get("workload_key"))
                and str(detection.get("cgroup_id")) == str(marker.get("cgroup_id"))
                and str(detection.get("pod_name")) == str(marker.get("pod_name"))
                and str(detection.get("pod_uid")) == str(marker.get("pod_uid"))
                and str(detection.get("node_name")) == str(marker.get("node_name"))
                and str(detection.get("container_name")) == expected_container
            ):
                invalid_detection_identity.append(injection_id)
        if marker_time is not None and alert_time >= marker_time:
            injection_latency.append(alert_time - marker_time)
        if events is not None and injection_id in events:
            event = events[injection_id]
            marker = markers[injection_id] if markers else {}
            identity_fields = (
                "node_name",
                "pod_name",
                "pod_uid",
                "workload_key",
                "workload_controller",
                "scenario",
                "seed",
                "rate_per_second",
            )
            identity_matches = all(
                str(event.get(field)) == str(marker.get(field))
                for field in identity_fields
            )
            kernel_time = float(event["kernel_event_at"])
            if (
                not identity_matches
                or alert_time < kernel_time
                or (marker_time is not None and kernel_time < marker_time - 0.050)
            ):
                invalid_kernel_order.append(injection_id)
            else:
                kernel_latency.append(alert_time - kernel_time)
    detected = len(valid_ids)
    expected = (
        len(expected_ids)
        if expected_ids is not None
        else detected if expected_injections is None else expected_injections
    )
    model_identity_gate = (
        len(model_identities) == 1
        and len(next(iter(model_identities))) == 64
        and all(character in "0123456789abcdef" for character in next(iter(model_identities)))
    )
    decision_policy_identity_gate = (
        len(decision_policy_identities) == 1
        and len(next(iter(decision_policy_identities))) == 64
        and all(
            character in "0123456789abcdef"
            for character in next(iter(decision_policy_identities))
        )
    )
    report = {
        "schema": "sentinel-pulse-latency-report-v2",
        "decision_sources": [
            {"path": str(item), "sha256": sha256_file(item)} for item in paths
        ],
        "decisions_sha256": sha256_file(paths[0]) if len(paths) == 1 else None,
        "injections_sha256": sha256_file(injection_path) if injection_path is not None else None,
        "kernel_events_sha256": (
            sha256_file(kernel_event_path) if kernel_event_path is not None else None
        ),
        "kernel_event_sources": sorted(
            {str(item.get("source")) for item in events.values()}
        ) if events is not None else [],
        "blind_attack_contract_sha256": (
            sha256_file(attack_contract_path) if attack_contract_path is not None else None
        ),
        "expected_injections": expected,
        "detected_injections": detected,
        "missing_injection_ids": missing_ids,
        "unknown_detection_ids": unknown_ids,
        "invalid_detection_identity_ids": invalid_detection_identity,
        "injection_identity_gate": not unknown_ids and not invalid_detection_identity,
        "missing_kernel_event_ids": missing_kernel_ids,
        "unknown_kernel_event_ids": unknown_kernel_ids,
        "invalid_kernel_event_order_ids": invalid_kernel_order,
        "kernel_timestamp_gate": bool(
            expected_ids is not None
            and events is not None
            and event_ids == expected_ids
            and not invalid_kernel_order
        ),
        "attack_matrix_gate": (
            contract_matrix is not None and not missing_matrix and not unknown_matrix
        ),
        "attack_matrix_expected_rows": len(contract_matrix) if contract_matrix is not None else None,
        "attack_matrix_observed_rows": len(observed_matrix) if observed_matrix is not None else None,
        "missing_attack_matrix_rows": [list(item) for item in missing_matrix],
        "unknown_attack_matrix_rows": [list(item) for item in unknown_matrix],
        "model_manifest_sha256": (
            next(iter(model_identities)) if model_identity_gate else None
        ),
        "model_identity_gate": model_identity_gate,
        "decision_policy_sha256": (
            next(iter(decision_policy_identities))
            if decision_policy_identity_gate
            else None
        ),
        "decision_policy_identity_gate": decision_policy_identity_gate,
        "run_id": (
            next(iter(run_identities)) if len(run_identities) == 1 else None
        ),
        "run_identity_gate": bool(
            len(run_identities) == 1
            and "" not in run_identities
            and (expected_run_id is None or run_identities == {expected_run_id})
        ),
        "recall": detected / expected if expected else 0.0,
        "injection_command_to_alert_seconds": summary(injection_latency),
        "kernel_to_alert_seconds": summary(kernel_latency),
        # Compatibility field: in v2 this is present only when it is derived
        # from independently recorded Tetragon kernel timestamps.
        "true_detection_latency_seconds": summary(kernel_latency),
        "post_window_processing_seconds": summary(processing),
        "inference_ms": summary(inference),
    }
    p99 = report["kernel_to_alert_seconds"].get("p99")
    report["latency_gate_p99_le_2s"] = p99 is not None and p99 <= 2.0
    report["blind_evidence_valid"] = (
        report["injection_identity_gate"]
        and report["kernel_timestamp_gate"]
        and report["attack_matrix_gate"]
        and report["model_identity_gate"]
        and report["decision_policy_identity_gate"]
        and report["run_identity_gate"]
        and report["latency_gate_p99_le_2s"]
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decisions", type=Path, action="append", required=True)
    parser.add_argument("--expected-injections", type=int)
    parser.add_argument("--injections", type=Path)
    parser.add_argument("--attack-contract", type=Path)
    parser.add_argument("--kernel-events", type=Path, required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = evaluate(
        args.decisions,
        args.expected_injections,
        args.injections,
        args.attack_contract,
        args.kernel_events,
        args.run_id,
    )
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    raise SystemExit(0 if report["blind_evidence_valid"] else 1)


if __name__ == "__main__":
    main()
