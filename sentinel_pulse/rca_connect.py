"""Normalize Tetragon connect events into privacy-safe RCA graph edges."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Mapping


SCHEMA = "sentinel-pulse-rca-connect-edge-v1"


def _socket_address(arguments: list) -> tuple[str | None, int | None, str | None]:
    """Accept Tetragon sockaddr/sock JSON variants without guessing payload."""
    for argument in arguments:
        if not isinstance(argument, dict):
            continue
        candidates = [argument]
        candidates.extend(value for value in argument.values() if isinstance(value, dict))
        for value in candidates:
            address = next(
                (
                    value.get(name)
                    for name in ("daddr", "address", "addr", "sin_addr", "sin6_addr")
                    if value.get(name) not in (None, "")
                ),
                None,
            )
            port = next(
                (
                    value.get(name)
                    for name in ("dport", "port", "sin_port", "sin6_port")
                    if value.get(name) is not None
                ),
                None,
            )
            family = value.get("family")
            if address is not None or port is not None:
                return (
                    str(address) if address is not None else None,
                    int(port) if port is not None else None,
                    str(family) if family is not None else None,
                )
    return None, None, None


def _labeled_integer(arguments: list, label: str) -> int | None:
    """Extract an integer argument without depending on its list position."""
    for argument in arguments:
        if not isinstance(argument, dict) or argument.get("label") != label:
            continue
        for name in ("int_arg", "uint_arg", "long_arg", "size_arg"):
            if argument.get(name) is not None:
                return int(argument[name])
    return None


def kubernetes_target_index(
    pods: Mapping, services: Mapping, endpoint_slices: Mapping
) -> dict[str, dict]:
    """Index Pod IP, Service ClusterIP and EndpointSlice addresses."""
    result: dict[str, dict] = {}
    for item in pods.get("items", []):
        metadata, status = item.get("metadata", {}), item.get("status", {})
        for entry in status.get("podIPs") or []:
            ip = entry.get("ip")
            if ip:
                result[str(ip)] = {
                    "kind": "Pod",
                    "namespace": metadata.get("namespace"),
                    "name": metadata.get("name"),
                    "uid": metadata.get("uid"),
                }
        if status.get("podIP") and str(status["podIP"]) not in result:
            result[str(status["podIP"])] = {
                "kind": "Pod",
                "namespace": metadata.get("namespace"),
                "name": metadata.get("name"),
                "uid": metadata.get("uid"),
            }
    for item in services.get("items", []):
        metadata, spec = item.get("metadata", {}), item.get("spec", {})
        addresses = list(spec.get("clusterIPs") or [])
        if spec.get("clusterIP") and spec.get("clusterIP") not in addresses:
            addresses.append(spec["clusterIP"])
        for ip in addresses:
            if ip and ip != "None":
                result[str(ip)] = {
                    "kind": "Service",
                    "namespace": metadata.get("namespace"),
                    "name": metadata.get("name"),
                    "uid": metadata.get("uid"),
                }
    for item in endpoint_slices.get("items", []):
        metadata = item.get("metadata", {})
        service = metadata.get("labels", {}).get("kubernetes.io/service-name")
        for endpoint in item.get("endpoints") or []:
            for ip in endpoint.get("addresses") or []:
                existing = result.get(str(ip), {})
                if existing.get("kind") == "Pod":
                    existing = dict(existing)
                    existing["service"] = service
                    result[str(ip)] = existing
                elif str(ip) not in result:
                    result[str(ip)] = {
                        "kind": "Endpoint",
                        "namespace": metadata.get("namespace"),
                        "name": service,
                    }
    return result


def normalize_connect_event(
    record: dict,
    target_index: Mapping[str, dict] | None = None,
    *,
    policy_name: str = "sentinel-aims-syscalls",
) -> dict | None:
    """Return one graph edge, or ``None`` for unrelated Tetragon events."""
    event = record.get("process_kprobe")
    if not isinstance(event, dict):
        return None
    function = str(event.get("function_name", "")).split("__x64_")[-1]
    if event.get("policy_name") != policy_name or function != "sys_connect":
        return None
    process = event.get("process")
    if not isinstance(process, dict):
        return None
    pod = process.get("pod") if isinstance(process.get("pod"), dict) else {}
    container = pod.get("container") if isinstance(pod.get("container"), dict) else {}
    arguments = event.get("args", [])
    address, port, family = _socket_address(arguments)
    target = dict((target_index or {}).get(address, {})) if address else {}
    return {
        "schema": SCHEMA,
        "observed_at": record.get("time"),
        "node_name": record.get("node_name"),
        "source": {
            "namespace": pod.get("namespace"),
            "pod_name": pod.get("name"),
            "pod_uid": pod.get("uid"),
            "container_name": container.get("name"),
            "exec_id": process.get("exec_id"),
            "parent_exec_id": process.get("parent_exec_id"),
            "pid": process.get("pid"),
            "uid": process.get("uid"),
            "binary": process.get("binary"),
        },
        "connection": {
            "socket_fd": _labeled_integer(arguments, "socket_fd"),
        },
        "destination": {
            "address": address,
            "port": port,
            "family": family,
            "kubernetes": target or None,
        },
        "application_content": {
            "captured": False,
            "reason": "connect_syscall_has_no_l7_payload",
            "recommended_source": "redacted_istio_envoy_access_log_or_trace",
        },
        "raw_event_sha256": hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _atomic_new_jsonl(lines, destination: Path) -> dict:
    """Materialize immutable JSONL without exposing a partial destination."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite RCA evidence: {destination}")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp"
    )
    digest = hashlib.sha256()
    count = 0
    try:
        with os.fdopen(descriptor, "wb") as sink:
            for item in lines:
                encoded = (
                    json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode()
                sink.write(encoded)
                digest.update(encoded)
                count += 1
            sink.flush()
            os.fsync(sink.fileno())
        os.link(temporary_name, destination)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    return {"edges": count, "output_sha256": digest.hexdigest()}


def materialize_connect_edges(lines, destination: Path, target_index: Mapping) -> dict:
    """Normalize one immutable event stream and return checksumable statistics."""
    counters = {
        "input_records": 0,
        "connect_edges": 0,
        "resolved_kubernetes_targets": 0,
        "unresolved_targets": 0,
    }

    def edges():
        for number, line in enumerate(lines, 1):
            if not str(line).strip():
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, TypeError) as error:
                raise ValueError(f"invalid Tetragon JSON at line {number}") from error
            if not isinstance(record, dict):
                raise ValueError(f"Tetragon record at line {number} is not an object")
            counters["input_records"] += 1
            edge = normalize_connect_event(record, target_index)
            if edge is None:
                continue
            counters["connect_edges"] += 1
            if edge["destination"]["kubernetes"]:
                counters["resolved_kubernetes_targets"] += 1
            else:
                counters["unresolved_targets"] += 1
            yield edge

    result = _atomic_new_jsonl(edges(), destination)
    if result["edges"] != counters["connect_edges"]:
        raise RuntimeError("RCA edge count changed while materializing evidence")
    return {
        "schema": "sentinel-pulse-rca-materialization-v1",
        **counters,
        "output": str(destination),
        "output_sha256": result["output_sha256"],
    }


def _collection(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("items"), list):
        raise ValueError(f"Kubernetes collection is invalid: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Materialize privacy-safe Tetragon connect edges for RCA"
    )
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--pods", type=Path, required=True)
    parser.add_argument("--services", type=Path, required=True)
    parser.add_argument("--endpoint-slices", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    target_index = kubernetes_target_index(
        _collection(args.pods),
        _collection(args.services),
        _collection(args.endpoint_slices),
    )
    with args.events.open(encoding="utf-8") as source:
        summary = materialize_connect_edges(source, args.output, target_index)
    json.dump(summary, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
