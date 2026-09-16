"""Normalize Tetragon connect events into privacy-safe RCA graph edges."""

from __future__ import annotations

import hashlib
import json
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
                    for name in ("daddr", "address", "sin_addr", "sin6_addr")
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
        for endpoint in item.get("endpoints", []):
            for ip in endpoint.get("addresses", []):
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
    address, port, family = _socket_address(event.get("args", []))
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
