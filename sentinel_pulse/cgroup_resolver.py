"""Resolve production pod cgroups without granting the detector Kubernetes RBAC.

The resolver is intended to run as root on each node.  It reads local CRI pod
metadata and scans cgroup v2.  Both the pod slice and all container descendants
are included because ``bpf_get_current_cgroup_id`` reports the leaf cgroup.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
from typing import Iterable


EXCLUDED_MARKERS = ("loadgen", "attack-runner", "sentinel-pulse")


def infer_role(pod_name: str) -> str:
    name = pod_name.lower()
    if "kafka-entity-operator" in name:
        return "kafka-operator"
    if "kafka" in name:
        return "kafka-broker"
    if "postgres" in name:
        return "postgresql"
    if "rabbitmq" in name:
        return "rabbitmq"
    if "redis-sentinel" in name:
        return "redis-sentinel"
    if "redis" in name:
        return "redis"
    if "minio" in name:
        return "minio"
    if "waypoint" in name or "istio" in name:
        return "istio-proxy"
    if "frontend" in name:
        return "frontend"
    if name.endswith("-service") or "-service-" in name or "api-gateway" in name:
        return "stateless-http"
    return "other-production"


def infer_workload_name(pod_name: str) -> str:
    """Remove rollout identity while retaining the stable controller name."""
    deployment = re.match(r"^(.+)-[0-9a-f]{8,10}-[a-z0-9]{5}$", pod_name)
    if deployment:
        return deployment.group(1)
    stateful = re.match(r"^(.+)-(\d+)$", pod_name)
    if stateful:
        return stateful.group(1)
    return pod_name


def cri_pods(namespace: str, command: str = "crictl") -> list[dict]:
    result = subprocess.run(
        [command, "pods", "-o", "json"], capture_output=True, text=True, check=True
    )
    payload = json.loads(result.stdout)
    selected: dict[str, dict] = {}
    for item in payload.get("items", []):
        metadata = item.get("metadata", {})
        if metadata.get("namespace") != namespace:
            continue
        name = metadata.get("name", "")
        if any(marker in name.lower() for marker in EXCLUDED_MARKERS):
            continue
        labels = item.get("labels", {})
        uid = labels.get("io.kubernetes.pod.uid") or metadata.get("uid", "")
        if not uid:
            continue
        selected[uid] = {
            "pod_uid": uid,
            "pod_name": name,
            "namespace": namespace,
            "role": infer_role(name),
            "workload_name": infer_workload_name(name),
        }
    return list(selected.values())


def cri_containers(command: str = "crictl") -> list[dict]:
    result = subprocess.run(
        [command, "ps", "-a", "-o", "json"], capture_output=True, text=True, check=True
    )
    payload = json.loads(result.stdout)
    containers = []
    for item in payload.get("containers", []):
        container_id = item.get("id", "")
        labels = item.get("labels", {})
        pod_uid = labels.get("io.kubernetes.pod.uid", "")
        if not container_id or not pod_uid:
            continue
        containers.append(
            {
                "container_id": container_id,
                "container_name": item.get("metadata", {}).get("name", "unknown"),
                "pod_uid": pod_uid,
            }
        )
    return containers


def resolve_cgroups(
    pods: Iterable[dict], cgroup_root: Path, containers: Iterable[dict] = ()
) -> dict[int, dict]:
    by_token = {
        pod["pod_uid"].replace("-", "_").lower(): pod for pod in pods
    }
    resolved: dict[int, dict] = {}
    containers_by_uid: dict[str, list[dict]] = {}
    for container in containers:
        containers_by_uid.setdefault(container["pod_uid"], []).append(container)
    for root, directories, _files in os.walk(cgroup_root):
        lowered = root.lower()
        matched = next((pod for token, pod in by_token.items() if token in lowered), None)
        if matched is None:
            continue
        try:
            cgroup_id = os.stat(root).st_ino
        except FileNotFoundError:
            continue
        item = dict(matched, cgroup_path=root, container_name="pod-slice")
        for container in containers_by_uid.get(matched["pod_uid"], []):
            if container["container_id"].lower() in lowered:
                item["container_name"] = container["container_name"]
                item["container_id"] = container["container_id"]
                break
        resolved[cgroup_id] = item
    return resolved


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def refresh(namespace: str, cgroup_root: Path, allow_file: Path, metadata_file: Path) -> dict:
    pods = cri_pods(namespace)
    containers = cri_containers()
    cgroups = resolve_cgroups(pods, cgroup_root, containers)
    node_name = os.environ.get("NODE_NAME") or socket.gethostname()
    for value in cgroups.values():
        value["node_name"] = node_name
    atomic_write(allow_file, "".join(f"{key}\n" for key in sorted(cgroups)))
    document = {
        "schema": "sentinel-pulse-cgroups-v1",
        "generated_at": time.time(),
        "namespace": namespace,
        "node_name": node_name,
        "pod_count": len({value["pod_uid"] for value in cgroups.values()}),
        "cgroup_count": len(cgroups),
        "cgroups": {str(key): value for key, value in sorted(cgroups.items())},
    }
    atomic_write(metadata_file, json.dumps(document, sort_keys=True, indent=2) + "\n")
    return document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default="production")
    parser.add_argument("--cgroup-root", type=Path, default=Path("/sys/fs/cgroup"))
    parser.add_argument("--allow-file", type=Path, required=True)
    parser.add_argument("--metadata-file", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=15.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    while True:
        document = refresh(args.namespace, args.cgroup_root, args.allow_file, args.metadata_file)
        print(json.dumps({key: document[key] for key in ("generated_at", "pod_count", "cgroup_count")}), flush=True)
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
