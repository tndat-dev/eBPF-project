"""Cluster access and exact target selection for attack/control campaigns.

Extracted from the retired 500 ms blind-matrix runner. Targets are resolved
from pod UID + container + cgroup identity, never from a pod-name prefix, and
attack outcomes are never consulted while choosing one.
"""
from __future__ import annotations

import json
import os
import subprocess


DEFAULT_BINARY_IN_CONTAINER = "/tmp/sentinel-runtime-attack-blind"
# CloudNativePG mounts /tmp read-only, while /run is an ephemeral writable
# runtime filesystem.  Tetragon was also empirically verified to emit the
# exact /run process_exec identity; /dev/shm execution was not observable.
CONTROLLER_BINARY_PATHS = {
    "aims-postgres-cnpg": "/run/sentinel-runtime-attack-blind",
    # Istio waypoint is distroless with a read-only root. This path is inside
    # its writable emptyDir mount and is allowlisted by the provenance policy.
    "aims-waypoint": "/etc/istio/proxy/sentinel-runtime-attack-blind",
    "aims-rabbitmq-server": "/operator/sentinel-runtime-attack-blind",
}


def binary_path_for_controller(controller: str) -> str:
    return CONTROLLER_BINARY_PATHS.get(controller, DEFAULT_BINARY_IN_CONTAINER)


def ready_pods(payload: dict, controller: str) -> list[dict]:
    result = []
    for pod in payload.get("items", []):
        metadata, status, spec = pod.get("metadata", {}), pod.get("status", {}), pod.get("spec", {})
        name = str(metadata.get("name", ""))
        conditions = {item.get("type"): item.get("status") for item in status.get("conditions", [])}
        containers = status.get("containerStatuses", [])
        if (
            (name == controller or name.startswith(controller + "-"))
            and status.get("phase") == "Running"
            and conditions.get("Ready") == "True"
            and containers
            and all(item.get("ready") is True for item in containers)
            and not metadata.get("deletionTimestamp")
        ):
            result.append({
                "name": name,
                "uid": metadata.get("uid"),
                "node_name": spec.get("nodeName"),
                "containers": [item.get("name") for item in spec.get("containers", [])],
            })
    return sorted(result, key=lambda item: (item["node_name"], item["name"]))


def select_cgroup(metadata: dict, pod_uid: str, model_container: str) -> tuple[int, dict]:
    matches = [
        (int(cgroup_id), value)
        for cgroup_id, value in metadata.get("cgroups", {}).items()
        if value.get("pod_uid") == pod_uid
        and value.get("container_name") == model_container
    ]
    if not matches:
        raise ValueError(
            f"expected a {model_container} cgroup for pod {pod_uid}, observed 0"
        )
    # A gVisor pod can expose both the parent pod slice and its deeper sentry
    # scope as ``pod-slice`` because CRI does not report a normal leaf container
    # ID.  The eBPF current-cgroup counter observes the deepest scope.  Resolve
    # by cgroup topology only; attack outcomes are never consulted.
    depths = [
        (str(item.get("cgroup_path", "")).count("/"), cgroup_id, item)
        for cgroup_id, item in matches
    ]
    maximum = max(depth for depth, _cgroup_id, _item in depths)
    leaves = [
        (cgroup_id, item)
        for depth, cgroup_id, item in depths
        if depth == maximum
    ]
    if len(leaves) != 1:
        raise ValueError(
            f"ambiguous deepest {model_container} cgroup for pod {pod_uid}: {len(leaves)}"
        )
    return leaves[0]


def select_target(runtime, row, workers, index):
    """Resolve exact controller/container from cgroup identity, not pod prefix."""
    pods = ready_pods(runtime.kubectl_json('get', 'pods', '-n', 'production', '-o', 'json'), row['workload_controller'])
    expected_container = row['workload_key'].split(':', 1)[1]
    cache, matches = {}, []
    for pod in pods:
        worker = workers.get(pod['node_name'])
        if worker is None or (expected_container != 'pod-slice' and expected_container not in pod['containers']):
            continue
        if pod['node_name'] not in cache:
            cache[pod['node_name']] = json.loads(runtime.remote_sudo(worker['host'], 'cat /run/sentinel-pulse/cgroups.json').stdout)
        try:
            cg, identity = select_cgroup(cache[pod['node_name']], pod['uid'], expected_container)
        except ValueError:
            continue
        if identity.get('namespace') != 'production' or identity.get('workload_name') != row['workload_controller']:
            continue
        container = pod['containers'][0] if expected_container == 'pod-slice' else expected_container
        matches.append((pod, worker, container, cg))
    if not matches:
        raise RuntimeError('no exact ready controller/container/cgroup target: ' + row['workload_key'])
    return matches[(index-1) % len(matches)]


class Runtime:
    def __init__(self, password: str, ssh_user: str = "dat"):
        self.password = password
        self.ssh_user = ssh_user
        self.environment = dict(os.environ, SSHPASS=password)

    def run(self, command: list[str], *, input_bytes=None, timeout=60, check=True):
        return subprocess.run(
            command, input=input_bytes, capture_output=True, timeout=timeout,
            check=check, env=self.environment,
        )

    def kubectl_json(self, *arguments: str) -> dict:
        result = self.run(["kubectl", *arguments], timeout=30)
        return json.loads(result.stdout)

    def remote_sudo(self, host: str, command: str, *, payload: bytes = b"", timeout=30):
        # Force sudo to consume exactly the password line even with cached
        # credentials; never let it leak into a JSON/tee payload.
        return self.run(
            [
                "sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=8", f"{self.ssh_user}@{host}",
                'sudo -k -S -p "" ' + command,
            ],
            input_bytes=self.password.encode() + b"\n" + payload,
            timeout=timeout,
        )
