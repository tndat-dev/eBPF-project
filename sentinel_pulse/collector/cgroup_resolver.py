"""Resolve production pod cgroups without granting the detector Kubernetes RBAC.

The resolver is intended to run as root on each node. It reads local CRI pod
metadata and scans cgroup v2. When CRI container IDs are visible, it resolves
those container cgroups and descendants, not their idle pod-slice ancestors.
Runtimes without visible container cgroups retain the deepest pod-slice
fallback (for example, a gVisor sentry scope).
"""

# ==============================================================================================================
# cgroup_resolver.py — TRẢ LỜI "CGROUP NÀO LÀ CONTAINER NÀO" MÀ KHÔNG CẦN QUYỀN KUBERNETES API.
# Chạy root trên mỗi worker node (unit riêng), lặp mỗi 15 s:
#   1) `crictl pods` / `crictl ps`: lấy pod và container của namespace production đang chạy trên node (qua CRI —
#      giao diện của container runtime — nên không cần RBAC của API server).
#   2) Quét cây cgroup v2 (/sys/fs/cgroup), khớp thư mục theo UID của pod và ID của container; cgroup id = số inode
#      của thư mục (đúng giá trị bpf_get_current_cgroup_id() trả về trong kernel).
#   3) Ghi hai file (ghi nguyên tử): allow-list (mỗi dòng một cgroup id — loader đọc file này) và metadata JSON
#      (cgroup id → pod, container, vai trò, tên workload, phiên bản — worker dùng để gắn danh tính).
# Pod của bộ sinh tải, runner tấn công và chính Sentinel Pulse bị loại (EXCLUDED_MARKERS).
# ==============================================================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
from typing import Iterable


# Pods the workers must not watch: the AIMS load/attack runners and Pulse itself.
EXCLUDED_MARKERS = ("loadgen", "attack-runner", "sentinel-pulse")


# Đoán vai trò từ tên pod (chỉ để ghi metadata và nhóm báo cáo; mô hình theo workload_key, không theo vai trò).
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


# Tên controller ổn định từ tên pod: bỏ đuôi hash của Deployment (-<hash>-<5 ký tự>) hoặc số thứ tự của StatefulSet.
def infer_workload_name(pod_name: str) -> str:
    """Remove rollout identity while retaining the stable controller name."""
    deployment = re.match(r"^(.+)-[0-9a-f]{8,10}-[a-z0-9]{5}$", pod_name)
    if deployment:
        return deployment.group(1)
    stateful = re.match(r"^(.+)-(\d+)$", pod_name)
    if stateful:
        return stateful.group(1)
    return pod_name


# Phiên bản template sinh ra pod (đổi khi image/cấu hình đổi, KHÔNG đổi khi pod khởi động lại) — từ nhãn hash của
# Deployment/Argo Rollouts/StatefulSet, annotation của Strimzi (Kafka) hoặc băm podSpec của CloudNativePG (Postgres).
def workload_revision(labels: dict, annotations: dict | None = None) -> str:
    """Return the controller revision that produced a pod.

    A pod UID is intentionally *not* a revision: every restart would then look
    like a new workload.  Kubernetes Deployment/Argo Rollouts template hashes
    change only when the effective pod template changes.  StatefulSet uses a
    controller-revision hash.  ``unknown`` is explicit so an older CRI runtime
    cannot accidentally be treated as an approved version.
    """
    for key in (
        "rollouts-pod-template-hash",
        "pod-template-hash",
        "controller-revision-hash",
    ):
        value = labels.get(key)
        if isinstance(value, str) and value:
            return value
    annotations = annotations or {}
    # StrimziPodSet does not expose controller-revision-hash, but its own
    # revision annotation changes with the generated broker pod generation.
    strimzi = annotations.get("strimzi.io/revision")
    if isinstance(strimzi, str) and strimzi:
        return f"strimzi-{strimzi}"
    # CloudNativePG stores the effective pod template as canonical JSON. Hash
    # the complete template rather than only podEnvHash so image, resources,
    # security context and probes are part of the inference provenance.
    cnpg_spec = annotations.get("cnpg.io/podSpec")
    if isinstance(cnpg_spec, str) and cnpg_spec:
        return f"cnpg-{hashlib.sha256(cnpg_spec.encode('utf-8')).hexdigest()[:16]}"
    return "unknown"


# Danh sách pod của namespace trên node này qua `crictl pods -o json`.
def cri_pods(namespace: str, command: str = "crictl") -> list[dict]:
    """Pods of the namespace, or of each of a comma-separated list."""
    result = subprocess.run(
        [command, "pods", "-o", "json"], capture_output=True, text=True, check=True
    )
    payload = json.loads(result.stdout)
    selected: dict[str, dict] = {}
    for item in payload.get("items", []):
        metadata = item.get("metadata", {})
        if metadata.get("namespace") not in namespace.split(","):
            continue
        name = metadata.get("name", "")
        if any(marker in name.lower() for marker in EXCLUDED_MARKERS):
            continue
        labels = item.get("labels", {})
        annotations = item.get("annotations", {})
        uid = labels.get("io.kubernetes.pod.uid") or metadata.get("uid", "")
        if not uid:
            continue
        selected[uid] = {
            "pod_uid": uid,
            "pod_name": name,
            "namespace": metadata.get("namespace"),
            "role": infer_role(name),
            "workload_name": infer_workload_name(name),
            "workload_revision": workload_revision(labels, annotations),
        }
    return list(selected.values())


# Danh sách container (id, tên, pod UID) qua `crictl ps -a -o json`.
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


# Ghép pod/container với thư mục cgroup. Ưu tiên cgroup của CONTAINER (nơi syscall thật sự xảy ra); chỉ khi runtime
# không lộ cgroup container (vd. gVisor) mới dùng cgroup sâu nhất của pod. Không lấy "pod slice" cha vì nó không có
# task nào → sẽ sinh ra một mô hình toàn số 0.
def resolve_cgroups(
    pods: Iterable[dict], cgroup_root: Path, containers: Iterable[dict] = ()
) -> dict[int, dict]:
    by_token = {
        pod["pod_uid"].replace("-", "_").lower(): pod for pod in pods
    }
    candidates: dict[str, list[tuple[int, int, dict, bool]]] = {}
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
        is_container_cgroup = False
        for container in containers_by_uid.get(matched["pod_uid"], []):
            if container["container_id"].lower() in lowered:
                item["container_name"] = container["container_name"]
                item["container_id"] = container["container_id"]
                is_container_cgroup = True
                break
        depth = len(Path(root).parts)
        candidates.setdefault(matched["pod_uid"], []).append(
            (depth, cgroup_id, item, is_container_cgroup)
        )

    resolved: dict[int, dict] = {}
    for entries in candidates.values():
        # A containerd pod slice is an ancestor and receives no task syscall
        # events while leaf tasks execute in their CRI container cgroup. Keeping
        # that ancestor manufactures a permanent all-zero "pod-slice" model.
        # Preserve gVisor/CRI-less fallback, but bind it to deepest scopes only.
        scoped = [entry for entry in entries if entry[3]]
        if scoped:
            selected = scoped
        else:
            deepest = max(entry[0] for entry in entries)
            selected = [entry for entry in entries if entry[0] == deepest]
        for _depth, cgroup_id, item, _is_container_cgroup in selected:
            resolved[cgroup_id] = item
    return resolved


# Ghi file nguyên tử: ghi file tạm, fsync, rồi rename đè — loader/worker không bao giờ đọc phải file ghi dở.
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


# Một vòng làm mới: CRI → ghép cgroup → ghi allow-list và metadata.
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
