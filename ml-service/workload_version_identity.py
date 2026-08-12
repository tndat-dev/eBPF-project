"""Resolve privacy-safe, immutable workload identity from Kubernetes Pod JSON."""

from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from typing import Any

from feature_capture_io import validate_v3_identity


VERSION_ANNOTATION = "runtime-sentinel.io/workload-version-id"
VERSION_LABEL = "app.kubernetes.io/version"


def immutable_image_digest(image_id: str) -> str:
    """Extract only the immutable digest, excluding private registry names."""
    match = re.search(r"sha256:[0-9a-fA-F]{64}$", str(image_id).strip())
    if not match:
        raise ValueError("container imageID does not end in an immutable sha256 digest")
    return match.group(0).lower()


def identity_from_pod(
    pod: dict[str, Any], cluster_id: str, container_name: str,
) -> dict[str, str]:
    metadata = pod.get("metadata") or {}
    statuses = (pod.get("status") or {}).get("containerStatuses") or []
    status = next(
        (item for item in statuses if item.get("name") == container_name), None,
    )
    if status is None:
        raise ValueError(f"container status is missing: {container_name}")
    annotations = metadata.get("annotations") or {}
    labels = metadata.get("labels") or {}
    version_id = annotations.get(VERSION_ANNOTATION) or labels.get(VERSION_LABEL)
    if not version_id:
        raise ValueError("workload version annotation/label is missing")
    return validate_v3_identity({
        "cluster_id": cluster_id,
        "workload_image_digest": immutable_image_digest(status.get("imageID", "")),
        "workload_version_id": str(version_id),
    })


def identity_map(pod_list: dict[str, Any], cluster_id: str) -> dict[str, dict[str, str]]:
    """Build exact pod-key identities; sidecars are never selected implicitly."""
    result = {}
    for pod in pod_list.get("items", []):
        metadata = pod.get("metadata") or {}
        namespace, name = metadata.get("namespace"), metadata.get("name")
        labels = metadata.get("labels") or {}
        container_name = labels.get("app.kubernetes.io/name")
        if not namespace or not name or not container_name:
            continue
        annotations = metadata.get("annotations") or {}
        if not (annotations.get(VERSION_ANNOTATION) or labels.get(VERSION_LABEL)):
            # Unrelated cluster components commonly use the app label but are
            # not part of the preregistered V9 target set.
            continue
        result[f"{namespace}/{name}"] = identity_from_pod(
            pod, cluster_id, container_name,
        )
    return result


class KubernetesWorkloadIdentityResolver:
    """Bounded-TTL Kubernetes identity cache for a future V9 collector."""

    def __init__(self, cluster_id: str, refresh_seconds: float = 60.0):
        validate_v3_identity({
            "cluster_id": cluster_id,
            "workload_image_digest": "sha256:" + "0" * 64,
            "workload_version_id": "validation-placeholder",
        })
        if refresh_seconds <= 0:
            raise ValueError("identity refresh interval must be positive")
        self.cluster_id = cluster_id
        self.refresh_seconds = refresh_seconds
        self._identities: dict[str, dict[str, str]] = {}
        self._refreshed_at = 0.0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None

    def refresh(self) -> None:
        """Refresh outside the inference lock, then atomically swap the cache."""
        completed = subprocess.run(
            ["kubectl", "get", "pods", "-A", "-o", "json"],
            text=True, capture_output=True, check=True, timeout=30,
        )
        document = json.loads(completed.stdout)
        identities = identity_map(document, self.cluster_id)
        if not identities:
            raise ValueError("Kubernetes identity snapshot contains no eligible pods")
        with self._lock:
            self._identities = identities
            self._refreshed_at = time.monotonic()
            self.last_error = None

    def _refresh_loop(self) -> None:
        while not self._stop.wait(self.refresh_seconds):
            try:
                self.refresh()
            except (json.JSONDecodeError, OSError, subprocess.SubprocessError,
                    ValueError) as exc:
                with self._lock:
                    self.last_error = str(exc)

    def start(self) -> None:
        """Populate once before capture, then refresh without blocking inference."""
        self.refresh()
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._refresh_loop, daemon=True,
                name="workload-identity-refresher",
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=min(self.refresh_seconds, 5.0))

    def resolve(self, pod_key: str) -> dict[str, str]:
        with self._lock:
            if time.monotonic() - self._refreshed_at >= 2 * self.refresh_seconds:
                raise ValueError("Kubernetes identity cache is stale")
            identity = self._identities.get(pod_key)
            if identity is None:
                raise ValueError(f"immutable workload identity is missing: {pod_key}")
            return dict(identity)
