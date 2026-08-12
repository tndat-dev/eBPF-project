from pathlib import Path
import sys

import pytest


sys.path.insert(0, str(Path(__file__).parents[1] / "ml-service"))
from workload_version_identity import (
    VERSION_ANNOTATION, KubernetesWorkloadIdentityResolver,
    identity_from_pod, identity_map, immutable_image_digest,
)


DIGEST = "sha256:" + "a" * 64


def pod(version="git-0123456789ab", image_id=f"registry/service@{DIGEST}"):
    return {
        "metadata": {
            "namespace": "production", "name": "catalog-abc-12345",
            "labels": {"app.kubernetes.io/name": "catalog"},
            "annotations": {VERSION_ANNOTATION: version},
        },
        "status": {"containerStatuses": [
            {"name": "istio-proxy", "imageID": "sha256:" + "b" * 64},
            {"name": "catalog", "imageID": image_id},
        ]},
    }


def test_image_identity_drops_private_registry_and_keeps_digest_only():
    assert immutable_image_digest(f"private.local/team/service@{DIGEST}") == DIGEST


def test_pod_identity_selects_app_container_not_sidecar():
    identity = identity_from_pod(pod(), "target-cluster-01", "catalog")
    assert identity == {
        "cluster_id": "target-cluster-01",
        "workload_image_digest": DIGEST,
        "workload_version_id": "git-0123456789ab",
    }


def test_identity_map_uses_exact_pod_key():
    identities = identity_map({"items": [pod()]}, "target-cluster-01")
    assert list(identities) == ["production/catalog-abc-12345"]


@pytest.mark.parametrize("image_id", ["service:latest", "", "sha256:1234"])
def test_mutable_or_incomplete_image_identity_is_rejected(image_id):
    with pytest.raises(ValueError, match="immutable sha256"):
        identity_from_pod(pod(image_id=image_id), "target-cluster-01", "catalog")


def test_missing_preregistered_version_is_rejected():
    with pytest.raises(ValueError, match="version annotation/label"):
        identity_from_pod(pod(version=""), "target-cluster-01", "catalog")


def test_unannotated_unrelated_pod_is_not_admitted_to_identity_map():
    unrelated = pod(version="")
    assert identity_map({"items": [unrelated]}, "target-cluster-01") == {}


def test_resolver_never_performs_lazy_network_io_on_inference_lookup():
    resolver = KubernetesWorkloadIdentityResolver(
        "target-cluster-01", refresh_seconds=60,
    )
    with pytest.raises(ValueError, match="cache is stale"):
        resolver.resolve("production/catalog-abc-12345")
