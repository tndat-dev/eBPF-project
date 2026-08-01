import pytest

from workload_identity import get_deployment_key


@pytest.mark.parametrize("replicaset_hash", ["56956b54", "7b596c5bff"])
def test_resolves_observed_replicaset_hash_lengths(replicaset_hash):
    pod = f"production/aims-frontend-{replicaset_hash}-abcde"
    assert get_deployment_key(pod) == "production/aims-frontend"


def test_resolves_statefulset_ordinal():
    assert get_deployment_key("production/postgres-2") == "production/postgres"


@pytest.mark.parametrize(
    "pod",
    [
        "production/audit-worker-short-abcde",
        "production/name-12345678-too-long",
        "missing-namespace",
    ],
)
def test_retains_ambiguous_names(pod):
    assert get_deployment_key(pod) == pod
