from sentinel_pulse.rca_connect import (
    kubernetes_target_index,
    normalize_connect_event,
)


def test_connect_event_preserves_process_lineage_and_resolves_destination():
    index = kubernetes_target_index(
        {
            "items": [{
                "metadata": {
                    "namespace": "production", "name": "catalog-abc", "uid": "pod-1"
                },
                "status": {"podIP": "10.0.2.44"},
            }]
        },
        {"items": []},
        {
            "items": [{
                "metadata": {
                    "namespace": "production",
                    "labels": {"kubernetes.io/service-name": "catalog"},
                },
                "endpoints": [{"addresses": ["10.0.2.44"]}],
            }]
        },
    )
    record = {
        "time": "2026-09-16T20:00:00Z",
        "node_name": "k8s-worker1.local",
        "process_kprobe": {
            "policy_name": "sentinel-aims-syscalls",
            "function_name": "__x64_sys_connect",
            "process": {
                "exec_id": "exec-child",
                "parent_exec_id": "exec-parent",
                "pid": 42,
                "uid": 10001,
                "binary": "/app/catalog",
                "pod": {
                    "namespace": "production",
                    "name": "api-gateway-abc",
                    "uid": "pod-source",
                    "container": {"name": "app"},
                },
            },
            "args": [{"sockaddr_arg": {
                "family": "AF_INET", "address": "10.0.2.44", "port": 8080
            }}],
        },
    }
    edge = normalize_connect_event(record, index)
    assert edge["source"]["exec_id"] == "exec-child"
    assert edge["source"]["parent_exec_id"] == "exec-parent"
    assert edge["destination"]["port"] == 8080
    assert edge["destination"]["kubernetes"]["name"] == "catalog-abc"
    assert edge["destination"]["kubernetes"]["service"] == "catalog"
    assert edge["application_content"]["captured"] is False


def test_connect_normalizer_rejects_unrelated_event():
    assert normalize_connect_event({"process_exec": {}}) is None
