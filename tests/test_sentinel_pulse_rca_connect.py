from sentinel_pulse.rca_connect import (
    kubernetes_target_index,
    materialize_connect_edges,
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


def test_connect_event_accepts_live_tetragon_sockaddr_shape():
    record = {
        "time": "2026-09-23T10:00:00Z",
        "node_name": "k8s-worker1.local",
        "process_kprobe": {
            "policy_name": "sentinel-aims-syscalls",
            "function_name": "__x64_sys_connect",
            "process": {
                "binary": "/usr/local/bin/uvicorn",
                "pod": {
                    "namespace": "production",
                    "name": "api-gateway-abc",
                    "container": {"name": "app"},
                },
            },
            "args": [
                {"int_arg": 28, "label": "socket_fd"},
                {"sockaddr_arg": {
                    "addr": "10.96.0.10", "family": "AF_INET", "port": 53
                }},
                {"int_arg": 16, "label": "address_length"},
            ],
        },
    }

    edge = normalize_connect_event(record)
    assert edge["source"]["binary"] == "/usr/local/bin/uvicorn"
    assert edge["connection"]["socket_fd"] == 28
    assert edge["destination"] == {
        "address": "10.96.0.10",
        "port": 53,
        "family": "AF_INET",
        "kubernetes": None,
    }


def test_target_index_accepts_empty_endpoint_slice_fields():
    index = kubernetes_target_index(
        {"items": []},
        {"items": []},
        {"items": [
            {"metadata": {"name": "empty-a"}, "endpoints": None},
            {"metadata": {"name": "empty-b"}, "endpoints": [{"addresses": None}]},
        ]},
    )
    assert index == {}


def test_materializer_writes_immutable_checksumed_edges(tmp_path):
    output = tmp_path / "connect-edges.jsonl"
    lines = [
        '{"process_exec":{}}\n',
        '{"time":"2026-09-23T10:00:00Z","process_kprobe":'
        '{"policy_name":"sentinel-aims-syscalls",'
        '"function_name":"__x64_sys_connect",'
        '"process":{"binary":"/app/service","pod":{}},'
        '"args":[{"sockaddr_arg":{"addr":"10.0.0.2","port":443}}]}}\n',
    ]
    summary = materialize_connect_edges(
        lines,
        output,
        {"10.0.0.2": {"kind": "Service", "name": "catalog"}},
    )
    assert summary["input_records"] == 2
    assert summary["connect_edges"] == 1
    assert summary["resolved_kubernetes_targets"] == 1
    assert len(summary["output_sha256"]) == 64
    edge = __import__("json").loads(output.read_text())
    assert edge["destination"]["kubernetes"]["name"] == "catalog"

    try:
        materialize_connect_edges(lines, output, {})
    except FileExistsError:
        pass
    else:
        raise AssertionError("existing RCA evidence was overwritten")
