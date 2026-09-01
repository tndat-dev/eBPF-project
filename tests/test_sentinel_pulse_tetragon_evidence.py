import json

import pytest

from sentinel_pulse.tetragon_evidence import find_exec_event, find_execve_kprobe_event


def marker():
    return {
        "schema": "sentinel-pulse-injection-v1",
        "injection_id": "blind-001",
        "injected_at": 1787224800.0,
        "duration_seconds": 8,
        "workload_controller": "catalog-service",
        "workload_key": "production/catalog-service:app",
        "cgroup_id": 42,
        "pod_name": "catalog-service-abc-12345",
        "pod_uid": "pod-uid",
        "node_name": "k8s-worker1.local",
        "scenario": "namespace_probe",
        "seed": 11003,
        "rate_per_second": 6,
    }


def event(*, pod_uid="pod-uid", arguments="namespace_probe 8 6 11003"):
    return json.dumps(
        {
            "process_exec": {
                "process": {
                    "exec_id": "node:clock:pid",
                    "pid": 4321,
                    "binary": "/tmp/sentinel-runtime-attack-blind",
                    "arguments": arguments,
                    "pod": {
                        "namespace": "production",
                        "name": "catalog-service-abc-12345",
                        "uid": pod_uid,
                    },
                }
            },
            "node_name": "k8s-worker1.local",
            "time": "2026-08-20T11:20:00.123456789Z",
        }
    )


def test_exact_tetragon_exec_becomes_kernel_latency_origin():
    result = find_exec_event(
        ["not-json", event()],
        marker(),
        expected_binary="/tmp/sentinel-runtime-attack-blind",
    )
    assert result["schema"] == "sentinel-pulse-kernel-event-v1"
    assert result["source"] == "tetragon_process_exec"
    assert result["exec_id"] == "node:clock:pid"
    assert result["raw_event_sha256"]
    assert result["raw_event"]["process_exec"]["process"]["pid"] == 4321


def test_wrong_pod_or_arguments_cannot_be_used_as_latency_origin():
    with pytest.raises(ValueError, match="exactly one"):
        find_exec_event(
            [event(pod_uid="other"), event(arguments="namespace_probe 8 24 11003")],
            marker(),
            expected_binary="/tmp/sentinel-runtime-attack-blind",
        )


def test_duplicate_kernel_events_fail_closed():
    with pytest.raises(ValueError, match="observed 2"):
        find_exec_event(
            [event(), event()],
            marker(),
            expected_binary="/tmp/sentinel-runtime-attack-blind",
        )


def kprobe_event(path="/tmp/sentinel-runtime-attack-blind", policy="sentinel-pulse-exec-provenance"):
    return json.dumps({
        "process_kprobe": {
            "process": {"exec_id": "runc:clock:pid", "pid": 999},
            "function_name": "__x64_sys_execve",
            "args": [{"string_arg": path}],
            "action": "KPROBE_ACTION_POST",
            "policy_name": policy,
        },
        "node_name": "k8s-worker1.local",
        "time": "2026-08-20T11:20:00.123456789Z",
    })


def test_live_execve_kprobe_is_a_kernel_latency_origin():
    result = find_execve_kprobe_event(
        [kprobe_event()], marker(),
        expected_binary="/tmp/sentinel-runtime-attack-blind",
    )
    assert result["source"] == "tetragon_execve_kprobe_grpc"
    assert result["policy_name"] == "sentinel-pulse-exec-provenance"
    assert result["identity_scope"] == "serialized_node_exact_binary"


def test_execve_kprobe_rejects_wrong_policy_or_binary():
    with pytest.raises(ValueError, match="observed 0"):
        find_execve_kprobe_event(
            [kprobe_event(policy="other"), kprobe_event(path="/tmp/other")],
            marker(), expected_binary="/tmp/sentinel-runtime-attack-blind",
        )
