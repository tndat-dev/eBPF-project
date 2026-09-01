from sentinel_pulse.traffic_gate import (
    INGRESS_PATHS,
    MICROSERVICES,
    east_west_errors,
    ingress_errors,
    ready_pod,
    rollout_summary,
)


def rollout(name, *, replicas=2, ready=2, phase="Healthy", runtime=None):
    return {
        "metadata": {"name": name, "resourceVersion": "10"},
        "spec": {
            "replicas": replicas,
            "template": {"spec": {"runtimeClassName": runtime}},
        },
        "status": {"readyReplicas": ready, "phase": phase},
    }


def test_rollout_gate_requires_native_runtime_and_full_readiness():
    payload = {"items": [rollout(name) for name in MICROSERVICES]}
    summary, errors = rollout_summary(payload)
    assert errors == []
    assert summary["payment-service"]["runtime_class"] is None

    payload["items"] = [
        rollout(name, runtime="sandbox" if name == "payment-service" else None)
        for name in MICROSERVICES
    ]
    payload["items"][0] = rollout(MICROSERVICES[0], ready=1)
    _, errors = rollout_summary(payload)
    assert any("not Healthy at full readiness" in error for error in errors)
    assert any("native runtime" in error for error in errors)


def test_request_gates_are_exact_and_fail_closed():
    east = {name: {"status_counts": {"200": 20}} for name in MICROSERVICES}
    north = {path: {"success": 20, "failure": 0} for path in INGRESS_PATHS}
    assert east_west_errors(east, 20) == []
    assert ingress_errors(north, 20) == []

    east["payment-service"]["status_counts"] = {"503": 20}
    north["/"] = {"success": 19, "failure": 1}
    assert "payment-service" in east_west_errors(east, 20)[0]
    assert "north-south /" in ingress_errors(north, 20)[0]


def test_ready_pod_rejects_terminating_and_unready_candidates():
    payload = {
        "items": [
            {
                "metadata": {"name": "terminating", "deletionTimestamp": "now"},
                "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]},
            },
            {
                "metadata": {"name": "unready"},
                "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "False"}]},
            },
            {
                "metadata": {"name": "ready"},
                "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]},
            },
        ]
    }
    assert ready_pod(payload)["metadata"]["name"] == "ready"
