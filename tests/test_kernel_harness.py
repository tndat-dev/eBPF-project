import importlib.util
import ast
import json
from pathlib import Path
import sys

import pytest


HERE = Path(__file__).resolve()
MODULE_PATH = next(path for path in (
    HERE.with_name("run_kernel_regression.py"),  # flat VM deployment
    HERE.parents[1] / "run_kernel_regression.py",  # VM tests/ subdirectory
    HERE.parents[1] / "ml-service" / "run_kernel_regression.py",
) if path.is_file())
sys.path.insert(0, str(MODULE_PATH.parent))
spec = importlib.util.spec_from_file_location("run_kernel_regression", MODULE_PATH)
run_kernel_regression = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_kernel_regression)

CONSUMER_PATH = MODULE_PATH.with_name("tetragon_consumer.py")
consumer_spec = importlib.util.spec_from_file_location("tetragon_consumer", CONSUMER_PATH)
tetragon_consumer = importlib.util.module_from_spec(consumer_spec)
sys.modules[consumer_spec.name] = tetragon_consumer
consumer_spec.loader.exec_module(tetragon_consumer)

ANALYZER_PATH = MODULE_PATH.with_name("analyze_normal_run.py")
analyzer_spec = importlib.util.spec_from_file_location(
    "analyze_normal_run", ANALYZER_PATH,
)
analyze_normal_run = importlib.util.module_from_spec(analyzer_spec)
analyzer_spec.loader.exec_module(analyze_normal_run)



def constant_set(path: Path, name: str) -> set[str]:
    """Read a literal manifest without importing optional ML dependencies."""
    tree = ast.parse(path.read_text())
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in statement.targets
        ):
            return set(ast.literal_eval(statement.value))
    raise AssertionError(f"missing literal {name} in {path}")


def pod(name, phase="Running", ready=True, deleting=False, created="2026-01-01T00:00:00Z"):
    metadata = {"name": name, "creationTimestamp": created}
    if deleting:
        metadata["deletionTimestamp"] = "2026-01-01T00:01:00Z"
    return {
        "metadata": metadata,
        "status": {
            "phase": phase,
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
            "containerStatuses": [{"name": "app", "ready": ready}],
        },
    }


def test_ready_pod_names_excludes_completed_unready_and_terminating_pods():
    payload = {
        "items": [
            pod("completed", phase="Succeeded", created="2026-04-01T00:00:00Z"),
            pod("unready", ready=False, created="2026-05-01T00:00:00Z"),
            pod("terminating", deleting=True, created="2026-06-01T00:00:00Z"),
            pod("ready-old", created="2026-02-01T00:00:00Z"),
            pod("ready-new", created="2026-03-01T00:00:00Z"),
        ]
    }

    assert run_kernel_regression.ready_pod_names(payload) == [
        "ready-new", "ready-old",
    ]


def test_ready_pod_names_requires_all_containers_ready():
    candidate = pod("partially-ready")
    candidate["status"]["containerStatuses"].append(
        {"name": "sidecar", "ready": False}
    )

    assert run_kernel_regression.ready_pod_names({"items": [candidate]}) == []


def test_fast_path_is_included_in_every_runtime_provenance_manifest():
    expected = constant_set(MODULE_PATH, "RUNTIME_FILES")
    assert "sentinel/fast_path.py" in expected
    assert "workload_identity.py" in expected
    assert constant_set(MODULE_PATH.with_name("run_kernel_matrix.py"), "RUNTIME_FILES") == expected
    assert constant_set(MODULE_PATH.with_name("promote_candidate.py"), "RUNTIME_FILES") == expected
    assert run_kernel_regression.FAST_PATH_EXPECTED_SCENARIOS == {
        "container_escape", "privilege_escalation",
    }


def test_blind_scenarios_are_supported_without_changing_v7_defaults():
    assert run_kernel_regression.SCENARIOS == (
        "reverse_shell", "container_escape", "cryptomining",
        "privilege_escalation", "data_exfiltration",
    )
    assert set(run_kernel_regression.BLIND_SCENARIOS) == {
        "local_socket_beacon", "namespace_probe", "process_fanout",
        "identity_transition_probe", "credential_read_burst",
    }
    assert set(run_kernel_regression.SUPPORTED_SCENARIOS) == (
        set(run_kernel_regression.SCENARIOS)
        | set(run_kernel_regression.BLIND_SCENARIOS)
    )


def test_tetragon_reader_reconciles_daemonset_pod_rollover(monkeypatch):
    reader = tetragon_consumer.TetragonKubectlReader()
    memberships = iter([["tetragon-old"], ["tetragon-new"]])
    started, terminated = [], []
    monkeypatch.setattr(
        reader, "_get_all_tetragon_pods",
        lambda *, announce=True: next(memberships),
    )
    monkeypatch.setattr(reader, "_start_pod_thread", started.append)
    monkeypatch.setattr(reader, "_terminate_pod_processes", terminated.append)

    assert reader._reconcile_pods(initial=True)
    assert reader._reconcile_pods()
    assert started == ["tetragon-old", "tetragon-new"]
    assert terminated == ["tetragon-old"]
    assert reader.health()["active_tetragon_pods"] == ["tetragon-new"]
    assert reader.health()["stale_streams_removed"] == 1


def test_tetragon_reader_filters_unready_sensor_containers(monkeypatch):
    payload = {
        "items": [
            {
                "metadata": {"name": "tetragon-ready"},
                "status": {
                    "phase": "Running",
                    "containerStatuses": [{"name": "tetragon", "ready": True}],
                },
            },
            {
                "metadata": {"name": "tetragon-unknown"},
                "status": {
                    "phase": "Running",
                    "containerStatuses": [{"name": "tetragon", "ready": False}],
                },
            },
        ]
    }

    class Result:
        stdout = json.dumps(payload)

    monkeypatch.setattr(tetragon_consumer.subprocess, "run", lambda *args, **kwargs: Result())
    reader = tetragon_consumer.TetragonKubectlReader()
    assert reader._get_all_tetragon_pods() == ["tetragon-ready"]


def test_tetragon_reader_pauses_when_full_coverage_is_required(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_FULL_TETRAGON_COVERAGE", "true")
    reader = tetragon_consumer.TetragonKubectlReader()
    started = []
    monkeypatch.setattr(reader, "_get_all_tetragon_pods", lambda *, announce=True: ["tetragon-a"])
    monkeypatch.setattr(reader, "_get_expected_tetragon_pod_count", lambda: 2)
    monkeypatch.setattr(reader, "_start_pod_thread", started.append)

    assert not reader._reconcile_pods(initial=True)
    health = reader.health()
    assert started == []
    assert health["coverage_healthy"] is False
    assert health["ready_tetragon_pods"] == ["tetragon-a"]
    assert health["expected_tetragon_pods"] == 2


def test_kernel_regression_rejects_partial_tetragon_coverage(monkeypatch):
    class Result:
        stdout = "6,5,5"

    monkeypatch.setattr(run_kernel_regression.subprocess, "run", lambda *args, **kwargs: Result())
    with pytest.raises(RuntimeError, match="incomplete Tetragon coverage"):
        run_kernel_regression.require_tetragon_full_coverage()


def healthy_sensor_snapshot():
    return {
        "active_tetragon_pods": [f"tetragon-{index}" for index in range(6)],
        "expected_tetragon_pods": 6,
        "require_full_coverage": True,
        "coverage_healthy": True,
        "backpressure_events": 0,
        "membership_failures": 0,
        "coverage_failures": 0,
        "stream_failures": 0,
    }


def test_validation_sensor_health_gate_requires_uninterrupted_full_coverage():
    health = healthy_sensor_snapshot()
    assert run_kernel_regression.sensor_snapshot_healthy(health)
    assert analyze_normal_run.sensor_snapshot_healthy(health)

    for field, bad_value in (
        ("coverage_healthy", False),
        ("backpressure_events", 1),
        ("membership_failures", 1),
        ("coverage_failures", 1),
        ("stream_failures", 1),
        ("expected_tetragon_pods", 7),
    ):
        invalid = {**health, field: bad_value}
        assert not run_kernel_regression.sensor_snapshot_healthy(invalid)
        assert not analyze_normal_run.sensor_snapshot_healthy(invalid)


def test_kernel_validation_defaults_match_production_confirmation_policy():
    assert run_kernel_regression.VALIDATION_POLICY_DEFAULTS == {
        "SENTINEL_CONFIRMATION_FLOOR_RATIO": "0.94",
        "SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR": "0.45",
        "SENTINEL_FAST_PATH_CONFIRMATION_FLOOR": "0.20",
        "SENTINEL_POD_STARTUP_GRACE_SECONDS": "60",
        "SENTINEL_EXTREME_VOLUME_FACTOR": "2.0",
    }


def test_binary_install_falls_back_after_bounded_kubectl_cp_timeout(
        tmp_path, monkeypatch):
    binary = tmp_path / "attack"
    binary.write_bytes(b"frozen-binary")
    monkeypatch.setattr(
        run_kernel_regression, "select_ready_pod",
        lambda _namespace, _selector: "ready-pod",
    )
    calls = []

    class Result:
        returncode = 0
        stderr = b""

    def bounded_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[1] == "cp":
            raise run_kernel_regression.subprocess.TimeoutExpired(
                command, kwargs["timeout"],
            )
        return Result()

    monkeypatch.setattr(run_kernel_regression.subprocess, "run", bounded_run)
    pod, method = run_kernel_regression.install_runtime_binary(
        "production", "app=security", binary, "/tmp/attack", attempts=1,
    )

    assert pod == "ready-pod"
    assert method == "kubectl-exec-stdin"
    assert calls[0][1]["timeout"] == 30
    assert calls[1][0][1:3] == ["exec", "-i"]
    assert calls[1][1]["input"] == b"frozen-binary"
    assert calls[1][1]["timeout"] == 30


def test_post_injection_observation_distinguishes_sensor_invisible_attempt():
    rows = [
        {"kind": "decision", "pod_key": "production/target", "ts": 9,
         "score": 1.0, "suspicious_mass": 1.0, "behavior_max_ratio": 10.0},
        {"kind": "decision", "pod_key": "production/target", "ts": 11,
         "score": 0.33, "suspicious_mass": 0.0, "behavior_max_ratio": 0.0},
        {"kind": "decision", "pod_key": "production/other", "ts": 12,
         "score": 1.0, "suspicious_mass": 1.0, "behavior_max_ratio": 20.0},
    ]
    observed = run_kernel_regression.post_injection_observation(
        rows, "production/target", 10,
    )
    assert observed == {
        "target_decision_count": 1,
        "post_injection_max_score": 0.33,
        "post_injection_max_suspicious_mass": 0.0,
        "post_injection_max_behavior_ratio": 0.0,
        "post_injection_suspicious_signal_observed": False,
    }


def test_pod_security_profile_records_local_preventive_controls(monkeypatch):
    payload = {
        "spec": {
            "nodeName": "worker-3",
            "securityContext": {
                "seccompProfile": {
                    "type": "Localhost", "localhostProfile": "profile.json"
                },
                "appArmorProfile": {
                    "type": "Localhost", "localhostProfile": "restricted"
                },
            },
            "containers": [{
                "name": "app",
                "securityContext": {"allowPrivilegeEscalation": False},
            }],
        }
    }
    monkeypatch.setattr(
        run_kernel_regression.subprocess, "check_output",
        lambda *args, **kwargs: json.dumps(payload),
    )
    profile = run_kernel_regression.pod_security_profile(
        "production", "target",
    )
    assert profile["seccomp_profile"]["type"] == "Localhost"
    assert profile["apparmor_profile"]["localhostProfile"] == "restricted"
    assert profile["node_name"] == "worker-3"
