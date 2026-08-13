import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service" if (ROOT / "ml-service").is_dir() else ROOT
sys.path.insert(0, str(SERVICE_ROOT))


def load(name):
    path = SERVICE_ROOT / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


finalizer = load("falco_attack_evidence_finalizer")


def _attack_rows(base, injection_id):
    context = {
        "release_id": "v8-test", "run_id": f"run-{injection_id}",
        "phase_id": "namespace_probe", "traffic_regime": "attack",
    }
    return [
        {
            "kind": "injection", "schema": "sentinel-injection-interval/v2",
            "ts": base, "injection_id": injection_id,
            "pod_key": "production/api-gateway-abc",
            "attack_type": "namespace_probe", "rate": 6, "seed": 19,
            **context,
        },
        {
            "kind": "feature_window", "schema": "sentinel-feature-window/v2",
            "ts": base + 10, "pod_key": "production/api-gateway-abc",
            "model_key": "production/api-gateway", "node_name": "worker",
            "window_start": base, "window_end": base + 10,
            "event_count": 2, "vector_size": 2,
            "sparse_vector": [[0, 0.5], [1, 0.5]],
            "syscall_counts": {"execve": 1, "unshare": 1},
            "contains_arguments_or_payloads": False,
            "capture_mode": "sequence",
            "syscall_sequence": ["execve", "unshare"],
            **context,
        },
        {
            "kind": "injection_end", "schema": "sentinel-injection-interval/v2",
            "ts": base + 9, "injection_id": injection_id,
            "pod_key": "production/api-gateway-abc",
            "attack_type": "namespace_probe", "attack_exit_code": 0,
            **context,
        },
    ]


def make_evidence(tmp_path, *, with_alert=True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    capture = tmp_path / "attack.jsonl"
    rows = _attack_rows(100.0, "inj-1") + _attack_rows(200.0, "inj-2")
    capture.write_text("".join(json.dumps(row) + "\n" for row in rows))
    falco = tmp_path / "falco"
    (falco / "code").mkdir(parents=True)
    source = b"# frozen collector\n"
    (falco / "code" / "falco_evidence_collector.py").write_bytes(source)
    for name in (
        "falco-daemonset.yaml", "falco-configmap.yaml", "falco-pods.json", "nodes.txt"
    ):
        (falco / name).write_text(name)
    contract = falco / "collection-contract.json"
    contract.write_text(json.dumps({
        "schema": "sentinel-falco-collection-contract/v1",
        "release_id": "v8-test", "since_time": "1970-01-01T00:01:30Z",
        "collector_sha256": hashlib.sha256(source).hexdigest(),
    }))
    state = {
        "schema": "sentinel-falco-collector-state/v1",
        "release_id": "v8-test", "updated_at": "1970-01-01T00:08:20Z",
        "expected_readers": 2,
        "ready_falco_pods": ["falco-a", "falco-b"],
        "active_readers": ["falco-a", "falco-b"],
        "coverage_healthy": True, "stream_failures": 0, "lines_seen": 20,
        "stream_failure_details": [],
        "privacy_safe_rows_written": 1 if with_alert else 0,
        "reader_ranges": {},
    }
    (falco / "collector-state.json").write_text(json.dumps(state))
    if with_alert:
        alert = {
            "schema": "sentinel-falco-alert/v1", "kind": "falco_alert",
            "event_ts": 105.0, "priority": "Warning", "rule": "Test rule",
            "source_falco_pod": "falco-a", "source_node": "worker",
            "target_namespace": "production", "target_pod": "api-gateway-abc",
            "release_id": "v8-test", "contains_arguments_or_payloads": False,
            "raw_output_stored": False,
        }
        alert["event_id"] = hashlib.sha256(
            json.dumps(alert, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        (falco / "falco-alerts.jsonl").write_text(json.dumps(alert) + "\n")
    return capture, falco, contract, tmp_path / "derived"


def test_attack_finalizer_maps_alert_and_reports_recall_latency(tmp_path):
    capture, falco, contract, output = make_evidence(tmp_path)
    report = finalizer.finalize(
        capture, falco, contract, output, expected_trials=2, now=500.0,
    )
    assert report["valid"] is True
    assert report["trial_count"] == 2
    assert report["detected_trials"] == 1
    assert report["recall"]["estimate"] == 0.5
    assert report["latency_seconds"]["median"] == 5.0
    assert report["privacy"]["raw_falco_output_stored"] is False
    assert (output / "SHA256SUMS").is_file()


def test_attack_finalizer_accepts_explicit_zero_alert_source(tmp_path):
    capture, falco, contract, output = make_evidence(tmp_path, with_alert=False)
    report = finalizer.finalize(
        capture, falco, contract, output, expected_trials=2, now=500.0,
    )
    assert report["detected_trials"] == 0
    assert report["recall"]["upper"] > 0
    assert (output / "falco-attack-alerts.jsonl").read_bytes() == b""


def test_attack_finalizer_rejects_only_failures_near_attack_intervals(tmp_path):
    capture, falco, contract, output = make_evidence(tmp_path / "outside")
    state_path = falco / "collector-state.json"
    state = json.loads(state_path.read_text())
    state["stream_failures"] = 1
    state["stream_failure_details"] = [{
        "observed_at": "1970-01-01T00:00:30+00:00",
        "kind": "membership",
        "pod": None,
    }]
    state_path.write_text(json.dumps(state))
    report = finalizer.finalize(
        capture, falco, contract, output, expected_trials=2, now=500.0,
    )
    assert report["coverage"]["stream_failures"] == 0
    assert report["coverage"]["out_of_scope_stream_failures"] == 1

    capture2, falco2, contract2, output2 = make_evidence(tmp_path / "overlap")
    state_path2 = falco2 / "collector-state.json"
    state2 = json.loads(state_path2.read_text())
    state2["stream_failures"] = 1
    state2["stream_failure_details"] = [{
        "observed_at": "1970-01-01T00:01:45+00:00",
        "kind": "membership",
        "pod": None,
    }]
    state_path2.write_text(json.dumps(state2))
    with pytest.raises(finalizer.EvidenceError, match="overlapping evidence"):
        finalizer.finalize(
            capture2, falco2, contract2, output2,
            expected_trials=2, now=500.0,
        )


def test_attack_finalizer_is_idempotent_after_immutable_publish(tmp_path):
    capture, falco, contract, output = make_evidence(tmp_path)
    first = finalizer.finalize(
        capture, falco, contract, output, expected_trials=2, now=500.0,
    )
    second = finalizer.finalize(
        capture, falco, contract, output, expected_trials=2, now=900.0,
    )
    assert second == first


def test_attack_finalizer_waits_for_horizon_and_settle(tmp_path):
    capture, falco, contract, output = make_evidence(tmp_path)
    with pytest.raises(finalizer.EvidenceNotSettled):
        finalizer.finalize(
            capture, falco, contract, output, expected_trials=2, now=250.0,
        )


def test_attack_finalizer_right_censors_horizon_at_next_same_pod_injection(tmp_path):
    capture, falco, contract, output = make_evidence(tmp_path)
    rows = _attack_rows(100.0, "inj-1") + _attack_rows(120.0, "inj-2")
    capture.write_text("".join(json.dumps(row) + "\n" for row in rows))
    report = finalizer.finalize(
        capture, falco, contract, output, expected_trials=2, now=500.0,
    )
    assert report["right_censored_trial_count"] == 1
    first, second = report["trials"]
    assert report["next_injection_boundary_guard_seconds"] == 1.0
    assert first["attribution_end"] == 119.0
    assert first["effective_post_attack_horizon_seconds"] == 10.0
    assert first["horizon_right_censored_by_next_injection"] is True
    assert second["horizon_right_censored_by_next_injection"] is False


def test_attack_finalizer_boundary_guard_excludes_next_attack_pre_ack_event(tmp_path):
    capture, falco, contract, output = make_evidence(tmp_path, with_alert=False)
    rows = _attack_rows(100.0, "inj-1") + _attack_rows(120.0, "inj-2")
    capture.write_text("".join(json.dumps(row) + "\n" for row in rows))
    alert = {
        "schema": "sentinel-falco-alert/v1", "kind": "falco_alert",
        "event_ts": 119.97, "priority": "Warning",
        "rule": "Detected ptrace PTRACE_ATTACH attempt",
        "source_falco_pod": "falco-a", "source_node": "worker",
        "target_namespace": "production", "target_pod": "api-gateway-abc",
        "release_id": "v8-test", "contains_arguments_or_payloads": False,
        "raw_output_stored": False,
    }
    alert["event_id"] = hashlib.sha256(
        json.dumps(alert, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    (falco / "falco-alerts.jsonl").write_text(json.dumps(alert) + "\n")
    state_path = falco / "collector-state.json"
    state = json.loads(state_path.read_text())
    state["privacy_safe_rows_written"] = 1
    state_path.write_text(json.dumps(state))
    report = finalizer.finalize(
        capture, falco, contract, output, expected_trials=2, now=500.0,
    )
    assert report["matched_alert_count"] == 0
    assert report["detected_trials"] == 0


def test_attack_finalizer_rejects_actual_overlapping_attacks(tmp_path):
    capture, falco, contract, output = make_evidence(tmp_path)
    rows = _attack_rows(100.0, "inj-1") + _attack_rows(108.0, "inj-2")
    capture.write_text("".join(json.dumps(row) + "\n" for row in rows))
    with pytest.raises(finalizer.EvidenceError, match="overlapping"):
        finalizer.finalize(
            capture, falco, contract, output, expected_trials=2, now=500.0,
        )
