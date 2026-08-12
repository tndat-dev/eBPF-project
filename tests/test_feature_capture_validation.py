import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "ml-service"))
from validate_feature_capture import validate_capture


def _row(start=10.0):
    return {
        "kind": "feature_window",
        "ts": start + 10,
        "schema": "sentinel-feature-window/v2",
        "pod_key": "production/service-pod",
        "model_key": "production/service",
        "node_name": "worker-1",
        "window_start": start,
        "window_end": start + 10,
        "event_count": 3,
        "vector_size": 4,
        "sparse_vector": [[1, 0.33333334], [3, 0.66666669]],
        "syscall_counts": {"connect": 1, "execve": 2},
        "contains_arguments_or_payloads": False,
        "capture_mode": "sequence",
        "syscall_sequence": ["execve", "connect", "execve"],
        "release_id": "v8-test", "run_id": "run-01",
        "phase_id": "steady-01", "traffic_regime": "steady",
    }


def test_feature_capture_validator_accepts_consistent_private_rows(tmp_path):
    path = tmp_path / "capture.jsonl"
    path.write_text("\n".join(json.dumps(_row(start)) for start in (10, 20)) + "\n")
    report = validate_capture(path)
    assert report["valid"] is True
    assert report["feature_windows"] == 2
    assert report["privacy_contract"]["payloads"] is False


def test_feature_capture_validator_rejects_payload_key_and_count_drift(tmp_path):
    row = _row()
    row["payload"] = "forbidden"
    row["event_count"] = 4
    path = tmp_path / "capture.jsonl"
    path.write_text(json.dumps(row) + "\n")
    report = validate_capture(path)
    assert report["valid"] is False
    assert any("privacy-unsafe" in error for error in report["errors"])
    assert any("do not sum" in error for error in report["errors"])


def test_capture_accepts_minimal_paired_injection_rows(tmp_path):
    rows = [
        _row(10),
        {"kind": "injection", "ts": 12.0,
         "schema": "sentinel-injection-interval/v2",
         "injection_id": "run:escape", "pod_key": "production/service-pod",
         "attack_type": "escape", "rate": 6, "seed": 1901,
         "release_id": "v8-test", "run_id": "run-01",
         "phase_id": "steady-01", "traffic_regime": "steady"},
        _row(20),
        {"kind": "injection_end", "ts": 22.0,
         "schema": "sentinel-injection-interval/v2",
         "injection_id": "run:escape", "pod_key": "production/service-pod",
         "attack_type": "escape", "attack_exit_code": 0,
         "release_id": "v8-test", "run_id": "run-01",
         "phase_id": "steady-01", "traffic_regime": "steady"},
    ]
    path = tmp_path / "capture.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    report = validate_capture(path)
    assert report["valid"] is True
    assert report["injection_intervals"] == 1


def test_capture_rejects_telemetry_or_injection_payload(tmp_path):
    rows = [
        _row(),
        {"kind": "decision", "ts": 20.0, "payload": "must-not-leak"},
        {"kind": "injection", "ts": 21.0,
         "schema": "sentinel-injection-interval/v2",
         "injection_id": "run:x", "pod_key": "production/service-pod",
         "attack_type": "x", "rate": 1, "seed": 1,
         "release_id": "v8-test", "run_id": "run-01",
         "phase_id": "steady-01", "traffic_regime": "steady",
         "ack": "raw stderr is forbidden"},
    ]
    path = tmp_path / "capture.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    report = validate_capture(path)
    assert report["valid"] is False
    assert any("unsupported/privacy-unsafe" in error for error in report["errors"])
    assert any("unexpected/privacy-unsafe" in error for error in report["errors"])


def test_feature_capture_validator_accepts_v3_immutable_identity(tmp_path):
    row = _row()
    row.update({
        "schema": "sentinel-feature-window/v3",
        "cluster_id": "cluster-target-01",
        "workload_image_digest": "sha256:" + "a" * 64,
        "workload_version_id": "git-0123456789ab",
    })
    path = tmp_path / "capture-v3.jsonl"
    path.write_text(json.dumps(row) + "\n")
    report = validate_capture(path)
    assert report["valid"] is True
    assert report["cluster_ids"] == {"cluster-target-01": 1}
    assert report["workload_image_digests"] == {"sha256:" + "a" * 64: 1}


def test_feature_capture_validator_rejects_v3_mutable_image_tag(tmp_path):
    row = _row()
    row.update({
        "schema": "sentinel-feature-window/v3",
        "cluster_id": "cluster-target-01",
        "workload_image_digest": "registry/private/service:latest",
        "workload_version_id": "v2",
    })
    path = tmp_path / "capture-v3.jsonl"
    path.write_text(json.dumps(row) + "\n")
    report = validate_capture(path)
    assert report["valid"] is False
    assert any("immutable sha256" in error for error in report["errors"])


def test_feature_capture_validator_rejects_identity_on_v2_row(tmp_path):
    row = _row()
    row["cluster_id"] = "cluster-target-01"
    path = tmp_path / "capture-v2.jsonl"
    path.write_text(json.dumps(row) + "\n")
    report = validate_capture(path)
    assert report["valid"] is False
    assert any("V2 row unexpectedly" in error for error in report["errors"])
