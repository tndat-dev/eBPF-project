import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "ml-service"))
from validate_feature_capture import validate_capture


def _row(start=10.0):
    return {
        "kind": "feature_window",
        "ts": start + 10,
        "schema": "sentinel-feature-window/v1",
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
