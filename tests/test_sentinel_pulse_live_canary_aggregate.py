import hashlib
import json

import pytest

from sentinel_pulse.aggregate_live_canary import aggregate


MODEL = "a" * 64
POLICY = "b" * 64


def write_node(root, node):
    root.mkdir()
    decisions = root / "decisions.jsonl"
    row = {
        "status": "normal",
        "node_name": node,
        "workload_key": "production/example:app",
        "model_manifest_sha256": MODEL,
        "decision_policy_sha256": POLICY,
        "inference_ms": 10.0,
        "post_window_processing_seconds": 0.1,
        "window_start": 1.0,
        "alerted_at": 1.6,
    }
    decisions.write_text(json.dumps(row) + "\n")
    alerts = root / "alerts.jsonl"
    alerts.write_text("")
    canary = root / "CANARY.json"
    canary.write_text(json.dumps({
        "valid": True,
        "accuracy_claim_allowed": False,
        "automatic_promotion": False,
        "model_manifest_sha256": MODEL,
        "decision_policy_sha256": POLICY,
        "detector_restarts": 0,
        "collector_duration_seconds": 900.0,
        "collector_rows": 100,
        "collector_workloads": 1,
        "decisions": 1,
        "alerts": 0,
    }))
    entries = []
    for path in (decisions, alerts, canary):
        entries.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (root / "CANARY_SHA256SUMS").write_text("\n".join(entries) + "\n")
    (root / "CANARY_COMPLETE").touch()


def test_aggregate_verifies_and_combines_raw_node_decisions(tmp_path):
    first, second = tmp_path / "worker-a", tmp_path / "worker-b"
    write_node(first, "worker-a")
    write_node(second, "worker-b")
    report = aggregate({"worker-a": first, "worker-b": second}, MODEL, POLICY)
    assert report["valid"] is True
    assert report["node_count"] == 2
    assert report["decisions"] == 2
    assert report["alerts"] == 0
    assert report["inference_ms"]["p99"] == 10.0
    assert report["window_start_to_decision_seconds"]["p99"] == pytest.approx(0.6)
    assert report["accuracy_claim_allowed"] is False
    assert report["node_identity_binding"].startswith("verified from node_name")


def test_aggregate_rejects_wrong_scored_node_identity(tmp_path):
    root = tmp_path / "worker-a"
    write_node(root, "worker-b")
    with pytest.raises(ValueError, match="node identity mismatch"):
        aggregate({"worker-a": root}, MODEL, POLICY)
