import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service" if (ROOT / "ml-service").is_dir() else ROOT


def load(name):
    path = SERVICE_ROOT / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


finalizer = load("falco_evidence_finalizer")


def make_evidence(tmp_path, *, with_alert=True):
    capture = tmp_path / "capture"
    falco = tmp_path / "falco"
    output = tmp_path / "derived" / "falco-rule-only-normal"
    capture.mkdir(parents=True)
    (falco / "code").mkdir(parents=True)
    release = "v8-test"
    split = {
        "schema": "sentinel-v8-capture-split/v1",
        "release_id": release,
        "normal": {
            "regimes": list(finalizer.REGIMES),
            "runs": [
                {"run_id": "normal-run-01", "role": "candidate_fit"},
                {"run_id": "normal-run-02", "role": "independent_evaluation"},
            ],
        },
    }
    split_path = capture / "v8_capture_split_contract.json"
    split_path.write_text(json.dumps(split))
    start = 1000.0
    for index, regime in enumerate(finalizer.REGIMES):
        phase = f"aims-{regime}-run-02"
        phase_root = capture / phase
        phase_root.mkdir()
        phase_start = start + index * 120
        manifest = {
            "phase": phase,
            "collection_started_at": f"1970-01-01T00:{int(phase_start // 60):02d}:{int(phase_start % 60):02d}+00:00",
            "collection_ended_at": f"1970-01-01T00:{int((phase_start + 60) // 60):02d}:{int((phase_start + 60) % 60):02d}+00:00",
            "minimum_duration_satisfied": True,
            "sensor_health": {"coverage_healthy": True},
        }
        # The synthetic minutes exceed 59, so use timestamp conversion instead.
        from datetime import datetime, timezone
        manifest["collection_started_at"] = datetime.fromtimestamp(
            phase_start, timezone.utc
        ).isoformat()
        manifest["collection_ended_at"] = datetime.fromtimestamp(
            phase_start + 60, timezone.utc
        ).isoformat()
        (phase_root / "collection_manifest.json").write_text(json.dumps(manifest))

    # The finalizer validates a frozen collector snapshot, but its focused
    # staging test must not depend on the live collector source tree.
    source = b"# frozen synthetic collector snapshot\n"
    (falco / "code" / "falco_evidence_collector.py").write_bytes(source)
    for name in (
        "falco-daemonset.yaml", "falco-configmap.yaml", "falco-pods.json", "nodes.txt"
    ):
        (falco / name).write_text(f"frozen-{name}\n")
    (falco / "collection-contract.json").write_text(json.dumps({
        "schema": finalizer.CONTRACT_SCHEMA,
        "release_id": release,
        "since_time": "1970-01-01T00:16:30Z",
        "collector_sha256": hashlib.sha256(source).hexdigest(),
    }))
    state = {
        "schema": finalizer.STATE_SCHEMA,
        "release_id": release,
        "updated_at": "1970-01-01T00:25:40Z",
        "expected_readers": 2,
        "ready_falco_pods": ["falco-a", "falco-b"],
        "active_readers": ["falco-a", "falco-b"],
        "coverage_healthy": True,
        "stream_failures": 0,
        "lines_seen": 10,
        "privacy_safe_rows_written": 1 if with_alert else 0,
        "reader_ranges": {
            "falco-a": {
                "node": "worker-a", "lines_seen": 10,
                "minimum_log_timestamp": 995.0,
                "maximum_log_timestamp": 1530.0,
            }
        },
    }
    (falco / "collector-state.json").write_text(json.dumps(state))
    if with_alert:
        row = {
            "schema": finalizer.ALERT_SCHEMA,
            "kind": "falco_alert",
            "event_ts": 1010.0,
            "priority": "Warning",
            "rule": "Test rule",
            "source_falco_pod": "falco-a",
            "source_node": "worker-a",
            "target_namespace": "production",
            "target_pod": "api-gateway-abc",
            "release_id": release,
            "contains_arguments_or_payloads": False,
            "raw_output_stored": False,
        }
        row["event_id"] = hashlib.sha256(
            json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        (falco / "falco-alerts.jsonl").write_text(json.dumps(row) + "\n")
    return capture, falco, split_path, output


def test_finalizer_freezes_phase_bounded_privacy_safe_evidence(tmp_path):
    capture, falco, split, output = make_evidence(tmp_path)
    report = finalizer.finalize(
        capture, falco, split, output, now=1600.0,
        max_state_age=120, minimum_settle_seconds=30,
    )
    assert report["valid"] is True
    assert report["phase_count"] == 4
    assert report["normal_alert_count"] == 1
    assert report["false_positive_rate"] is None
    assert report["coverage"]["active_readers_with_zero_log_output"] == ["falco-b"]
    stored = (output / "falco-normal-alerts.jsonl").read_text()
    assert "command" not in stored
    row = json.loads(stored)
    assert row["phase"] == "aims-steady-run-02"
    assert row["dataset_role"] == "independent_evaluation"
    assert (output / "SHA256SUMS").is_file()


def test_zero_alert_file_is_valid_only_when_state_reports_zero_rows(tmp_path):
    capture, falco, split, output = make_evidence(tmp_path, with_alert=False)
    report = finalizer.finalize(capture, falco, split, output, now=1600.0)
    assert report["normal_alert_count"] == 0
    assert (output / "falco-normal-alerts.jsonl").read_bytes() == b""

    capture2, falco2, split2, output2 = make_evidence(
        tmp_path / "bad", with_alert=False
    )
    state = json.loads((falco2 / "collector-state.json").read_text())
    state["privacy_safe_rows_written"] = 2
    (falco2 / "collector-state.json").write_text(json.dumps(state))
    with pytest.raises(finalizer.EvidenceError, match="reports rows"):
        finalizer.finalize(capture2, falco2, split2, output2, now=1600.0)


def test_finalizer_rejects_incomplete_or_failed_reader_coverage(tmp_path):
    capture, falco, split, output = make_evidence(tmp_path)
    state = json.loads((falco / "collector-state.json").read_text())
    state["active_readers"] = ["falco-a"]
    state["stream_failures"] = 1
    (falco / "collector-state.json").write_text(json.dumps(state))
    with pytest.raises(finalizer.EvidenceError, match="membership is incomplete"):
        finalizer.finalize(capture, falco, split, output, now=1600.0)


def test_finalizer_waits_until_stream_state_passes_settle_boundary(tmp_path):
    capture, falco, split, output = make_evidence(tmp_path)
    with pytest.raises(finalizer.EvidenceNotSettled):
        finalizer.finalize(
            capture, falco, split, output, now=1440.0,
            max_state_age=120, minimum_settle_seconds=30,
        )


def test_finalizer_rejects_privacy_schema_expansion_and_overwrite(tmp_path):
    capture, falco, split, output = make_evidence(tmp_path)
    row = json.loads((falco / "falco-alerts.jsonl").read_text())
    row["command"] = "forbidden"
    (falco / "falco-alerts.jsonl").write_text(json.dumps(row) + "\n")
    with pytest.raises(finalizer.EvidenceError, match="privacy schema"):
        finalizer.finalize(capture, falco, split, output, now=1600.0)

    capture2, falco2, split2, output2 = make_evidence(tmp_path / "immutable")
    finalizer.finalize(capture2, falco2, split2, output2, now=1600.0)
    with pytest.raises(finalizer.EvidenceError, match="immutable"):
        finalizer.finalize(capture2, falco2, split2, output2, now=1600.0)
