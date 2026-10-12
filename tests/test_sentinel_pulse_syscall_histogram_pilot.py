import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel_pulse.syscall_histogram_analysis import summarize, verify_seals
from sentinel_pulse import syscall_histogram_pilot as pilot
from sentinel_pulse.syscall_histogram_pilot import read_traffic_receipt


def seal_capture(root: Path) -> None:
    files = sorted(path for path in root.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    (root / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files
    ))


def capture_fixture(root: Path, *, receipt: bool = True) -> Path:
    root.mkdir()
    begin, end = 1000.0, 1001.0
    metadata = {
        "schema": "sentinel-pulse-cgroups-v1",
        "node_name": "worker-a",
        "generated_at": "fixture",
        "cgroups": {"123": {
            "node_name": "worker-a", "namespace": "production", "pod_uid": "uid-1",
            "pod_name": "api-0", "container_name": "api", "workload_revision": "rev-1",
            "workload_name": "api", "role": "app",
        }},
    }
    metadata_bytes = json.dumps(metadata).encode()
    traffic = {
        "schema": "sentinel-pulse-traffic-receipt-v1", "receipt_id": "traffic-1",
        "registered_at_unix": 900.0, "node_name": "worker-a",
        "schedule": [{"start_unix": 999.0, "end_unix": 1002.0, "regime": "steady"}],
    }
    start = {
        "schema": "sentinel-pulse-syscall-histogram-pilot-v1", "run_id": "test-1",
        "node_name": "worker-a", "registered_wall_time": 950.0,
        "traffic_regime": "registered_schedule" if receipt else "unlabelled",
        "traffic_receipt_id": "traffic-1" if receipt else None,
        "traffic_receipt_sha256": hashlib.sha256(json.dumps(traffic).encode()).hexdigest() if receipt else None,
        "allowlist_cgroup_ids": [123],
        "snapshot_interval_ms": 1000,
    }
    terminal = {
        "state": "completed", "exit_code": 0, "probe_started_at_unix": 999.5,
        "probe_ended_at_unix": 1001.5,
    }
    rows = [
        {"observed_at": 999.5, "identity_match": True, "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(), "document": metadata},
        {"observed_at": 1001.0, "identity_match": True, "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(), "document": metadata},
    ]
    interval = {
        "schema": "sentinel-pulse-syscall-id-histogram-v1", "type": "interval",
        "cgroup_id": 123, "window_start": begin, "window_end": end,
        "snapshot_scan_seconds": 0.02, "counts": {"0": 10, "257": 2},
    }
    integrity = {
        "schema": "sentinel-pulse-syscall-id-histogram-v1", "type": "integrity",
        "window_start": begin, "interval_seconds": 1.0, "target_count": 1,
        "dropped_updates": 0, "map_entries": 2,
    }
    (root / "START.json").write_text(json.dumps(start))
    (root / "TERMINAL.json").write_text(json.dumps(terminal))
    (root / "histogram.jsonl").write_text(json.dumps(interval) + "\n" + json.dumps(integrity) + "\n")
    (root / "host-metrics.jsonl").write_text(json.dumps({"phase": "probe"}) + "\n")
    (root / "metadata-snapshots.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    if receipt:
        (root / "traffic-receipt.json").write_text(json.dumps(traffic))
    seal_capture(root)
    return root


def test_registered_receipt_is_accepted_only_if_preregistered_and_node_bound(tmp_path):
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps({
        "schema": "sentinel-pulse-traffic-receipt-v1", "receipt_id": "r1",
        "registered_at_unix": 10, "node_name": "worker-a",
        "schedule": [{"start_unix": 11, "end_unix": 20, "regime": "peak"}],
    }))
    assert read_traffic_receipt(receipt, "worker-a", 12)["document"]["receipt_id"] == "r1"
    with pytest.raises(ValueError, match="node"):
        read_traffic_receipt(receipt, "worker-b", 12)
    with pytest.raises(ValueError, match="before"):
        read_traffic_receipt(receipt, "worker-a", 9)


def test_complete_bound_capture_is_eligible_for_syscall_frequency_summary(tmp_path):
    root = capture_fixture(tmp_path / "capture")
    result = summarize(root)
    assert result["capture_valid_for_feature_selection"] is True
    workload = next(iter(result["workloads"].values()))
    assert workload["syscall_total"] == 12
    assert workload["traffic_regimes"] == {"steady": 1}


def test_unlabelled_capture_remains_engineering_only(tmp_path):
    result = summarize(capture_fixture(tmp_path / "capture", receipt=False))
    assert result["capture_valid_for_feature_selection"] is False
    assert result["selection_rank_allowed"] is False
    assert result["evidence_class"] == "engineering_pilot_or_invalid_capture"


def test_interval_crossing_traffic_boundary_is_not_silently_labelled(tmp_path):
    root = capture_fixture(tmp_path / "capture")
    receipt_path = root / "traffic-receipt.json"
    traffic = json.loads(receipt_path.read_text())
    traffic["schedule"] = [
        {"start_unix": 999, "end_unix": 1000.5, "regime": "steady"},
        {"start_unix": 1000.5, "end_unix": 1002, "regime": "peak"},
    ]
    receipt_path.write_text(json.dumps(traffic))
    start = json.loads((root / "START.json").read_text())
    start["traffic_receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    (root / "START.json").write_text(json.dumps(start))
    seal_capture(root)
    result = summarize(root)
    assert result["selection_rank_allowed"] is False
    assert result["integrity"]["problems"]["interval_outside_single_registered_regime"] == 1


def test_tampered_capture_artifact_fails_seal_validation(tmp_path):
    root = capture_fixture(tmp_path / "capture")
    (root / "histogram.jsonl").write_text("tampered\n")
    with pytest.raises(ValueError, match="seal mismatch"):
        summarize(root)


def test_target_coverage_must_match_preregistered_allowlist(tmp_path):
    root = capture_fixture(tmp_path / "capture")
    histogram = root / "histogram.jsonl"
    records = [json.loads(line) for line in histogram.read_text().splitlines()]
    records[1]["target_count"] = 2
    histogram.write_text("".join(json.dumps(record) + "\n" for record in records))
    seal_capture(root)
    result = summarize(root)
    assert result["selection_rank_allowed"] is False
    assert result["integrity"]["problems"]["target_coverage_mismatch"] == 1


def test_runner_lifecycle_seals_a_bounded_fake_loader_without_attaching_bpf(tmp_path, monkeypatch):
    loader = tmp_path / "fake-loader"
    loader.write_text("#!/bin/sh\nexit 0\n")
    loader.chmod(0o755)
    obj = tmp_path / "probe.o"
    obj.write_bytes(b"test object")
    allowlist = tmp_path / "allowlist"
    allowlist.write_text("123\n")
    metadata = tmp_path / "cgroups.json"
    metadata.write_text(json.dumps({
        "schema": "sentinel-pulse-cgroups-v1", "node_name": "worker-a",
        "generated_at": "fixture", "cgroups": {"123": {}}
    }))
    output = tmp_path / "run"
    args = SimpleNamespace(
        run_id="runner-test", source_commit="a" * 40, loader=loader, object=obj,
        allowlist=allowlist, metadata=metadata, output=output,
        duration_seconds=1, interval_ms=1000, baseline_seconds=300, post_seconds=300,
        metric_interval_seconds=10, owner_uid=None, owner_gid=None, traffic_receipt=None,
    )
    phases = []
    def instant_sample(phase, *unused, **kwargs):
        phases.append(phase)
        (output / "host-metrics.jsonl").open("a").write(json.dumps({"phase": phase}) + "\n")
        (output / "metadata-snapshots.jsonl").open("a").write(json.dumps({
            "observed_at": 1000, "identity_match": True, "document": metadata.read_text()
        }) + "\n")
        child = kwargs.get("child", unused[-1] if phase == "probe" and unused else None)
        if child is not None:
            child.wait(timeout=2)

    monkeypatch.setattr(pilot.os, "geteuid", lambda: 0)
    monkeypatch.setattr(pilot, "_sample_phase", instant_sample)
    monkeypatch.setattr(pilot, "_stop", False)

    assert pilot.run(args) == 0
    assert phases == ["baseline", "probe", "post"]
    assert (output / "TERMINAL.json").is_file()
    assert (output / "SHA256SUMS").is_file()
    assert not (output / "metadata").exists()
    assert "START.json" in verify_seals(output)
