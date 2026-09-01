import hashlib
import json

import pytest

from sentinel_pulse.finalize_500ms_dataset import finalize
from sentinel_pulse.freeze_training_contract import freeze
from sentinel_pulse.train import (
    interval_bounds,
    source_git_provenance,
    validate_training_contract,
)


def write_capture(path, node, ends):
    rows = [{"schema": "sentinel-pulse-feature-schema-v1"}]
    rows.extend({
        "schema": "sentinel-pulse-feature-v1",
        "node_name": node,
        "window_start": end - 0.5,
        "window_end": end,
        "collector_stats": {"target_snapshot_gap": 0},
    } for end in ends)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    path.chmod(0o444)


def write_inputs(tmp_path, node="worker-a"):
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps({
        "schema": "sentinel-pulse-capture-contract-v1",
        "campaign_id": "pulse500-data-a",
        "normal_only": True,
        "expected_nodes": [node],
        "intervals": [
            {"regime": "steady", "start": 10.0, "end": 12.0},
            {"regime": "burst", "start": 13.0, "end": 15.0},
        ],
    }))
    capture = tmp_path / "features.jsonl"
    write_capture(capture, node, (9.5, 10.5, 11.5, 13.5, 14.5, 15.0))
    final_report = tmp_path / "FINAL.json"
    final_report.write_text(json.dumps({
        "valid": True,
        "rows": 6,
        "capture_sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
    }))
    return contract, capture, final_report


def test_500ms_manifest_binds_frozen_capture_to_contract(tmp_path):
    contract, capture, final_report = write_inputs(tmp_path)
    output = tmp_path / "capture-manifest.json"
    report = finalize(capture, contract, "worker-a", final_report, output)
    assert report["capture_profile"] == "exact-ebpf-500ms-rolling-10"
    assert report["rows_by_regime"] == {"burst": 3, "steady": 2}
    assert report["campaign_span_rows"] == 5
    assert output.stat().st_mode & 0o222 == 0


def test_500ms_manifest_rejects_capture_that_ends_early(tmp_path):
    contract, capture, final_report = write_inputs(tmp_path)
    capture.chmod(0o644)
    write_capture(capture, "worker-a", (9.5, 10.5, 11.5, 13.5))
    final_report.write_text(json.dumps({
        "valid": True,
        "rows": 4,
        "capture_sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
    }))
    with pytest.raises(ValueError, match="ended before"):
        finalize(capture, contract, "worker-a", final_report, tmp_path / "out.json")


def test_training_interval_bounds_are_profile_specific():
    assert interval_bounds(0.5) == (0.35, 0.80)
    assert interval_bounds(1.0) == (0.80, 1.50)
    with pytest.raises(ValueError, match="0.5 or 1.0"):
        interval_bounds(0.25)


def test_training_contract_binds_dataset_blind_matrix_and_parameters(tmp_path):
    dataset = tmp_path / "dataset.jsonl"
    blind = tmp_path / "blind.json"
    dataset.write_text("dataset")
    blind.write_text("blind")
    contract = tmp_path / "training.json"
    contract.write_text(json.dumps({
        "schema": "sentinel-pulse-training-contract-v1",
        "frozen_before_training": True,
        "automatic_promotion": False,
        "dataset_sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(),
        "blind_attack_contract_sha256": hashlib.sha256(blind.read_bytes()).hexdigest(),
        "history_windows": 3,
        "alpha": 0.001,
        "window_seconds": 0.5,
    }))
    report = validate_training_contract(contract, dataset, blind, 3, 0.001, 0.5)
    assert report["frozen_before_training"] is True
    with pytest.raises(ValueError, match="training contract mismatch"):
        validate_training_contract(contract, dataset, blind, 4, 0.001, 0.5)


def test_source_provenance_hashes_tracked_and_untracked_changes(tmp_path):
    import subprocess

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Pulse Test"],
        check=True,
    )
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("frozen\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-qm", "fixture"], check=True
    )

    clean = source_git_provenance(tmp_path)
    assert clean["source_clean"] is True
    assert clean["source_git_status"] == []
    assert clean["source_untracked_files"] == []

    tracked.write_text("changed\n")
    (tmp_path / "untracked.txt").write_text("first\n")
    dirty = source_git_provenance(tmp_path)
    assert dirty["source_clean"] is False
    assert "untracked.txt" in dirty["source_untracked_files"]
    assert dirty["source_git_diff_sha256"] != clean["source_git_diff_sha256"]

    (tmp_path / "untracked.txt").write_text("second\n")
    changed = source_git_provenance(tmp_path)
    assert changed["source_git_diff_sha256"] != dirty["source_git_diff_sha256"]


def test_v2_training_contract_rejects_source_drift(tmp_path):
    dataset = tmp_path / "dataset.jsonl"
    blind = tmp_path / "blind.json"
    dataset.write_text("dataset")
    blind.write_text("blind")
    source = {
        "source_git_commit": "a" * 40,
        "source_clean": False,
        "source_git_diff_sha256": "b" * 64,
    }
    contract = tmp_path / "training.json"
    freeze(contract, {
        "schema": "sentinel-pulse-training-contract-v2",
        "frozen_before_training": True,
        "automatic_promotion": False,
        "dataset_sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(),
        "blind_attack_contract_sha256": hashlib.sha256(blind.read_bytes()).hexdigest(),
        "history_windows": 3,
        "alpha": 0.001,
        "window_seconds": 0.5,
        **source,
    })
    assert contract.stat().st_mode & 0o222 == 0
    validate_training_contract(
        contract, dataset, blind, 3, 0.001, 0.5, source
    )
    with pytest.raises(ValueError, match="source mismatch"):
        validate_training_contract(
            contract,
            dataset,
            blind,
            3,
            0.001,
            0.5,
            {**source, "source_git_diff_sha256": "c" * 64},
        )
