import hashlib
import json

import pytest

from sentinel_pulse.finalize_500ms_dataset import finalize
from sentinel_pulse.train import interval_bounds


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
