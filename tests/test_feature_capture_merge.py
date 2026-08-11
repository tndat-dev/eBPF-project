import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "ml-service"))
from merge_feature_captures import merge_captures


def feature(start, run_id):
    return {
        "kind": "feature_window", "ts": start + 10,
        "schema": "sentinel-feature-window/v2",
        "pod_key": "production/api-pod", "model_key": "production/api",
        "node_name": "worker-1", "window_start": start,
        "window_end": start + 10, "event_count": 1, "vector_size": 3,
        "sparse_vector": [[1, 1.0]], "syscall_counts": {"execve": 1},
        "contains_arguments_or_payloads": False, "capture_mode": "sequence",
        "syscall_sequence": ["execve"], "release_id": "v8-test",
        "run_id": run_id, "phase_id": f"{run_id}-phase",
        "traffic_regime": "steady",
    }


def write(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def test_merge_freezes_chronological_hash_bound_capture(tmp_path):
    second = tmp_path / "second.jsonl"
    first = tmp_path / "first.jsonl"
    write(second, [feature(20, "run-02")])
    write(first, [feature(0, "run-01")])
    output = tmp_path / "frozen.jsonl"
    manifest = merge_captures([second, first], output)
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert [row["window_start"] for row in rows] == [0, 20]
    assert manifest["source_count"] == 2
    assert manifest["validation"]["valid"] is True
    assert output.with_suffix(".manifest.json").is_file()
    original = output.read_bytes()
    resumed = merge_captures([second, first], output)
    assert resumed == manifest
    assert output.read_bytes() == original


def test_merge_rejects_cross_capture_window_overlap_without_output(tmp_path):
    one = tmp_path / "one.jsonl"
    two = tmp_path / "two.jsonl"
    write(one, [feature(0, "run-01")])
    write(two, [feature(5, "run-02")])
    output = tmp_path / "frozen.jsonl"
    with pytest.raises(ValueError, match="overlapping window"):
        merge_captures([one, two], output)
    assert not output.exists()
