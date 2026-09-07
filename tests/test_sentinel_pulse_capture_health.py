import io
import json

import numpy as np
import pytest

from sentinel_pulse.capture import run
from sentinel_pulse.encoding import compact_record, decode_vector
from sentinel_pulse.inspect_feature_tail import inspect
from sentinel_pulse.validate_capture import validate


def capture(tmp_path, times, **kwargs):
    metadata = tmp_path / "metadata.json"
    metadata.write_text(json.dumps({"cgroups": {"7": {
        "namespace": "production", "workload_name": "test", "container_name": "app",
        "pod_uid": "pod", "node_name": "node",
    }}}))
    source = []
    for index, timestamp in enumerate(times, 1):
        source.extend([
            {"type": "cgroup_snapshot", "cgroup_id": 7, "total": index,
             "counts": {"0": index}, "syscall_bins": [index] + [0] * 63,
             "transition_bins": [0] * 64},
            {"type": "snapshot_end", "observed_at": timestamp,
             "targets": 1, "snapshots": 1},
        ])
    destination = io.StringIO()
    run(io.StringIO("".join(json.dumps(r) + "\n" for r in source)),
        destination, metadata, **kwargs)
    path = tmp_path / "features.jsonl"
    path.write_text(destination.getvalue())
    return path


def capture_multiple_cgroups(tmp_path, times, cgroup_count=3, **kwargs):
    metadata = tmp_path / "metadata.json"
    metadata.write_text(json.dumps({"cgroups": {
        str(cgroup): {
            "namespace": "production", "workload_name": f"test-{cgroup}",
            "container_name": "app", "pod_uid": f"pod-{cgroup}",
            "node_name": "node",
        }
        for cgroup in range(1, cgroup_count + 1)
    }}))
    source = []
    for index, timestamp in enumerate(times, 1):
        for cgroup in range(1, cgroup_count + 1):
            source.append({
                "type": "cgroup_snapshot", "cgroup_id": cgroup,
                "total": index, "counts": {"0": index},
                "syscall_bins": [index] + [0] * 63,
                "transition_bins": [0] * 64,
            })
        source.append({
            "type": "snapshot_end", "observed_at": timestamp,
            "targets": cgroup_count, "snapshots": cgroup_count,
        })
    destination = io.StringIO()
    run(io.StringIO("".join(json.dumps(row) + "\n" for row in source)),
        destination, metadata, **kwargs)
    path = tmp_path / "features-multiple.jsonl"
    path.write_text(destination.getvalue())
    return path


def test_gap_remains_visible_after_cadence_recovers(tmp_path):
    path = capture(tmp_path, [10.0, 10.5, 13.0, 13.5],
                   interval_min_seconds=0.35, interval_max_seconds=0.8)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    features = [row for row in rows if row["schema"] == "sentinel-pulse-feature-v1"]
    assert [r["collector_stats"].get("capture_interval_violation", 0)
            for r in features] == [0, 1, 1]
    assert features[1]["window_end"] - features[1]["window_start"] == 2.5
    tail = inspect(path, observed_at=features[-1]["emitted_at"])
    assert tail["interval_seconds"] == 0.5
    assert not tail["valid"]
    assert "collector loss: capture_interval_violation=1" in tail["errors"]
    assert all(np.isfinite(decode_vector(row)).all() for row in features)


def test_gap_counter_counts_loader_snapshots_not_workload_rows(tmp_path):
    path = capture_multiple_cgroups(
        tmp_path, [10.0, 10.5, 13.0, 13.5],
        interval_min_seconds=0.35, interval_max_seconds=0.8,
    )
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    features = [row for row in rows if row["schema"] == "sentinel-pulse-feature-v1"]
    gap_rows = [row for row in features if row["window_end"] == 13.0]
    recovered_rows = [row for row in features if row["window_end"] == 13.5]
    assert len(gap_rows) == 3
    assert {row["collector_stats"]["capture_interval_violation"] for row in gap_rows} == {1}
    assert {row["collector_stats"]["capture_interval_violation"] for row in recovered_rows} == {1}


def test_default_capture_keeps_one_second_control_compatible(tmp_path):
    path = capture(tmp_path, [10.0, 11.0, 12.0])
    report = validate(path, minimum_rows_per_workload=1)
    assert report["valid"], report["errors"]


@pytest.mark.parametrize("encoding", ["compact", "inline"])
def test_full_validator_rejects_nonfinite_features(tmp_path, encoding):
    path = capture(tmp_path, [10.0, 11.0])
    schema, record = map(json.loads, path.read_text().splitlines())
    vector = decode_vector(record)
    vector[0] = float("nan")
    record.pop("vector_f32_zlib_b64", None)
    record["vector"] = vector.tolist()
    if encoding == "compact":
        record["columns"] = schema["columns"]
        record, _ = compact_record(record)
    path.write_text(json.dumps(schema) + "\n" + json.dumps(record) + "\n")
    report = validate(path, minimum_rows_per_workload=1)
    assert not report["valid"]
    assert any("non-finite feature vector" in error for error in report["errors"])


def test_capture_requires_both_interval_bounds(tmp_path):
    with pytest.raises(ValueError, match="both capture interval bounds"):
        capture(tmp_path, [10.0], interval_min_seconds=0.35)
