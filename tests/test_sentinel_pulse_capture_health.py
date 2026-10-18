import io
import json

import pytest

from sentinel_pulse.capture import run


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


def test_loader_cadence_is_not_confused_with_per_cgroup_history(tmp_path):
    metadata = tmp_path / "metadata.json"
    metadata.write_text(json.dumps({"cgroups": {
        "1": {"namespace": "production", "workload_name": "a",
              "container_name": "app", "pod_uid": "a", "node_name": "node"},
        "2": {"namespace": "production", "workload_name": "b",
              "container_name": "app", "pod_uid": "b", "node_name": "node"},
    }}))
    rows = [
        {"type": "cgroup_snapshot", "cgroup_id": 1, "total": 1,
         "counts": {"0": 1}, "syscall_bins": [1] + [0] * 63,
         "transition_bins": [0] * 64},
        {"type": "snapshot_end", "observed_at": 10.0, "targets": 1, "snapshots": 1},
        {"type": "cgroup_snapshot", "cgroup_id": 2, "total": 1,
         "counts": {"0": 1}, "syscall_bins": [1] + [0] * 63,
         "transition_bins": [0] * 64},
        {"type": "snapshot_end", "observed_at": 10.5, "targets": 1, "snapshots": 1},
        {"type": "cgroup_snapshot", "cgroup_id": 1, "total": 2,
         "counts": {"0": 2}, "syscall_bins": [2] + [0] * 63,
         "transition_bins": [0] * 64},
        {"type": "snapshot_end", "observed_at": 11.0, "targets": 1, "snapshots": 1},
    ]
    destination = io.StringIO()
    run(io.StringIO("".join(json.dumps(row) + "\n" for row in rows)),
        destination, metadata, interval_min_seconds=0.35,
        interval_max_seconds=0.8)
    features = [json.loads(line) for line in destination.getvalue().splitlines()
                if json.loads(line).get("schema") == "sentinel-pulse-feature-v1"]
    assert len(features) == 1
    assert features[0]["window_end"] - features[0]["window_start"] == 1.0
    assert features[0]["collector_snapshot_interval_seconds"] == 0.5
    assert features[0]["collector_stats"].get("capture_interval_violation", 0) == 0










def test_capture_requires_both_interval_bounds(tmp_path):
    with pytest.raises(ValueError, match="both capture interval bounds"):
        capture(tmp_path, [10.0], interval_min_seconds=0.35)
