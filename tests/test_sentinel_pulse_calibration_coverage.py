import json

from sentinel_pulse.audit_calibration_coverage import audit
from sentinel_pulse.encoding import schema_digest


FEATURE_COLUMNS = ["feature-a", "feature-b"]


def write_dataset(path, rows):
    digest = schema_digest(FEATURE_COLUMNS)
    with path.open("w") as handle:
        handle.write(json.dumps({
            "schema": "sentinel-pulse-feature-schema-v1",
            "columns": FEATURE_COLUMNS,
        }) + "\n")
        for index in range(rows):
            handle.write(json.dumps({
                "schema": "sentinel-pulse-feature-v1",
                "workload_key": "production/example:app",
                "node_name": "worker-a",
                "pod_uid": "pod-a",
                "container_name": "app",
                "cgroup_id": 42,
                "window_end": index * 0.5,
                "traffic_regime": "steady",
                "feature_schema_sha256": digest,
                "vector": [0.0] * len(FEATURE_COLUMNS),
            }) + "\n")


def test_coverage_is_fail_closed_when_alpha_is_not_representable(tmp_path):
    dataset = tmp_path / "features.jsonl"
    write_dataset(dataset, 200)
    report = audit(dataset, history=3, alpha=0.001, window_seconds=0.5)
    workload = report["workloads"]["production/example:app"]
    assert report["all_workloads_eligible"] is False
    assert workload["minimum_calibration_examples"] == 999
    assert workload["status"] == "insufficient-calibration"


def test_coverage_accepts_a_representable_alpha(tmp_path):
    dataset = tmp_path / "features.jsonl"
    write_dataset(dataset, 200)
    report = audit(dataset, history=3, alpha=0.1, window_seconds=0.5)
    assert report["all_workloads_eligible"] is True
    assert report["eligible_workloads"] == 1
