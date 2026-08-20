import json
import hashlib

import pytest

from sentinel_pulse.analyze_500ms_overhead_replication import analyze_replications


def write_campaign(root, campaign, date, node, pod_uid, effect):
    root.mkdir()
    protocol = {
        "schema": "sentinel-pulse-500ms-overhead-protocol-v1",
        "campaign_id": campaign,
        "mode": "full",
        "registered_at": f"{date}T00:00:00Z",
        "git_commit": "a" * 40,
        "endpoint": {"node": node, "pod_uid": pod_uid},
    }
    records = []
    pairs = []
    for index, condition in enumerate(("off", "on") * 4, 1):
        records.append({
            "condition": condition,
            "rps_median": 100.0,
            "latency_p99_ms_median": 10.0,
        })
        if index % 2 == 0:
            pairs.append({
                "throughput_loss_percent": effect,
                "p99_latency_increase_percent": -effect,
            })
    result = {
        "schema": "sentinel-pulse-500ms-overhead-result-v1",
        "mode": "full",
        "valid": True,
        "campaign_id": campaign,
        "records": records,
        "pairs": pairs,
    }
    (root / "PROTOCOL.json").write_text(json.dumps(protocol))
    (root / "RESULT.json").write_text(json.dumps(result))
    for index in (2, 3, 5, 8):
        (root / f"p{index:02d}-on-finalize.json").write_text(json.dumps({
            "valid": True,
            "rows": 100,
            "interval_seconds": {"p99": 0.51},
            "ingest_lag_seconds": {"p99": 0.03},
            "experiment_average_cpu_cores": 0.05,
            "experiment_memory_peak_bytes": 40_000_000,
            "collector_max_drops": {"drop": 0},
        }))
    indexed = sorted(path for path in root.iterdir() if path.is_file())
    (root / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}\n"
        for path in indexed
    ))
    (root / "COMPLETE").touch()


def test_replication_analysis_requires_cross_day_worker_and_endpoint(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    write_campaign(first, "a", "2026-08-17", "worker1", "pod-a", -1.0)
    write_campaign(second, "b", "2026-08-20", "worker4", "pod-b", 1.0)
    report = analyze_replications([first, second])
    assert report["independence"]["cross_day"] is True
    assert report["independence"]["cross_worker"] is True
    assert report["treatment_telemetry"]["runs"] == 8
    assert report["interpretation"]["equivalence_established"] is False


def test_replication_analysis_rejects_same_day_or_worker(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    write_campaign(first, "a", "2026-08-17", "worker1", "pod-a", -1.0)
    write_campaign(second, "b", "2026-08-17", "worker1", "pod-b", 1.0)
    with pytest.raises(ValueError, match="span two dates, nodes"):
        analyze_replications([first, second])
