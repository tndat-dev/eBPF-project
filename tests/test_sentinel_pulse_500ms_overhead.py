import json
from pathlib import Path

import pytest

from sentinel_pulse.aggregate_500ms_overhead import aggregate


def write_phase(root: Path, campaign: str, name: str, condition: str, rps: float, p99: float):
    directory = root / f"{name}-20260817T000000Z"
    directory.mkdir()
    report = {
        "experiment_id": campaign,
        "phase": name,
        "url": "http://10.0.2.1/api/products/",
        "quality_gate": {"passed": True},
        "failed_requests_total": 0,
        "runs": [{"run": 1}],
        "requests_per_second": {"median": rps},
        "latency_p99_ms": {"median": p99},
        "condition": condition,
    }
    (directory / "report.json").write_text(json.dumps(report))


def protocol(root: Path, phases: list[dict], mode: str = "smoke") -> Path:
    path = root / "protocol.json"
    path.write_text(json.dumps({
        "schema": "sentinel-pulse-500ms-overhead-protocol-v1",
        "campaign_id": "campaign-a",
        "mode": mode,
        "endpoint": {"url": "http://10.0.2.1/api/products/"},
        "repetitions_per_phase": 1,
        "phases": phases,
    }))
    return path


def test_aggregate_accepts_balanced_smoke_pair(tmp_path):
    phases = []
    for index, (condition, rps, p99) in enumerate(
        (("off", 100.0, 10.0), ("on", 95.0, 11.0)), 1
    ):
        name = f"p{index:02d}-{condition}"
        phases.append({
            "index": index,
            "name": name,
            "condition": condition,
        })
        write_phase(tmp_path, "campaign-a", name, condition, rps, p99)
    report = aggregate(tmp_path, protocol(tmp_path, phases))
    assert report["valid"] is True
    assert report["inferential"] is False
    assert report["effects"]["throughput_loss"]["median_percent"] == pytest.approx(5.0)
    assert report["effects"]["p99_latency_increase"]["median_percent"] == pytest.approx(10.0)


def test_aggregate_rejects_unbalanced_pair(tmp_path):
    phases = []
    for index in (1, 2):
        name = f"p{index:02d}-off"
        phases.append({
            "index": index,
            "name": name,
            "condition": "off",
        })
        write_phase(tmp_path, "campaign-a", name, "off", 100.0, 10.0)
    with pytest.raises(ValueError, match="not OFF/ON balanced"):
        aggregate(tmp_path, protocol(tmp_path, phases))
