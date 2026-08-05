import importlib.util
import json
from pathlib import Path

import pytest


PATH = Path(__file__).parents[1] / "sentinel/benchmarks/aggregate_counterbalanced_overhead.py"
spec = importlib.util.spec_from_file_location("aggregate_overhead", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def _write_campaign(root: Path, count: int = 6):
    for index, order in enumerate(sorted(module.EXPECTED_ORDERS)[:count], 1):
        experiment = f"campaign-p{index:02d}"
        phases = {}
        for name, rps, latency in (
            ("no_tracing", 1000, 10),
            ("tetragon_only", 980, 11),
            ("full_pipeline", 950, 12),
        ):
            phases[name] = {
                "rps_median": rps,
                "latency_p99_ms_median": latency,
            }
        (root / f"comparison-wrk-{experiment}.json").write_text(json.dumps({
            "experiment_id": experiment, "phases": phases,
        }))
        (root / f"protocol-{experiment}.json").write_text(json.dumps({
            "experiment_id": experiment, "phase_order": order,
        }))


def test_aggregate_requires_all_orders_and_uses_paired_blocks(tmp_path):
    _write_campaign(tmp_path)
    report = module.aggregate(tmp_path, "campaign")
    assert len(report["experiments"]) == 6
    effect = report["effects"]["full_pipeline_vs_no_tracing"]
    assert effect["throughput_loss"]["median_percent"] == pytest.approx(5.0)
    assert effect["p99_latency_increase"]["median_percent"] == pytest.approx(20.0)


def test_aggregate_rejects_incomplete_campaign(tmp_path):
    _write_campaign(tmp_path, count=5)
    with pytest.raises(ValueError, match="incomplete"):
        module.aggregate(tmp_path, "campaign")
