import json

import pytest

from sentinel_pulse.analyze_500ms_overhead_pilot import (
    analyze,
    exact_sign_flip_pvalue,
)


def test_exact_sign_flip_pvalue_is_two_sided_and_exact():
    assert exact_sign_flip_pvalue([-1.0, -2.0, -3.0, -4.0]) == pytest.approx(0.125)
    assert exact_sign_flip_pvalue([1.0, -1.0]) == pytest.approx(1.0)


def test_pilot_analysis_refuses_equivalence_claim(tmp_path):
    records = []
    pairs = []
    for index, (condition, rps, p99) in enumerate(
        (("off", 100, 10), ("on", 99, 11), ("on", 101, 9), ("off", 100, 10),
         ("on", 100, 10), ("off", 100, 10), ("off", 100, 10), ("on", 100, 10)), 1
    ):
        records.append({
            "condition": condition,
            "rps_median": rps,
            "latency_p99_ms_median": p99,
        })
    for pair in range(4):
        pairs.append({
            "throughput_loss_percent": float(pair),
            "p99_latency_increase_percent": float(pair - 1),
        })
    result = {
        "schema": "sentinel-pulse-500ms-overhead-result-v1",
        "mode": "full",
        "valid": True,
        "campaign_id": "pilot",
        "records": records,
        "pairs": pairs,
    }
    (tmp_path / "RESULT.json").write_text(json.dumps(result))
    (tmp_path / "SHA256SUMS").write_text("index")
    for index in (2, 3, 5, 8):
        (tmp_path / f"p{index:02d}-on-finalize.json").write_text(json.dumps({
            "valid": True,
            "rows": 100,
            "interval_seconds": {"p99": 0.51},
            "ingest_lag_seconds": {"p99": 0.03},
            "experiment_average_cpu_cores": 0.05,
            "experiment_memory_peak_bytes": 40_000_000,
            "collector_max_drops": {"drop": 0},
        }))
    report = analyze(tmp_path)
    assert report["interpretation"]["equivalence_established"] is False
    assert report["exploratory_posthoc"] is True
    assert report["treatment_telemetry"]["all_integrity_gates_passed"] is True
