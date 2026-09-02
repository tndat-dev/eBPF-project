import json

from sentinel_pulse.classify_normal_failure import classify


def test_missing_report_is_generic_finalizer_failure(tmp_path):
    assert classify(tmp_path) == "normal_finalize_failed"


def test_coverage_rejection_is_not_mislabeled_generic_failure(tmp_path):
    (tmp_path / "NORMAL_REPORT.json").write_text(json.dumps({
        "schema": "sentinel-pulse-normal-soak-report-v1",
        "alerts": 0,
        "maximum_alerts": 0,
        "coverage_gate": False,
        "duration_gate": True,
        "expected_workload_gate": True,
    }))

    assert classify(tmp_path) == "normal_coverage_gate_failed"


def test_alert_failure_takes_precedence_over_other_failed_gates(tmp_path):
    (tmp_path / "NORMAL_REPORT.json").write_text(json.dumps({
        "schema": "sentinel-pulse-normal-soak-report-v1",
        "alerts": 1,
        "maximum_alerts": 0,
        "coverage_gate": False,
    }))

    assert classify(tmp_path) == "normal_alert_gate_failed"
