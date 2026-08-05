import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml-service"))
from paper_statistics import (
    build_report,
    load_blind_attack_rows,
    main,
    wilson_interval,
)


def _normal():
    return {
        "passed": True,
        "detections": 0,
        "models": {"production/a": {"windows": 100}},
    }


def _attack():
    scenarios = {
        "escape": {
            "detected": True,
            "detection_latency_seconds": 2.0,
            "fast_path_latency_seconds": 0.5,
            "inference_median_ms": 3.0,
            "sensor_health_healthy": True,
            "normal_alerts_before_attack": 0,
        },
        "exfil": {
            "detected": False,
            "detection_latency_seconds": None,
            "fast_path_latency_seconds": None,
            "inference_median_ms": 4.0,
            "sensor_health_healthy": True,
            "normal_alerts_before_attack": 0,
        },
    }
    return {
        "all_passed": False,
        "workloads": {"production/a": {"report": {"scenarios": scenarios}}},
    }


def test_wilson_zero_successes_has_nonzero_upper_bound():
    interval = wilson_interval(0, 100)
    assert interval[0] == 0.0
    assert 0.03 < interval[1] < 0.04


def test_publication_report_keeps_sample_units_and_failed_attacks():
    report = build_report(_normal(), _attack())
    assert report["confusion_counts"] == {
        "true_positive": 1,
        "false_negative": 1,
        "false_positive": 0,
        "true_negative": 100,
    }
    assert report["metrics"]["recall"]["estimate"] == 0.5
    assert report["latency_seconds"]["confirmed_ml"]["count"] == 1
    assert report["sample_units"]["normal"] == "eligible workload window"


def test_publication_report_groups_by_workload_and_scenario():
    report = build_report(_normal(), _attack())
    assert report["by_workload"]["production/a"]["recall"]["trials"] == 2
    assert report["by_scenario"]["escape"]["recall"]["estimate"] == 1.0
    assert report["by_scenario"]["exfil"]["recall"]["estimate"] == 0.0


def test_derived_json_is_location_independent(tmp_path, monkeypatch):
    outputs = []
    for location in ("author", "reviewer"):
        directory = tmp_path / location
        directory.mkdir()
        normal = directory / "normal.json"
        attack = directory / "attack.json"
        output = directory / "statistics.json"
        normal.write_text(json.dumps(_normal()))
        attack.write_text(json.dumps(_attack()))
        monkeypatch.setattr(sys, "argv", [
            "paper_statistics.py", "--normal", str(normal),
            "--attack", str(attack), "--output", str(output),
        ])
        assert main() == 0
        outputs.append(output.read_bytes())
    assert outputs[0] == outputs[1]


def test_blind_matrix_validates_hashes_and_preserves_metadata(tmp_path):
    trial_dir = tmp_path / "service-trial-01" / "run"
    trial_dir.mkdir(parents=True)
    trial_report = {
        "runtime_binary_sha256": "binary",
        "runtime_code_sha256": {"detector.py": "source"},
        "validation_harness_sha256": "harness",
        "scenarios": {
            "escape": {
                "detected": False,
                "detection_latency_seconds": None,
                "fast_path_latency_seconds": 0.25,
                "inference_median_ms": 2.0,
                "sensor_health_healthy": True,
                "normal_alerts_before_attack": 0,
                "fast_path_expected": True,
                "fast_path_expected_matched": True,
                "attack_acknowledged": True,
            }
        },
    }
    trial_path = trial_dir / "report.json"
    trial_path.write_text(json.dumps(trial_report))
    import hashlib
    digest = hashlib.sha256(trial_path.read_bytes()).hexdigest()
    aggregate = {
        "completed_trials": 1,
        "expected_scenario_trials": 1,
        "detected": 0,
        "runtime_binary_sha256": "binary",
        "runtime_source_sha256": "source",
        "trials": [{
            "target": "production/service",
            "trial": 1,
            "rate": 6,
            "seed": 101,
            "total": 1,
            "detected": 0,
            "report_path": str(trial_path),
            "report_sha256": digest,
        }],
    }
    aggregate_path = tmp_path / "report.json"
    aggregate_path.write_text(json.dumps(aggregate))
    rows = load_blind_attack_rows(aggregate_path, aggregate)
    assert rows[0]["workload"] == "production/service"
    assert rows[0]["rate"] == 6
    assert rows[0]["attack_acknowledged"] is True


def test_split_normal_reports_use_eligible_windows_and_reject_overlap():
    normals = [
        {"passed": True, "detections": 0, "eligible_decision_windows": 40,
         "completed_phases": ["run-02"]},
        {"passed": True, "detections": 0, "eligible_decision_windows": 60,
         "completed_phases": ["run-04"]},
    ]
    report = build_report(normals, _attack())
    assert report["metrics"]["false_alert_rate_per_window"]["trials"] == 100
    assert report["evidence_health"]["normal_phase_count"] == 2
