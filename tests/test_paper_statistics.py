import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml-service"))
from paper_statistics import build_report, main, wilson_interval


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
