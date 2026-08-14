import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service"
sys.path.insert(0, str(SERVICE_ROOT))

from render_syscall_paper_results import METHOD_LABELS, render


def result(experiment_id, *, full=False):
    fast_path = {"enabled": False, "replayed": False}
    if full:
        fast_path = {
            "enabled": True, "replayed": False,
            "latency_seconds": {"median": .8, "p95": 1.2, "p99": 1.4},
            "normal_operational_evidence": {
                "early_warning_count": 0, "exposure_hours": 24,
                "early_warnings_per_hour": 0,
                "claim_limit": "retrospective operational evidence only",
            },
        }
    return {
        "experiment_id": experiment_id,
        "normal": {
            "independent_runs": 5, "phases": 20, "windows": 1000,
            "eligible_windows": 900,
            "exposure_hours": 24, "false_alerts": 1,
            "false_alerts_per_hour": 1 / 24,
            "false_alert_rate_per_eligible_window": 1 / 900,
        },
        "attack": {
            "trials": 200, "detected": 190, "recall_point": .95,
            "recall": {"lower": .91, "upper": .97},
            "precision": 190 / 191, "f1": .97,
        },
        "latency_seconds": {"median": 10, "p95": 19, "p99": 20},
        "inference_ms": {"median": 1.2}, "fast_path": fast_path,
    }


def matrix(tmp_path):
    for experiment_id in METHOD_LABELS:
        directory = tmp_path / experiment_id
        directory.mkdir()
        (directory / "result.json").write_text(json.dumps(result(
            experiment_id, full=experiment_id == "syscall__full_v7",
        )))
    comparisons = [
        {"significant_at_0_05": index == 0,
         "normal_significant_at_0_05": False}
        for index in range(55)
    ]
    (tmp_path / "paired_statistics.json").write_text(json.dumps({
        "methods": 11, "pairwise_comparisons": 55,
        "comparisons": comparisons,
    }))


def test_renderer_writes_complete_non_overclaiming_markdown_and_csv(tmp_path):
    matrix(tmp_path)
    markdown, csv_path = tmp_path / "results.md", tmp_path / "results.csv"
    report = render(tmp_path, markdown, csv_path)
    assert report["methods"] == 11
    assert report["comparisons"] == 55
    text = markdown.read_text()
    assert "1/55" in text
    assert "false alerts/hour` không phải statistical FPR" in text
    assert "eligible-window⁻¹" in text
    assert "Protocol-mixed precision / F1*" in text
    assert "deployment precision/F1" in text
    assert "retrospective operational evidence only" in text
    assert "exact kernel-event latency" in text
    assert len(csv_path.read_text().splitlines()) == 12


def test_renderer_refuses_incomplete_matrix(tmp_path):
    matrix(tmp_path)
    (tmp_path / "syscall__full_v7" / "result.json").unlink()
    with pytest.raises(ValueError, match="all 11"):
        render(tmp_path, tmp_path / "results.md", tmp_path / "results.csv")
