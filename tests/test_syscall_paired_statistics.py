import json
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[1] / "ml-service"
sys.path.insert(0, str(SERVICE_ROOT))

from analyze_syscall_evaluation_matrix import (
    analyze_matrix, exact_mcnemar_p, holm_adjust,
)


def result(experiment_id, detections, latency_offset=0.0):
    outcomes = []
    for index, detected in enumerate(detections):
        outcomes.append({
            "injection_id": f"trial-{index}",
            "pod_key": f"production/workload-{index % 2}",
            "scenario": "exec", "seed": index, "rate": 2,
            "detected": detected,
            "latency_seconds": 1.0 + latency_offset if detected else None,
            "censor_seconds": 35.0,
        })
    return {
        "experiment_id": experiment_id, "release_id": "v8",
        "normal_capture_sha256": "a" * 64,
        "capture_sha256": "b" * 64, "split_sha256": "c" * 64,
        "evaluation_protocol_sha256": "d" * 64,
        "environment_sha256": "e" * 64,
        "normal": {"false_alerts": 0, "exposure_hours": 20.0},
        "attack": {
            "trials": len(outcomes), "detected": sum(detections),
            "recall_point": sum(detections) / len(outcomes),
            "recall": {"estimate": sum(detections) / len(outcomes)},
            "outcomes": outcomes,
        },
    }


def write_result(root, experiment_id, document):
    directory = root / experiment_id
    directory.mkdir()
    (directory / "result.json").write_text(json.dumps(document))


def test_exact_mcnemar_and_holm_correction():
    assert exact_mcnemar_p(0, 0) == 1.0
    assert exact_mcnemar_p(10, 0) == pytest.approx(2 / 1024)
    pairs = [{"mcnemar_p": 0.01}, {"mcnemar_p": 0.04}, {"mcnemar_p": 0.5}]
    holm_adjust(pairs)
    assert pairs[0]["mcnemar_holm_p"] == pytest.approx(0.03)
    assert pairs[1]["mcnemar_holm_p"] == pytest.approx(0.08)
    assert pairs[2]["mcnemar_holm_p"] == pytest.approx(0.5)


def test_paired_analysis_uses_trial_identity_and_workload_blocks(tmp_path):
    left = "syscall__left"
    right = "syscall__right"
    write_result(tmp_path, left, result(left, [True, True, False, False]))
    write_result(
        tmp_path, right,
        result(right, [False, True, True, False], latency_offset=1.0),
    )
    report = analyze_matrix(
        tmp_path, {left, right}, bootstrap_iterations=100, seed=7,
    )
    assert report["methods"] == 2
    assert report["trials_per_method"] == 4
    comparison = report["comparisons"][0]
    assert comparison["a_only_detected"] == 1
    assert comparison["b_only_detected"] == 1
    assert comparison["both_detected"] == 1
    assert comparison["neither_detected"] == 1
    assert comparison["recall_difference_a_minus_b"]["blocks"] == 2
    assert report["method_summaries"][left]["detected_latency_cdf"]["1.0"] == 1.0


def test_paired_analysis_rejects_metadata_drift(tmp_path):
    left = "syscall__left"
    right = "syscall__right"
    left_result = result(left, [True, False])
    right_result = result(right, [True, False])
    right_result["attack"]["outcomes"][0]["seed"] = 999
    write_result(tmp_path, left, left_result)
    write_result(tmp_path, right, right_result)
    with pytest.raises(ValueError, match="trial metadata mismatch"):
        analyze_matrix(tmp_path, {left, right}, bootstrap_iterations=10)


def test_paired_analysis_rejects_missing_method(tmp_path):
    left = "syscall__left"
    write_result(tmp_path, left, result(left, [True, False]))
    with pytest.raises(ValueError, match="experiment set mismatch"):
        analyze_matrix(tmp_path, {left, "syscall__right"}, bootstrap_iterations=10)
