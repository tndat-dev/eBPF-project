import json

from sentinel_pulse.evaluate_operational_latency import evaluate


def _marker(path):
    path.write_text(
        json.dumps(
            {
                "schema": "sentinel-pulse-semantic-soak-start-v4",
                "blind_evaluation_started": False,
                "started_not_before": "1970-01-01T00:01:40+00:00",
                "run_id": "soak-test",
                "model_manifest_sha256": "a" * 64,
                "decision_policy_sha256": "b" * 64,
            }
        )
    )


def _decision(end, processing):
    return {
        "schema": "sentinel-pulse-decision-v1",
        "status": "normal",
        "run_id": "soak-test",
        "model_manifest_sha256": "a" * 64,
        "decision_policy_sha256": "b" * 64,
        "workload_key": "production/catalog:app",
        "window_start": end - 1.0,
        "window_end": end,
        "alerted_at": end + processing,
        "post_window_processing_seconds": processing,
        "inference_ms": 3.0,
    }


def test_operational_latency_is_marker_bound_and_not_attack_latency(tmp_path):
    marker = tmp_path / "SOAK_START.json"
    _marker(marker)
    decisions = tmp_path / "decisions.jsonl"
    decisions.write_text(
        "".join(
            json.dumps(row) + "\n"
            for row in (_decision(99.0, 0.1), _decision(100.0, 0.2), _decision(101.0, 1.2))
        )
    )
    report = evaluate([decisions], marker)
    assert report["excluded_scored_windows_before_marker"] == 1
    assert report["scored_rows"] == 2
    assert report["window_start_to_decision_over_2s"] == 1
    assert report["latency"]["inference_ms"]["p99"] == 3.0
    assert report["true_attack_kernel_to_alert_claim"] is False
