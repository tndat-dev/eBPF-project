import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[1] / "ml-service"
sys.path.insert(0, str(SERVICE_ROOT))

from assemble_syscall_evaluation_matrix import (
    build_ml_result, build_rule_result, classification_metrics, normalized_latency,
    verify_checksums,
)


def test_classification_metrics_preserve_normal_false_alerts():
    metrics = classification_metrics(180, 200, 20)
    assert metrics["recall_point"] == 0.9
    assert metrics["precision"] == 0.9
    assert metrics["f1"] == pytest.approx(0.9)
    assert "independent normal" in metrics["definition"]


def test_latency_normalizer_accepts_both_report_shapes():
    assert normalized_latency({
        "count": 2, "min": 1, "median": 2, "p95": 3,
        "p99": 4, "max": 5,
    }) == {
        "sample_count": 2, "minimum": 1, "median": 2,
        "p95": 3, "p99": 4, "maximum": 5,
    }
    assert normalized_latency({
        "count": 1, "minimum": 0.5, "maximum": 0.5,
    })["sample_count"] == 1


def test_classification_metrics_reject_invalid_counts():
    with pytest.raises(ValueError):
        classification_metrics(201, 200, 0)
    with pytest.raises(ValueError):
        classification_metrics(1, 2, -1)


def test_ml_result_binds_normal_and_attack_policy(tmp_path):
    phases = []
    for run in range(2, 7):
        for regime in ("steady", "burst", "recovery", "toolmix"):
            manifest = tmp_path / f"{regime}-{run}.json"
            manifest.write_text('{"actual_duration_seconds": 3600}')
            phases.append({
                "phase": f"aims-{regime}-run-{run:02d}",
                "source": {"manifest": str(manifest)},
                "alerts": int(run == 2 and regime in ("steady", "burst")),
            })
    policy = {
        "require_behavior_gate": True,
        "enable_extreme_volume_gate": True,
        "enable_adaptive_threshold": True,
        "confirmation_windows": 2,
        "score_component": "ensemble", "model_routing": "per_workload",
    }
    candidate = {"model": "a" * 64}
    normal = {
        "experiment_id": "syscall__full_v7", "status": "complete",
        "evaluation_policy": policy, "candidate_sha256": candidate,
        "initial_calibration_sha256": "b" * 64,
        "phases": phases, "alerts": 2, "detections": 2, "windows": 1000,
    }
    attack = {
        "experiment_id": "syscall__full_v7", "status": "complete",
        "evaluation_policy": {**policy, "fast_path_replayed": False},
        "candidate_sha256": candidate,
        "initial_calibration_sha256": "b" * 64,
        "completed_trials": 200, "detected_trials": 180,
        "post_attack_horizon_seconds": 30,
        "labels_used_for_training_or_tuning": False,
        "attack_capture_sha256": "c" * 64,
        "evaluation_protocol_sha256": "d" * 64,
        "recall": {"estimate": 0.9},
        "latency_seconds": {"count": 180, "median": 10},
        "trial_median_inference_ms": {"count": 200, "median": 1},
        "trials": [
            {
                "injection_id": f"trial-{index:03d}",
                "pod_key": "production/catalog", "scenario": "exec",
                "seed": index % 5, "rate": 2, "start": index * 40,
                "end": index * 40 + 5, "detected": index < 180,
                "first_confirmation_latency_seconds": (
                    2.0 if index < 180 else None
                ),
            }
            for index in range(200)
        ],
    }
    common = {
        "contract": {
            "result_schema": "result/v1", "release_id": "v8",
            "feature_capture_schema": "feature/v2",
            "injection_schema": "injection/v2", "trial_seeds": [1],
        },
        "dataset_sha256": "e" * 64,
        "dataset_manifest_sha256": "f" * 64,
        "capture_sha256": "c" * 64,
        "capture_manifest_sha256": "1" * 64,
        "normal_capture_sha256": "6" * 64,
        "normal_capture_manifest_sha256": "7" * 64,
        "vocab_sha256": "2" * 64, "split_sha256": "3" * 64,
        "blind_attack_contract_sha256": "4" * 64,
        "evaluation_protocol_sha256": "d" * 64,
        "environment_sha256": "5" * 64,
        "normal_phase_contract": {
            phase["phase"]: {
                "run_id": f"normal-run-{phase['phase'].rsplit('-', 1)[-1]}",
                "traffic_regime": phase["phase"].split("-")[1],
                "exposure_seconds": 3600,
            }
            for phase in phases
        },
    }
    result = build_ml_result("full_v7", normal, attack, common)
    assert result["normal"]["independent_runs"] == 5
    assert result["normal"]["phases"] == 20
    assert result["normal"]["exposure_hours"] == 20
    assert len(result["normal"]["phase_outcomes"]) == 20
    assert result["attack"]["recall"]["estimate"] == 0.9
    assert result["attack"]["recall_point"] == 0.9
    assert result["latency_seconds"]["sample_count"] == 180
    assert len(result["attack"]["outcomes"]) == 200
    assert result["attack"]["outcomes"][0]["censor_seconds"] == 35
    assert result["normal_capture_sha256"] == "6" * 64
    assert len(result["code_sha256"]) == 64


def test_checksum_verifier_rejects_tamper(tmp_path):
    artifact = tmp_path / "artifact.json"
    artifact.write_text("original")
    import hashlib
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (tmp_path / "SHA256SUMS").write_text(f"{digest}  artifact.json\n")
    verify_checksums(tmp_path)
    artifact.write_text("tampered")
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_checksums(tmp_path)


def test_rule_result_normalizes_tetragon_alert_rate_name():
    common = {
        "contract": {
            "result_schema": "result/v1", "release_id": "v8",
            "feature_capture_schema": "feature/v2",
            "injection_schema": "injection/v2", "trial_seeds": [1],
        },
        "dataset_sha256": "a" * 64, "dataset_manifest_sha256": "b" * 64,
        "capture_sha256": "c" * 64, "capture_manifest_sha256": "d" * 64,
        "normal_capture_sha256": "e" * 64,
        "normal_capture_manifest_sha256": "f" * 64,
        "vocab_sha256": "1" * 64, "split_sha256": "2" * 64,
        "blind_attack_contract_sha256": "3" * 64,
        "evaluation_protocol_sha256": "4" * 64,
        "environment_sha256": "5" * 64,
        "normal_phase_contract": {
            "aims-steady-run-02": {
                "run_id": "normal-run-02", "traffic_regime": "steady",
                "exposure_seconds": 3600,
            },
        },
    }
    normal = {
        "independent_runs": 1, "phases": 1, "windows": 100,
        "false_alerts": 2, "exposure_hours": 1, "alerts_per_hour": 2,
        "phase_outcomes": [{
            "phase": "aims-steady-run-02", "run_id": "normal-run-02",
            "windows": 100, "false_alerts": 2,
        }],
    }
    attack = {
        "trials": 1, "detected": 1, "recall": {"estimate": 1},
        "post_attack_horizon_seconds": 30,
        "outcomes": [{
            "injection_id": "trial-1", "pod_key": "production/api",
            "scenario": "exec", "seed": 1, "rate": 2,
            "start": 10, "end": 15, "detected": True,
            "latency_seconds": 1,
        }],
    }
    result = build_rule_result(
        "tetragon_rule_only", normal, attack, {"count": 1, "median": 1},
        common, "6" * 64,
    )
    assert result["normal"]["false_alerts_per_hour"] == 2
    assert "alerts_per_hour" not in result["normal"]
