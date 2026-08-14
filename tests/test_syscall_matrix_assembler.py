import json
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = (
    REPOSITORY_ROOT / "ml-service"
    if (REPOSITORY_ROOT / "ml-service").is_dir()
    else REPOSITORY_ROOT
)
sys.path.insert(0, str(SERVICE_ROOT))

from assemble_syscall_evaluation_matrix import (
    build_ml_result, build_rule_result, classification_metrics, normalized_latency,
    live_fast_path, sha256, verify_checksums,
)


def test_classification_metrics_preserve_normal_false_alerts():
    metrics = classification_metrics(180, 200, 20)
    assert metrics["recall_point"] == 0.9
    assert metrics["precision"] == 0.9
    assert metrics["f1"] == pytest.approx(0.9)
    assert "independent normal" in metrics["definition"]
    assert metrics["deployment_precision_claim_valid"] is False
    assert "different sampling units" in metrics["precision_f1_scope"]


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


def test_rule_outcomes_preserve_per_trial_right_censoring():
    from assemble_syscall_evaluation_matrix import normalized_outcomes
    rows = normalized_outcomes([{
        "injection_id": "trial-1", "pod_key": "production/api",
        "scenario": "probe", "seed": 1, "rate": 6,
        "start": 100, "end": 145, "attribution_end": 154,
        "detected": False,
        "horizon_right_censored_by_next_injection": True,
    }], horizon_seconds=30)
    assert rows[0]["censor_seconds"] == 54
    assert rows[0]["horizon_right_censored"] is True


def test_rule_outcomes_join_frozen_interval_metadata_when_adapter_omits_it():
    from assemble_syscall_evaluation_matrix import normalized_outcomes
    rows = normalized_outcomes([{
        "injection_id": "trial-1", "pod_key": "production/api",
        "scenario": "probe", "seed": 1, "rate": 6,
        "detected": True, "latency_seconds": 2.5,
    }], horizon_seconds=30, interval_metadata={
        "trial-1": {
            "start": 100, "end": 145, "attribution_end": 154,
            "horizon_right_censored_by_next_injection": True,
        },
    })
    assert rows[0]["latency_seconds"] == 2.5
    assert rows[0]["censor_seconds"] == 54
    assert rows[0]["horizon_right_censored"] is True


def test_rule_outcomes_use_canonical_censor_boundary_for_present_intervals():
    from assemble_syscall_evaluation_matrix import normalized_outcomes
    rows = normalized_outcomes([{
        "injection_id": "trial-1", "pod_key": "production/api",
        "scenario": "probe", "seed": 1, "rate": 6,
        "start": 100, "end": 145, "detected": False,
    }], horizon_seconds=30, interval_metadata={
        "trial-1": {
            "start": 100, "end": 145, "attribution_end": 154,
            "horizon_right_censored_by_next_injection": True,
        },
    })
    assert rows[0]["censor_seconds"] == 54
    assert rows[0]["horizon_right_censored"] is True


def test_rule_outcomes_reject_missing_interval_join():
    from assemble_syscall_evaluation_matrix import normalized_outcomes
    with pytest.raises(ValueError, match="interval metadata is missing"):
        normalized_outcomes([{
            "injection_id": "trial-1", "pod_key": "production/api",
            "scenario": "probe", "seed": 1, "rate": 6,
            "detected": False, "latency_seconds": None,
        }], horizon_seconds=30, interval_metadata={})


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
                "eligible_decision_windows": 50,
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
        "evaluator_source_sha256": sha256(
            SERVICE_ROOT / "evaluate_aims_normal_split.py"
        ),
        "evaluation_policy": policy, "candidate_sha256": candidate,
        "initial_calibration_sha256": "b" * 64,
        "phases": phases, "alerts": 2, "detections": 2, "windows": 1100,
        "eligible_decision_windows": 1000,
    }
    attack = {
        "experiment_id": "syscall__full_v7", "status": "complete",
        "evaluator_source_sha256": sha256(
            SERVICE_ROOT / "evaluate_aims_attack_replay.py"
        ),
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
        "attack_observability_audit_sha256": "8" * 64,
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
    assert result["normal"]["eligible_windows"] == 1000
    assert result["normal"]["false_alert_rate_per_eligible_window"] == 0.002
    assert len(result["normal"]["phase_outcomes"]) == 20
    assert result["attack"]["recall"]["estimate"] == 0.9
    assert result["attack"]["recall_point"] == 0.9
    assert result["latency_seconds"]["sample_count"] == 180
    assert len(result["attack"]["outcomes"]) == 200
    assert result["attack"]["outcomes"][0]["censor_seconds"] == 35
    assert result["normal_capture_sha256"] == "6" * 64
    assert result["attack_observability_audit_sha256"] == "8" * 64
    assert len(result["code_sha256"]) == 64

    attack["evaluator_source_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="attack evaluator provenance"):
        build_ml_result("full_v7", normal, attack, common)


def test_ml_result_rejects_missing_eligible_window_accounting(tmp_path):
    # The full integration fixture above proves the accepted shape. This
    # focused mutation guards against reintroducing alert-dependent FPR
    # denominators in future assemblers.
    phases = [{
        "phase": "aims-steady-run-02", "alerts": 0,
        "eligible_decision_windows": 1,
    }]
    with pytest.raises(ValueError, match="eligible-window accounting"):
        # Validation happens before attack trial materialization.
        build_ml_result("full_v7", {
            "experiment_id": "syscall__full_v7", "status": "complete",
            "evaluator_source_sha256": sha256(
                SERVICE_ROOT / "evaluate_aims_normal_split.py"
            ),
            "evaluation_policy": {}, "candidate_sha256": {},
            "initial_calibration_sha256": "x", "development_gate": {},
            "phases": phases, "alerts": 0, "detections": 0, "windows": 1,
        }, {
            "experiment_id": "syscall__full_v7", "status": "complete",
            "evaluator_source_sha256": sha256(
                SERVICE_ROOT / "evaluate_aims_attack_replay.py"
            ),
            "evaluation_policy": {"fast_path_replayed": False},
            "candidate_sha256": {}, "initial_calibration_sha256": "x",
            "development_gate": {}, "completed_trials": 200,
            "labels_used_for_training_or_tuning": False,
            "attack_capture_sha256": "c", "evaluation_protocol_sha256": "p",
        }, {
            "capture_sha256": "c", "evaluation_protocol_sha256": "p",
        })


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
        "attack_observability_audit_sha256": "8" * 64,
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


def test_live_fast_path_keeps_attack_evidence_when_normal_track_is_excluded(tmp_path):
    child = tmp_path / "trial.json"
    child.write_text(json.dumps({
        "scenarios": {
            f"scenario-{index:03d}": {
                "fast_path_expected": index < 20,
                "fast_path_expected_matched": index < 19,
                "fast_path_warning_count": int(index < 19),
                "fast_path_latency_seconds": 0.5 if index < 19 else None,
            }
            for index in range(200)
        },
    }))
    aggregate = tmp_path / "aggregate.json"
    aggregate.write_text(json.dumps({
        "trials": [{"report_path": str(child)}],
    }))
    exclusion = tmp_path / "normal.exclusion.json"
    exclusion.write_text(json.dumps({
        "schema": "sentinel-fast-path-normal-exclusion/v1",
        "valid": False, "status": "excluded", "claim_available": False,
        "automatic_promotion": False,
        "evidence_class": "retrospective_operational_normal_evidence",
        "claim_limit": "no normal claim", "reason": "counter changed",
    }))
    result = live_fast_path(
        aggregate, tmp_path / "missing-normal.json", exclusion,
    )
    assert result["scenario_trials"] == 200
    assert result["expected_matched"] == 19
    assert result["normal_operational_evidence"]["status"] == "excluded"
    assert result["normal_operational_evidence"]["early_warning_count"] is None
    assert result["normal_operational_evidence"]["reason"] == "counter changed"
