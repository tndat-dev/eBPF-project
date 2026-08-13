import hashlib
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("sklearn")

SERVICE_ROOT = Path(__file__).resolve().parents[1] / "ml-service"
if not SERVICE_ROOT.is_dir():
    SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from evaluate_aims_normal_split import (candidate_hashes,
                                        development_gate,
                                        matrix_dimensions,
                                        resumable_phase_reports,
                                        ScoreComponentManager,
                                        validate_blind_prerequisite,
                                        validate_calibration_provenance,
                                        write_report)


def test_rejected_candidate_override_is_shared_ablation_only():
    training = {
        "accepted_offline": False,
        "model_routing": "shared_workload",
        "labels_used_for_training_or_tuning": False,
        "independent_evaluation_rows_used": False,
        "attack_rows_used": False,
    }
    with pytest.raises(ValueError, match="development gate"):
        development_gate(training, "shared_workload", False)
    gate = development_gate(training, "shared_workload", True)
    assert gate == {
        "accepted": False,
        "rejected_shared_ablation_evaluation_only": True,
        "automatic_promotion": False,
    }
    with pytest.raises(ValueError, match="development gate"):
        development_gate(training, "per_workload", True)
    with pytest.raises(ValueError, match="development gate"):
        development_gate({**training, "attack_rows_used": True},
                         "shared_workload", True)


def test_v8_matrix_dimensions_include_all_six_runs():
    split = {
        "schema": "sentinel-v8-capture-split/v1",
        "normal": {
            "minutes_per_phase": 72,
            "runs": [{"run_id": f"normal-run-{run:02d}"}
                     for run in range(1, 7)],
        },
    }
    release = {"normal_protocol": {"independent_runs_per_regime": 5}}
    assert matrix_dimensions(split, release) == (6, 72)


def test_terminal_calibration_is_bound_to_fit_candidate(tmp_path):
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    training = candidate / "training_report.json"
    dataset = candidate / "dataset_manifest.json"
    calibration = tmp_path / "calibration.json"
    training.write_text("training")
    dataset.write_text("dataset")
    calibration.write_text("calibration")
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report = tmp_path / "calibration.report.json"
    report.write_text(json.dumps({
        "source_role": "candidate_fit",
        "evaluation_data_used": False,
        "training_report_sha256": digest(training),
        "dataset_manifest_sha256": digest(dataset),
        "calibration_sha256": digest(calibration),
    }))
    result = validate_calibration_provenance(
        report, calibration, candidate
    )
    assert result["sha256"] == digest(report)
    calibration.write_text("tampered")
    with pytest.raises(ValueError, match="calibration_sha256"):
        validate_calibration_provenance(report, calibration, candidate)


def test_candidate_hashes_are_name_sorted_and_content_bound(tmp_path):
    (tmp_path / "z").write_bytes(b"last")
    (tmp_path / "a").write_bytes(b"first")
    result = candidate_hashes(tmp_path)
    assert list(result) == ["a", "z"]
    assert result["a"] == hashlib.sha256(b"first").hexdigest()


def test_blind_test_requires_passed_validation_for_exact_candidate(tmp_path):
    report = tmp_path / "validation.json"
    hashes = {"model": "abc"}
    report.write_text(json.dumps({
        "role": "independent_validation", "passed": True,
        "candidate_sha256": hashes,
    }))
    report_doc = json.loads(report.read_text())
    report_doc["initial_calibration_sha256"] = "c" * 64
    report.write_text(json.dumps(report_doc))
    result = validate_blind_prerequisite(report, hashes, "c" * 64)
    assert result["sha256"] == hashlib.sha256(report.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="different candidate"):
        validate_blind_prerequisite(report, {"model": "changed"}, "c" * 64)
    with pytest.raises(ValueError, match="different calibration"):
        validate_blind_prerequisite(report, hashes, "d" * 64)


def test_blind_test_rejects_failed_or_missing_validation(tmp_path):
    report = tmp_path / "validation.json"
    report.write_text(json.dumps({
        "role": "independent_validation", "passed": False,
        "candidate_sha256": {},
    }))
    with pytest.raises(ValueError, match="not a passed"):
        validate_blind_prerequisite(report, {}, "c" * 64)
    with pytest.raises(ValueError, match="requires"):
        validate_blind_prerequisite(None, {}, "c" * 64)


def test_evaluation_checkpoint_is_atomic_and_identity_bound(tmp_path):
    output = tmp_path / "evaluation.json"
    identity = {
        "status": "evaluating",
        "role": "independent_validation",
        "evidence_root": "/evidence",
        "candidate_sha256": {"model": "a"},
        "initial_calibration_sha256": "b",
        "split_contract_sha256": "c",
        "release_contract_sha256": "d",
        "evaluation_policy": {
            "require_behavior_gate": True,
            "enable_extreme_volume_gate": True,
            "enable_adaptive_threshold": True,
            "confirmation_windows": 2,
            "score_component": "ensemble",
        },
        "phases": [{"phase": "steady-02", "passed": True}],
    }
    write_report(output, identity)
    assert not output.with_suffix(".json.tmp").exists()
    assert resumable_phase_reports(
        output, identity, ["steady-02", "burst-02"],
    ) == identity["phases"]

    changed = dict(identity, initial_calibration_sha256="changed")
    with pytest.raises(ValueError, match="identity mismatch"):
        resumable_phase_reports(output, changed, ["steady-02"])

    changed_policy = dict(
        identity,
        evaluation_policy={**identity["evaluation_policy"],
                           "confirmation_windows": 1},
    )
    with pytest.raises(ValueError, match="identity mismatch"):
        resumable_phase_reports(output, changed_policy, ["steady-02"])


def test_evaluation_checkpoint_rejects_non_prefix_phases(tmp_path):
    output = tmp_path / "evaluation.json"
    report = {
        "status": "evaluating", "role": "independent_validation",
        "evidence_root": "/evidence", "candidate_sha256": {},
        "initial_calibration_sha256": "b",
        "split_contract_sha256": "c", "release_contract_sha256": "d",
        "phases": [{"phase": "burst-02"}],
    }
    write_report(output, report)
    with pytest.raises(ValueError, match="not a phase prefix"):
        resumable_phase_reports(output, report, ["steady-02", "burst-02"])


def test_score_component_manager_keeps_fixed_baseline_at_literal_threshold():
    class Manager:
        vocab_size = 2
        _models = {"production/api": type(
            "Bundle", (), {"baseline_scores": [.95]}
        )()}

        def list_models(self):
            return ["production/api"]

        def score(self, _key, _vector):
            return {
                "ensemble_score": .7,
                "lstm_score": .6,
                "if_score": .9,
                "behavior_limits": {},
            }

    fixed = ScoreComponentManager(
        Manager(), "isolation_forest", adaptive_threshold=False,
    )
    assert fixed.score("production/api", None)["ensemble_score"] == .9
    assert fixed._models["production/api"].baseline_scores == []

    adaptive = ScoreComponentManager(
        Manager(), "lstm", adaptive_threshold=True,
    )
    assert adaptive.score("production/api", None)["ensemble_score"] == .6
    assert adaptive._models is Manager._models
