import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml-service"))
from evaluation_matrix_validation import expected_experiments, validate_evaluation_matrix


DIGEST = "a" * 64


def _contract():
    return {
        "schema": "contract/v1",
        "result_schema": "result/v1",
        "release_id": "test-paired",
        "feature_capture_schema": "sentinel-feature-window/v2",
        "injection_schema": "sentinel-injection-interval/v2",
        "paired_replay_required": True,
        "confidence_level": 0.95,
        "trial_seeds": [1, 2],
        "tracks": {
            "syscall": {
                "minimum_normal_phases": 4,
                "minimum_independent_normal_runs": 2,
                "minimum_attack_trials": 4,
                "baselines": ["rules", "full"],
                "ablations": ["no_gate"],
            }
        },
    }


def _write_matrix(root, contract):
    for experiment_id, track in expected_experiments(contract).items():
        directory = root / experiment_id
        directory.mkdir()
        result = {
            "schema": contract["result_schema"],
            "experiment_id": experiment_id,
            "track": track,
            "release_id": contract["release_id"],
            "feature_capture_schema": contract["feature_capture_schema"],
            "injection_schema": contract["injection_schema"],
            "completed": True,
            "blind_set_used_for_training": False,
            "paired_replay": True,
            "trial_seeds": contract["trial_seeds"],
            "dataset_sha256": DIGEST,
            "dataset_manifest_sha256": DIGEST,
            "capture_sha256": DIGEST,
            "capture_manifest_sha256": DIGEST,
            "vocab_sha256": DIGEST,
            "split_sha256": DIGEST,
            "blind_attack_contract_sha256": DIGEST,
            "evaluation_protocol_sha256": DIGEST,
            "environment_sha256": DIGEST,
            "code_sha256": DIGEST,
            "normal": {
                "independent_runs": 2, "phases": 4,
                "windows": 50, "false_alerts": 0,
            },
            "attack": {"trials": 4, "detected": 3},
            "latency_seconds": {"sample_count": 3},
            "statistics": {"confidence_level": 0.95, "method": "block bootstrap"},
        }
        (directory / "result.json").write_text(json.dumps(result))


def test_evaluation_matrix_accepts_only_complete_comparable_results(tmp_path):
    contract = _contract()
    _write_matrix(tmp_path, contract)
    report = validate_evaluation_matrix(tmp_path, contract)
    assert report["valid"] is True
    assert report["completed_experiments"] == 3


def test_evaluation_matrix_rejects_missing_result(tmp_path):
    contract = _contract()
    _write_matrix(tmp_path, contract)
    path = tmp_path / "syscall__rules" / "result.json"
    path.unlink()
    report = validate_evaluation_matrix(tmp_path, contract)
    assert report["valid"] is False
    assert any("missing experiments" in error for error in report["errors"])


def test_evaluation_matrix_rejects_dataset_switch_and_blind_tuning(tmp_path):
    contract = _contract()
    _write_matrix(tmp_path, contract)
    path = tmp_path / "syscall__no_gate" / "result.json"
    result = json.loads(path.read_text())
    result["dataset_sha256"] = "b" * 64
    result["blind_set_used_for_training"] = True
    path.write_text(json.dumps(result))
    report = validate_evaluation_matrix(tmp_path, contract)
    assert report["valid"] is False
    assert any("blind-set" in error for error in report["errors"])
    assert any("incomparable dataset_sha256" in error for error in report["errors"])


def test_evaluation_matrix_requires_shared_frozen_protocol_digest(tmp_path):
    contract = _contract()
    _write_matrix(tmp_path, contract)
    path = tmp_path / "syscall__rules" / "result.json"
    result = json.loads(path.read_text())
    result.pop("evaluation_protocol_sha256")
    path.write_text(json.dumps(result))
    report = validate_evaluation_matrix(tmp_path, contract)
    assert report["valid"] is False
    assert any(
        "invalid evaluation_protocol_sha256" in error
        for error in report["errors"]
    )


def test_evaluation_matrix_can_gate_one_track_independently(tmp_path):
    contract = _contract()
    contract["tracks"]["agent"] = {
        "minimum_normal_phases": 4,
        "minimum_independent_normal_runs": 2,
        "minimum_attack_trials": 4,
        "baselines": ["semantic"],
        "ablations": [],
    }
    _write_matrix(tmp_path, contract)
    agent_result = tmp_path / "agent__semantic" / "result.json"
    agent_result.unlink()
    agent_result.parent.rmdir()
    report = validate_evaluation_matrix(tmp_path, contract, {"syscall"})
    assert report["valid"] is True
    assert report["selected_tracks"] == ["syscall"]
