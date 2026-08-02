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
        "confidence_level": 0.95,
        "trial_seeds": [1, 2],
        "tracks": {
            "syscall": {
                "minimum_normal_runs": 2,
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
            "completed": True,
            "blind_set_used_for_training": False,
            "trial_seeds": contract["trial_seeds"],
            "dataset_sha256": DIGEST,
            "split_sha256": DIGEST,
            "blind_attack_contract_sha256": DIGEST,
            "environment_sha256": DIGEST,
            "code_sha256": DIGEST,
            "normal": {"runs": 2, "windows": 50, "false_alerts": 0},
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
