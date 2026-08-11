import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service"
sys.path.insert(0, str(SERVICE_ROOT))

from validate_generalization_contract import validate_contract


CONTRACT = SERVICE_ROOT / "generalization_evaluation_contract.json"


def test_generalization_contract_is_frozen_leakage_safe_and_hash_bound():
    report = validate_contract(CONTRACT, SERVICE_ROOT)
    assert report["valid"], report["errors"]
    assert report["targets"] == 8
    assert report["folds"] == 8


def test_generalization_contract_rejects_v8_seed_reuse(tmp_path):
    contract = json.loads(CONTRACT.read_text())
    attack = json.loads((SERVICE_ROOT / "v8_blind_attack_contract.json").read_text())
    contract["generalization_attack_seeds"][0] = attack["trial_seeds"][0]
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(contract))
    report = validate_contract(path, SERVICE_ROOT)
    assert not report["valid"]
    assert any("overlap V8" in error for error in report["errors"])


def test_generalization_contract_rejects_held_out_calibration(tmp_path):
    contract = json.loads(CONTRACT.read_text())
    contract["generalization_tracks"]["leave_one_workload_out"][
        "adaptive_threshold_on_held_out_data"
    ] = True
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(contract))
    report = validate_contract(path, SERVICE_ROOT)
    assert not report["valid"]
    assert any("zero-shot leakage" in error for error in report["errors"])
