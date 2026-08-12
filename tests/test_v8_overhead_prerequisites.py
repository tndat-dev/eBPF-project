import json
import pickle
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service"
sys.path.insert(0, str(SERVICE_ROOT))

from validate_v8_overhead_prerequisites import candidate_hashes, sha256, validate


def fixture(tmp_path):
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "vocab.pkl").write_bytes(pickle.dumps({"read": 0}))
    (candidate / "training_report.json").write_text('{"accepted_offline":true}')
    calibration = tmp_path / "calibration.json"
    calibration.write_text("{}")
    hashes = candidate_hashes(candidate)
    normal = tmp_path / "normal.json"
    normal.write_text(json.dumps({
        "role": "independent_evaluation", "status": "complete", "passed": True,
        "candidate_sha256": hashes,
        "initial_calibration_sha256": sha256(calibration),
    }))
    blind = tmp_path / "blind.json"
    blind.write_text(json.dumps({
        "expected_trials": 40, "completed_trials": 40,
        "expected_scenario_trials": 200, "total": 200,
        "model_sha256": hashes,
        "normal_calibration_sha256": sha256(calibration),
        "paired_attack_evidence": {
            "source_count": 200, "injection_intervals": 200,
            "labels_used_for_training": False,
        },
        "all_passed": False,
    }))
    marker = tmp_path / "NORMAL_ABLATION_REPLAY_COMPLETE"
    marker.write_text("")
    return candidate, calibration, normal, blind, marker


def test_v8_overhead_gate_accepts_terminal_miss_without_tuning(tmp_path):
    paths = fixture(tmp_path)
    report = validate(*paths)
    assert report["valid"]
    assert report["blind_infrastructure_complete"]
    assert report["blind_all_passed"] is False
    assert report["automatic_promotion"] is False


def test_v8_overhead_gate_rejects_candidate_drift(tmp_path):
    paths = fixture(tmp_path)
    (paths[0] / "model.pkl").write_text("drift")
    with pytest.raises(ValueError, match="normal prerequisite"):
        validate(*paths)


def test_v8_overhead_gate_rejects_incomplete_paired_attack(tmp_path):
    paths = fixture(tmp_path)
    blind = json.loads(paths[3].read_text())
    blind["paired_attack_evidence"]["source_count"] = 199
    paths[3].write_text(json.dumps(blind))
    with pytest.raises(ValueError, match="blind evidence"):
        validate(*paths)
