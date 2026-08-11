import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "ml-service"))
from validate_v8_capture_contract import validate_contract, sha256


def contracts(vocab):
    evaluation = {
        "release_id": "v8-test", "feature_capture_schema": "feature/v2",
        "injection_schema": "injection/v2",
        "tracks": {"syscall": {
            "minimum_normal_phases": 20,
            "minimum_independent_normal_runs": 5,
        }},
    }
    split = {
        "schema": "sentinel-v8-capture-split/v1", "release_id": "v8-test",
        "frozen_before_capture": True, "capture_mode": "sequence",
        "feature_schema": "feature/v2", "injection_schema": "injection/v2",
        "vocab_sha256": sha256(vocab),
        "normal": {"minutes_per_phase": 72,
                   "regimes": ["steady", "burst", "recovery", "toolmix"],
                   "runs": [
                       {"run_id": f"normal-run-{index:02d}",
                        "role": "candidate_fit" if index == 1
                        else "independent_evaluation"}
                       for index in range(1, 7)
                   ]},
        "separation": {"evaluation_runs_may_train_or_tune": False,
                       "attack_windows_may_train_or_tune": False,
                       "split_unit": "whole run before feature-window construction"},
    }
    return split, evaluation


def test_v8_capture_contract_accepts_one_fit_and_five_test_runs(tmp_path):
    vocab = tmp_path / "vocab.pkl"
    vocab.write_bytes(b"frozen-vocabulary")
    split, evaluation = contracts(vocab)
    assert validate_contract(split, evaluation, vocab) == []


def test_v8_capture_contract_rejects_split_leakage(tmp_path):
    vocab = tmp_path / "vocab.pkl"
    vocab.write_bytes(b"frozen-vocabulary")
    split, evaluation = contracts(vocab)
    split["normal"]["runs"][1]["role"] = "candidate_fit"
    split["separation"]["evaluation_runs_may_train_or_tune"] = True
    errors = validate_contract(split, evaluation, vocab)
    assert "exactly one fit run is required" in errors
    assert "insufficient independent evaluation runs" in errors
    assert "fit/evaluation leakage exclusion is incomplete" in errors
