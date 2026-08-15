import json
from pathlib import Path

import pytest

from sentinel_pulse.decision_policy import corroborate, load_decision_policy


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "sentinel_pulse" / "protocol" / "decision-policy-semantic-v1.json"
SCORE_POLICY = ROOT / "sentinel_pulse" / "protocol" / "decision-policy-semantic-v2.json"


def test_frozen_policy_is_checksum_bound_one_window_and_uses_no_blind_outcome():
    policy, digest = load_decision_policy(POLICY)
    assert len(digest) == 64
    assert policy["same_window_corroboration"]["additional_window_wait"] == 0
    assert "blind" not in json.dumps(policy["development_normal_evidence"]).lower()
    confirmed, mass, fields = corroborate(policy, {"connect": 4, "openat": 99})
    assert confirmed is True
    assert mass == 4
    assert fields == {"connect": 4}


def test_policy_rejects_unknown_security_field(tmp_path):
    policy = json.loads(POLICY.read_text())
    policy["same_window_corroboration"]["security_activity_fields"].append("read")
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    with pytest.raises(ValueError, match="security fields"):
        load_decision_policy(path)


def test_policy_rejects_missing_exact_counts_and_negative_values():
    policy, _ = load_decision_policy(POLICY)
    with pytest.raises(ValueError, match="requires exact"):
        corroborate(policy, None)
    with pytest.raises(ValueError, match="cannot be negative"):
        corroborate(policy, {"connect": -1})


def test_v2_policy_binds_non_negative_per_workload_calibration_margin():
    policy, digest = load_decision_policy(SCORE_POLICY)
    assert len(digest) == 64
    assert policy["score_corroboration"] == {
        "reference": "per_workload_calibration_max",
        "minimum_excess_over_calibration_max": 0.01,
    }


def test_policy_rejects_negative_score_margin(tmp_path):
    policy = json.loads(SCORE_POLICY.read_text())
    policy["score_corroboration"]["minimum_excess_over_calibration_max"] = -0.01
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    with pytest.raises(ValueError, match="score excess"):
        load_decision_policy(path)
