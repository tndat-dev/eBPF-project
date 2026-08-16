import json
from pathlib import Path

import pytest

from sentinel_pulse.decision_policy import (
    corroborate,
    corroboration_details,
    load_decision_policy,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "sentinel_pulse" / "protocol" / "decision-policy-semantic-v1.json"
SCORE_POLICY = ROOT / "sentinel_pulse" / "protocol" / "decision-policy-semantic-v2.json"
ENVELOPE_POLICY = ROOT / "sentinel_pulse" / "protocol" / "decision-policy-semantic-v3.json"


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


def _write_envelope_policy(tmp_path):
    policy = json.loads(SCORE_POLICY.read_text())
    policy["name"] = "test-workload-envelope"
    policy["same_window_corroboration"]["security_activity_fields"] += [
        "socket",
        "openat",
    ]
    policy["same_window_corroboration"]["workload_normal_envelope"] = {
        "signal_groups": [
            {
                "name": "local_socket_beacon",
                "fields": ["socket", "connect"],
                "minimum_excess": 4,
            },
            {
                "name": "credential_open",
                "fields": ["openat"],
                "minimum_excess": 4,
            },
        ],
        "workload_group_maxima": {
            "production/catalog:app": {
                "local_socket_beacon": 8,
                "credential_open": 20,
            }
        },
    }
    path = tmp_path / "envelope.json"
    path.write_text(json.dumps(policy))
    return path


def test_workload_envelope_suppresses_normal_mass_and_detects_excess(tmp_path):
    policy, _ = load_decision_policy(_write_envelope_policy(tmp_path))
    normal = corroboration_details(
        policy,
        {"socket": 1, "connect": 7, "openat": 20},
        "production/catalog:app",
    )
    assert normal["confirmed"] is False
    assert normal["signal_groups"]["local_socket_beacon"]["excess"] == 0

    burst = corroboration_details(
        policy,
        {"socket": 2, "connect": 10, "openat": 20},
        "production/catalog:app",
    )
    assert burst["confirmed"] is True
    assert burst["signal_groups"]["local_socket_beacon"]["triggered"] is True


def test_workload_envelope_fails_closed_for_unknown_workload(tmp_path):
    policy, _ = load_decision_policy(_write_envelope_policy(tmp_path))
    with pytest.raises(ValueError, match="envelope is missing"):
        corroborate(policy, {"connect": 99}, "production/unknown:app")


def test_frozen_v3_envelope_covers_every_candidate_and_suppresses_known_normal():
    policy, digest = load_decision_policy(ENVELOPE_POLICY)
    envelope = policy["same_window_corroboration"]["workload_normal_envelope"]
    assert len(digest) == 64
    assert len(envelope["workload_group_maxima"]) == 20
    redis = corroboration_details(
        policy,
        {"connect": 8},
        "production/aims-redis-sentinel-sentinel:aims-redis-sentinel-sentinel",
    )
    kafka = corroboration_details(
        policy,
        {"clone": 1, "mprotect": 1},
        "production/aims-kafka-entity-operator:topic-operator",
    )
    assert redis["confirmed"] is False
    assert kafka["confirmed"] is False


def test_v3_envelope_keeps_zero_baseline_namespace_primitive_detectable():
    policy, _ = load_decision_policy(ENVELOPE_POLICY)
    decision = corroboration_details(
        policy,
        {"unshare": 1},
        "production/catalog-service:app",
    )
    assert decision["confirmed"] is True
    assert decision["signal_groups"]["namespace_probe"]["triggered"] is True
