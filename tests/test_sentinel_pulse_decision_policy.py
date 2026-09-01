import json
from pathlib import Path

import pytest

from sentinel_pulse.decision_policy import (
    corroborate,
    corroboration_details,
    load_decision_policy,
)
from sentinel_pulse.build_semantic_policy import write_policy


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "sentinel_pulse" / "protocol" / "decision-policy-semantic-v1.json"
SCORE_POLICY = ROOT / "sentinel_pulse" / "protocol" / "decision-policy-semantic-v2.json"
ENVELOPE_POLICY = ROOT / "sentinel_pulse" / "protocol" / "decision-policy-semantic-v3.json"
EXTENDED_ENVELOPE_POLICY = (
    ROOT / "sentinel_pulse" / "protocol" / "decision-policy-semantic-v4.json"
)
FAILED_V3_ALERTS = ROOT / "tests" / "fixtures" / "sentinel_pulse_v3_normal_alerts.json"


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


def test_v4_envelope_suppresses_every_frozen_v3_normal_alert():
    policy, digest = load_decision_policy(EXTENDED_ENVELOPE_POLICY)
    fixture = json.loads(FAILED_V3_ALERTS.read_text())
    assert fixture["schema"] == "sentinel-pulse-v3-normal-alert-fixture-v1"
    assert fixture["source_run_id"] == "semantic-envelope-soak-c1"
    assert fixture["source_alert_sha256"] == {
        "worker1.jsonl": "94127408f6def61f776039a77b6fdd86c85b8bb48cc5a1da69bfb00b7e07a5de",
        "worker3.jsonl": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "worker4.jsonl": "7809ced229536d21fe9adb5d0f4bf30993d9636f25339f3e0439f10d37440ecf",
    }
    for record in fixture["records"]:
        result = corroboration_details(
            policy,
            record["security_activity_fields"],
            record["workload_key"],
        )
        assert result["confirmed"] is False
    assert len(digest) == 64
    assert len(fixture["records"]) == 8


def test_v4_envelope_preserves_single_namespace_primitive_detection():
    policy, _ = load_decision_policy(EXTENDED_ENVELOPE_POLICY)
    decision = corroboration_details(
        policy,
        {"mount": 1},
        "production/aims-minio-pool-0:minio",
    )
    assert decision["confirmed"] is True
    assert decision["signal_groups"]["namespace_probe"]["triggered"] is True
    assert policy["development_normal_evidence"][
        "semantic_envelope_extension_v4_sha256"
    ] == "80d8a008b15bbb7b63d33452443ae50a5b676085e791c7d75e3e99b4d7fa619c"


def test_v2_policy_uses_direct_normal_evidence_and_is_read_only(tmp_path):
    base = json.loads(EXTENDED_ENVELOPE_POLICY.read_text())
    policy = {
        **base,
        "schema": "sentinel-pulse-decision-policy-v2",
        "evidence_class": "nonformal_runtime_compatibility_pilot",
        "blind_outcome_used": False,
        "automatic_promotion": False,
        "source_git_commit": "a" * 40,
        "source_clean": False,
        "source_git_diff_sha256": "b" * 64,
        "development_normal_evidence": {
            "dataset_sha256": "1" * 64,
            "dataset_manifest_sha256": "2" * 64,
            "semantic_envelope_calibration_sha256": "3" * 64,
            "model_manifest_sha256": "4" * 64,
            "training_contract_sha256": "5" * 64,
            "base_policy_sha256": "6" * 64,
        },
    }
    path = tmp_path / "policy-v2.json"
    write_policy(path, policy)
    loaded, digest = load_decision_policy(path)
    assert loaded["blind_outcome_used"] is False
    assert len(digest) == 64
    assert path.stat().st_mode & 0o222 == 0


def test_v2_policy_rejects_missing_direct_evidence(tmp_path):
    base = json.loads(EXTENDED_ENVELOPE_POLICY.read_text())
    base.update({
        "schema": "sentinel-pulse-decision-policy-v2",
        "evidence_class": "pilot",
        "blind_outcome_used": False,
        "automatic_promotion": False,
        "source_git_commit": "a" * 40,
        "source_git_diff_sha256": "b" * 64,
        "development_normal_evidence": {},
    })
    path = tmp_path / "invalid-v2.json"
    path.write_text(json.dumps(base))
    with pytest.raises(ValueError, match="development evidence"):
        load_decision_policy(path)


def test_v3_policy_requires_normal_calibrated_bounded_join(tmp_path):
    base = json.loads(EXTENDED_ENVELOPE_POLICY.read_text())
    base.update({
        "schema": "sentinel-pulse-decision-policy-v3",
        "evidence_class": "normal_only_bounded_join_candidate",
        "blind_outcome_used": False,
        "automatic_promotion": False,
        "source_git_commit": "a" * 40,
        "source_clean": False,
        "source_git_diff_sha256": "b" * 64,
        "bounded_event_time_corroboration": {
            "mode": "bounded_model_semantic_join",
            "maximum_evidence_age_seconds": 1.0,
            "requires_raw_model_anomaly": True,
            "requires_score_corroboration": True,
            "requires_semantic_corroboration": True,
            "consume_on_alert": True,
            "normal_only_calibration": True,
        },
        "development_normal_evidence": {
            "dataset_sha256": "1" * 64,
            "dataset_manifest_sha256": "2" * 64,
            "semantic_envelope_calibration_sha256": "3" * 64,
            "model_manifest_sha256": "4" * 64,
            "training_contract_sha256": "5" * 64,
            "base_policy_sha256": "6" * 64,
            "temporal_calibration_sha256": "7" * 64,
        },
    })
    path = tmp_path / "policy-v3.json"
    path.write_text(json.dumps(base))
    policy, digest = load_decision_policy(path)
    assert policy["bounded_event_time_corroboration"][
        "maximum_evidence_age_seconds"
    ] == 1.0
    assert len(digest) == 64

    base["bounded_event_time_corroboration"][
        "maximum_evidence_age_seconds"
    ] = 2.1
    path.write_text(json.dumps(base))
    with pytest.raises(ValueError, match="bounded event-time"):
        load_decision_policy(path)


def test_b2_policy_limits_cross_window_join_to_rare_groups():
    policy, digest = load_decision_policy(
        ROOT / "sentinel_pulse" / "protocol" / "decision-policy-temporal-b2.json"
    )
    assert len(digest) == 64
    assert policy["bounded_event_time_corroboration"][
        "eligible_semantic_signal_groups"
    ] == ["identity_transition", "namespace_probe"]


def test_b3_policy_requires_persistence_only_for_common_groups():
    policy, digest = load_decision_policy(
        ROOT / "sentinel_pulse" / "protocol" / "decision-policy-temporal-b3.json"
    )
    confirmation = policy["temporal_confirmation"]
    assert len(digest) == 64
    assert confirmation["required_consecutive_windows"] == 2
    assert confirmation["maximum_gap_seconds"] == 1.25
    assert confirmation["immediate_bypass_signal_groups"] == [
        "identity_transition",
        "namespace_probe",
    ]
    assert policy["blind_outcome_used"] is False
