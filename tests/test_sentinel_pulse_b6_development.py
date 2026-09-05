import json
from pathlib import Path

from sentinel_pulse.integrity import sha256_file


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "sentinel_pulse" / "protocol" / "development-b6"


def load(name: str) -> dict:
    return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))


def test_b6_normal_replays_remove_identity_bypass_without_attack_outcomes():
    expected = {
        "b6-b5-failure-projection.json": (
            228563,
            "b560838a02c4391a03d486ec15ca48313af8c712a291ee8b5bde1ab0d3eeb487",
        ),
        "b6-b4-canary-projection.json": (
            56491,
            "49d593a8f65367559a44f0f0c01f30cb4b9dfa977267ff7537cce9620bc9de92",
        ),
        "b6-r6-projection.json": (
            874270,
            "14206a006570edaf62611f15806ad6d190ab398e8f90166cc0405d835e959e30",
        ),
    }
    total = 0
    for name, (rows, digest) in expected.items():
        report = load(name)
        assert sha256_file(EVIDENCE / name) == digest
        assert report["normal_only_development_evidence"] is True
        assert report["attack_outcomes_used"] is False
        assert report["automatic_promotion"] is False
        assert report["bypass_groups"] == ["namespace_probe"]
        assert report["bounded_event_time_groups"] == ["namespace_probe"]
        assert report["required_consecutive_windows"] == 2
        assert report["required_consecutive_windows_by_group"] == {
            "local_socket_beacon": 3
        }
        assert report["maximum_gap_seconds"] == 1.25
        assert report["projected_alerts"] == 0
        assert report["scored_rows"] == rows
        total += rows
    assert total == 1159324


def test_b5_failure_audit_preserves_claim_limit_and_alert_mechanism():
    audit = load("b5-formal-failure-audit.json")
    assert audit["candidate_status"] == "rejected_normal_gate"
    assert audit["accuracy_claim_allowed"] is False
    assert audit["blind_attack_opened"] is False
    assert audit["terminal"] == {
        "failed_at": "2026-09-04T09:26:06Z",
        "reason": "normal_alert_observed",
        "total_decision_rows": 230683,
        "scored_decision_rows": 228563,
        "alerts": 1,
        "detector_restarts": 0,
    }
    alert = audit["alert"]
    assert alert["workload_key"] == "production/aims-kafka-dual-role:kafka"
    assert alert["temporal_confirmation_count"] == 1
    assert alert["temporal_confirmation_bypassed"] is True
    assert alert["bounded_event_time_corroborated"] is False
    assert audit["infrastructure_limit"]["source_worker_capture_valid"] is False
    successor = audit["successor_projection"]
    assert successor["attack_outcomes_used"] is False
    assert successor["automatic_promotion"] is False
    assert successor["report_sha256"] == sha256_file(
        EVIDENCE / successor["report"]
    )
