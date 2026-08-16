import json
from pathlib import Path

import pytest

from sentinel_pulse.extend_semantic_envelope import extend_envelope
from sentinel_pulse.integrity import sha256_file


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "sentinel_pulse" / "protocol" / "decision-policy-semantic-v3.json"
MODEL_SHA = "b7e603fdd23bb61b71ba09e171116ac6f05bf74699c2a62e51f5e719d50718cc"
POLICY_SHA = "382e45628544f9a93b0adb11a900b5496fdd82c6fa847913cf29aacbba06d5d1"


def _frozen_failed_evidence(tmp_path: Path, *, blind_started: bool = False):
    evidence = tmp_path / "failed-evidence"
    worker = evidence / "worker1"
    worker.mkdir(parents=True)
    decisions = worker / "decisions.jsonl"
    records = [
        {
            "status": "warming",
            "model_manifest_sha256": MODEL_SHA,
            "decision_policy_sha256": POLICY_SHA,
            "run_id": "failed-normal-test",
            "workload_key": "production/aims-redis:aims-redis",
        },
        {
            "schema": "sentinel-pulse-decision-v1",
            "status": "normal",
            "model_manifest_sha256": MODEL_SHA,
            "decision_policy_sha256": POLICY_SHA,
            "run_id": "failed-normal-test",
            "workload_key": "production/aims-redis:aims-redis",
            "security_activity_fields": {"socket": 3, "connect": 4},
        },
        {
            "schema": "sentinel-pulse-decision-v1",
            "status": "alert",
            "model_manifest_sha256": MODEL_SHA,
            "decision_policy_sha256": POLICY_SHA,
            "run_id": "failed-normal-test",
            "workload_key": "production/aims-redis:aims-redis",
            "security_activity_fields": {
                "setuid": 24,
                "setgid": 24,
                "capset": 3,
                "openat": 23,
            },
        },
    ]
    decisions.write_text("".join(json.dumps(row) + "\n" for row in records))
    summary = evidence / "FAILURE_SUMMARY.json"
    summary.write_text(
        json.dumps(
            {
                "schema": "sentinel-pulse-normal-soak-failure-v3",
                "status": "failed",
                "blind_evaluation_started": blind_started,
                "decision_policy_sha256": POLICY_SHA,
                "model_manifest_sha256": MODEL_SHA,
                "run_id": "failed-normal-test",
                "total_decisions": 3,
                "observed_alerts": 1,
                "workers": {"worker1": {"decision_rows": 3, "alert_rows": 1}},
            }
        )
        + "\n"
    )
    checksums = evidence / "SHA256SUMS"
    checksums.write_text(
        f"{sha256_file(summary)}  ./FAILURE_SUMMARY.json\n"
        f"{sha256_file(decisions)}  ./worker1/decisions.jsonl\n"
    )
    return summary, checksums, decisions


def test_failed_normal_can_extend_a_new_policy_without_blind_outcomes(tmp_path):
    summary, checksums, decisions = _frozen_failed_evidence(tmp_path)
    report = extend_envelope(POLICY, summary, checksums, [decisions])
    redis = report["workload_group_maxima"]["production/aims-redis:aims-redis"]

    assert report["normal_only"] is True
    assert report["blind_outcome_used"] is False
    assert report["rows"] == 3
    assert report["status_counts"] == {"alert": 1, "normal": 1, "warming": 1}
    assert redis["local_socket_beacon"] == 7
    assert redis["identity_transition"] == 51
    assert redis["credential_open"] == 23
    assert report["changed_maxima"]["production/aims-redis:aims-redis"] == {
        "credential_open": {"base_max": 12, "extended_max": 23},
        "identity_transition": {"base_max": 21, "extended_max": 51},
        "local_socket_beacon": {"base_max": 3, "extended_max": 7},
    }


def test_extension_rejects_tampered_evidence(tmp_path):
    summary, checksums, decisions = _frozen_failed_evidence(tmp_path)
    decisions.write_text(decisions.read_text() + "{}\n")
    with pytest.raises(ValueError, match="checksum mismatch"):
        extend_envelope(POLICY, summary, checksums, [decisions])


def test_extension_rejects_any_run_that_started_blind_evaluation(tmp_path):
    summary, checksums, decisions = _frozen_failed_evidence(
        tmp_path, blind_started=True
    )
    with pytest.raises(ValueError, match="blind outcomes"):
        extend_envelope(POLICY, summary, checksums, [decisions])
