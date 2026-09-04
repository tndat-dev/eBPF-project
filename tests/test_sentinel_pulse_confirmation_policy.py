import json
from pathlib import Path

import pytest

from sentinel_pulse.build_confirmation_policy import build_policy
from sentinel_pulse.build_semantic_policy import write_policy
from sentinel_pulse.decision_policy import load_decision_policy
from sentinel_pulse.integrity import sha256_file


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "sentinel_pulse" / "protocol" / "decision-policy-temporal-b2.json"


def _calibration(path: Path, projected_alerts: int = 0) -> Path:
    base, base_sha256 = load_decision_policy(BASE)
    path.write_text(
        json.dumps(
            {
                "schema": "sentinel-pulse-temporal-confirmation-development-replay-v1",
                "normal_only_development_evidence": True,
                "attack_outcomes_used": False,
                "automatic_promotion": False,
                "projected_alerts": projected_alerts,
                "evidence_checksums_sha256": "c" * 64,
                "decision_policy_sha256": base_sha256,
                "model_manifest_sha256": base["development_normal_evidence"][
                    "model_manifest_sha256"
                ],
                "required_consecutive_windows": 2,
                "required_consecutive_windows_by_group": {
                    "local_socket_beacon": 3
                },
                "maximum_gap_seconds": 1.25,
                "bypass_groups": ["namespace_probe"],
                "bounded_event_time_groups": ["namespace_probe"],
                "maximum_evidence_age_seconds": 1.0,
                "run_id": "normal-primary",
                "scored_rows": 100,
            }
        )
        + "\n"
    )
    return path


def test_builds_checksum_bound_confirmation_policy(tmp_path):
    calibration = _calibration(tmp_path / "calibration.json")
    policy = build_policy(
        BASE,
        calibration,
        "sentinel-pulse-consecutive-confirmation-b3",
        source={
            "source_git_commit": "a" * 40,
            "source_clean": False,
            "source_git_diff_sha256": "b" * 64,
        },
        bounded_join_groups=["namespace_probe"],
    )
    output = tmp_path / "policy.json"
    write_policy(output, policy)
    loaded, digest = load_decision_policy(output)
    assert len(digest) == 64
    assert loaded["temporal_confirmation"] == {
        "mode": "consecutive_same_group",
        "required_consecutive_windows": 2,
        "required_consecutive_windows_by_group": {"local_socket_beacon": 3},
        "maximum_gap_seconds": 1.25,
        "immediate_bypass_signal_groups": ["namespace_probe"],
        "normal_only_calibration": True,
        "consume_on_alert": True,
    }
    assert loaded["development_normal_evidence"][
        "temporal_confirmation_calibration_sha256"
    ] == sha256_file(calibration)
    assert loaded["bounded_event_time_corroboration"][
        "eligible_semantic_signal_groups"
    ] == ["namespace_probe"]


def test_binds_additional_independent_normal_replay(tmp_path):
    calibration = _calibration(tmp_path / "primary.json")
    additional = _calibration(tmp_path / "additional.json")
    extra = json.loads(additional.read_text())
    extra["decision_policy_sha256"] = "d" * 64
    extra["run_id"] = "normal-independent"
    extra["scored_rows"] = 200
    additional.write_text(json.dumps(extra) + "\n")
    policy = build_policy(
        BASE,
        calibration,
        "sentinel-pulse-multi-replay",
        source={
            "source_git_commit": "a" * 40,
            "source_clean": True,
            "source_git_diff_sha256": "b" * 64,
        },
        bounded_join_groups=["namespace_probe"],
        additional_calibration_paths=[additional],
    )
    bound = policy["development_normal_evidence"][
        "additional_temporal_confirmation_calibrations"
    ]
    assert bound == [
        {
            "report_sha256": sha256_file(additional),
            "evidence_checksums_sha256": "c" * 64,
            "decision_policy_sha256": "d" * 64,
            "run_id": "normal-independent",
            "scored_rows": 200,
            "projected_alerts": 0,
        }
    ]


def test_rejects_calibration_with_projected_normal_alert(tmp_path):
    calibration = _calibration(tmp_path / "failed.json", projected_alerts=1)
    with pytest.raises(ValueError, match="compatible normal-only"):
        build_policy(BASE, calibration, "invalid")
