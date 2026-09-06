import json
from pathlib import Path

from sentinel_pulse.integrity import sha256_file


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "sentinel_pulse" / "protocol" / "development-b7"


def test_b7_normal_only_replays_suppress_predecessor_alerts_without_blind_data():
    expected = {
        "b7-b4-canary-projection.json": (
            56491,
            "cdb29eec7eae57f078260cbc6ff85fbf3d52a3da3cae218e4eab7cd2d863de17",
        ),
        "b7-b5-failure-projection.json": (
            228563,
            "96ee41fd0d4340344828ad45b1ca7a676a5aaabcbb743cd8248483a7a376f2c5",
        ),
        "b7-b6-failure-projection.json": (
            6191601,
            "775eda2f844229e96bdd55ad3b2c60f38f5fc47b1d2910af4faf3ceb67375df1",
        ),
        "b7-r6-projection.json": (
            874270,
            "f448312b59848a2f95c6113e361dd2db922634c28be9505c6df9459940d77fb9",
        ),
    }
    total = 0
    for name, (scored_rows, digest) in expected.items():
        path = EVIDENCE / name
        report = json.loads(path.read_text(encoding="utf-8"))
        assert sha256_file(path) == digest
        assert report["normal_only_development_evidence"] is True
        assert report["attack_outcomes_used"] is False
        assert report["automatic_promotion"] is False
        assert report["required_consecutive_windows"] == 2
        assert report["required_consecutive_windows_by_group"] == {
            "credential_open": 3,
            "local_socket_beacon": 3,
        }
        assert report["bypass_groups"] == ["namespace_probe"]
        assert report["bounded_event_time_groups"] == ["namespace_probe"]
        assert report["maximum_gap_seconds"] == 1.25
        assert report["projected_alerts"] == 0
        assert report["original_alerts"] == 1
        assert report["original_alerts_suppressed"] == 1
        assert report["scored_rows"] == scored_rows
        total += scored_rows

    assert total == 7350925


def test_b7_b6_replay_is_bound_to_the_terminal_b6_identity():
    report = json.loads(
        (EVIDENCE / "b7-b6-failure-projection.json").read_text(encoding="utf-8")
    )
    assert report["run_id"] == "sentinel-pulse-formal-normal-b6-r1-20260905T032856Z"
    assert report["model_manifest_sha256"] == (
        "2e37ffd1ef4476b09e123315b467e47814613b9ff22dfd0b4e28fbb375952a81"
    )
    assert report["decision_policy_sha256"] == (
        "53f3346fc23a75a8435017d1fccf4f8e3a332e540f97a00026ce7c8110ded51a"
    )
    assert report["evidence_checksums_sha256"] == (
        "d6010e2a833c88648aacc48c2b82d81f74b3e152a239df71aeb12c113df493c9"
    )
    assert report["status_counts"]["alert"] == 1
    assert report["status_counts"]["warming"] == 56266
    assert report["projected_status_counts"].get("alert", 0) == 0
    assert report["latency_cost_contract"] == {
        "additional_windows_for_non_bypass_groups": 1,
        "maximum_additional_windows_for_overridden_groups": 2,
        "attack_latency_not_estimated_from_normal_evidence": True,
        "blind_live_latency_gate_still_required": True,
    }
