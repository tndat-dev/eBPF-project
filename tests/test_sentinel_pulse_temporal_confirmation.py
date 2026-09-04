import json
import hashlib
from pathlib import Path

import pytest

from sentinel_pulse.evaluate_temporal_confirmation import evaluate


def _record(end, status="alert", group="process_fanout"):
    return {
        "schema": "sentinel-pulse-decision-v1",
        "status": status,
        "workload_key": "production/catalog:app",
        "cgroup_id": "7",
        "window_end": float(end),
        "raw_model_anomalous": True,
        "semantic_corroborated": True,
        "score_corroborated": True,
        "semantic_signal_groups": {
            group: {"triggered": True},
            "namespace_probe": {"triggered": group == "namespace_probe"},
        },
    }


def _write(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in records))


def test_isolated_noisy_group_is_suppressed(tmp_path):
    path = tmp_path / "decisions.jsonl"
    _write(path, [_record(1.0)])
    report = evaluate([path])
    assert report["original_alerts"] == 1
    assert report["projected_alerts"] == 0
    assert report["original_alerts_suppressed"] == 1


def test_same_group_in_two_consecutive_windows_confirms(tmp_path):
    path = tmp_path / "decisions.jsonl"
    _write(path, [_record(1.0), _record(2.0)])
    report = evaluate([path])
    assert report["projected_alerts"] == 1


def test_three_window_group_override_suppresses_two_window_burst(tmp_path):
    path = tmp_path / "decisions.jsonl"
    _write(
        path,
        [
            _record(1.0, group="local_socket_beacon"),
            _record(1.5, group="local_socket_beacon"),
        ],
    )
    report = evaluate(
        [path],
        required_consecutive_windows_by_group={"local_socket_beacon": 3},
    )
    assert report["projected_alerts"] == 0
    assert report["required_consecutive_windows_by_group"] == {
        "local_socket_beacon": 3
    }


def test_rotating_overlap_does_not_fake_a_same_group_streak(tmp_path):
    path = tmp_path / "decisions.jsonl"
    first = _record(1.0, group="a")
    first["semantic_signal_groups"]["b"] = {"triggered": True}
    second = _record(1.5, group="b")
    second["semantic_signal_groups"]["c"] = {"triggered": True}
    third = _record(2.0, group="c")
    third["semantic_signal_groups"]["d"] = {"triggered": True}
    _write(path, [first, second, third])
    report = evaluate([path], required_consecutive_windows=3)
    assert report["projected_alerts"] == 0


def test_confirmation_evidence_is_consumed_after_alert(tmp_path):
    path = tmp_path / "decisions.jsonl"
    _write(path, [_record(1.0), _record(1.5), _record(2.0)])
    report = evaluate([path])
    assert report["projected_alerts"] == 1


def test_different_group_or_large_gap_does_not_confirm(tmp_path):
    path = tmp_path / "decisions.jsonl"
    _write(
        path,
        [
            _record(1.0, group="process_fanout"),
            _record(2.0, group="credential_open"),
            _record(5.0, group="credential_open"),
        ],
    )
    report = evaluate([path])
    assert report["projected_alerts"] == 0


def test_namespace_primitive_bypasses_temporal_wait(tmp_path):
    path = tmp_path / "decisions.jsonl"
    _write(path, [_record(1.0, group="namespace_probe")])
    report = evaluate([path])
    assert report["projected_alerts"] == 1


def test_bounded_join_reproduces_cross_window_identity_alert(tmp_path):
    path = tmp_path / "decisions.jsonl"
    semantic = _record(1.0, status="suppressed", group="identity_transition")
    semantic["score_corroborated"] = False
    model = _record(1.5, status="alert", group="identity_transition")
    model["semantic_corroborated"] = False
    model["semantic_signal_groups"]["identity_transition"]["triggered"] = False
    _write(path, [semantic, model])
    report = evaluate(
        [path], bounded_join_groups=frozenset({"identity_transition"})
    )
    assert report["projected_alerts"] == 1
    assert report["bounded_event_time_groups"] == ["identity_transition"]


def test_bounded_join_group_restriction_suppresses_cross_window_identity(tmp_path):
    path = tmp_path / "decisions.jsonl"
    semantic = _record(1.0, status="suppressed", group="identity_transition")
    semantic["score_corroborated"] = False
    model = _record(1.5, status="alert", group="identity_transition")
    model["semantic_corroborated"] = False
    model["semantic_signal_groups"]["identity_transition"]["triggered"] = False
    _write(path, [semantic, model])
    report = evaluate([path], bounded_join_groups=frozenset({"namespace_probe"}))
    assert report["projected_alerts"] == 0


def test_soak_marker_excludes_early_rows_and_binds_identity(tmp_path):
    path = tmp_path / "decisions.jsonl"
    rows = [_record(99.0), _record(100.0), _record(101.0)]
    for row in rows:
        row.update(
            {
                "run_id": "soak-test",
                "model_manifest_sha256": "a" * 64,
                "decision_policy_sha256": "b" * 64,
            }
        )
    _write(path, rows)
    marker = tmp_path / "SOAK_START.json"
    marker.write_text(
        json.dumps(
            {
                "schema": "sentinel-pulse-semantic-soak-start-v4",
                "blind_evaluation_started": False,
                "started_not_before": "1970-01-01T00:01:40+00:00",
                "run_id": "soak-test",
                "model_manifest_sha256": "a" * 64,
                "decision_policy_sha256": "b" * 64,
            }
        )
    )
    report = evaluate([path], soak_marker_path=marker)
    assert report["excluded_scored_windows_before_marker"] == 1
    assert report["scored_rows"] == 2
    assert report["soak_marker_identity_gate"] is True


def test_frozen_v4_incident_alerts_are_isolated_candidates():
    root = Path(__file__).resolve().parents[1]
    path = (
        root
        / "validation-evidence"
        / "sentinel-pulse-campaign"
        / "sentinel-pulse-normal-20260814T075831Z"
        / "semantic-envelope-soak-d1"
        / "analysis"
        / "incident-decisions.jsonl"
    )
    report = evaluate([path])
    assert report["original_alerts"] == 2
    assert report["projected_alerts"] == 0
    assert report["attack_outcomes_used"] is False


def test_confirmation_replay_binds_checksum_and_candidate_identity(tmp_path):
    root = tmp_path / "evidence"
    path = root / "nodes" / "worker-a" / "decisions.jsonl"
    path.parent.mkdir(parents=True)
    record = _record(1.0)
    record.update(
        {
            "model_manifest_sha256": "a" * 64,
            "decision_policy_sha256": "b" * 64,
            "run_id": "normal-b2",
            "node_name": "worker-a",
            "pod_uid": "pod-a",
            "container_name": "app",
        }
    )
    _write(path, [record])
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    checksums = root / "FAILED_FINAL_SHA256SUMS"
    checksums.write_text(f"{digest}  nodes/worker-a/decisions.jsonl\n")
    report = evaluate(
        [path],
        maximum_gap_seconds=1.25,
        evidence_checksums_path=checksums,
        expected_model_sha256="a" * 64,
        expected_policy_sha256="b" * 64,
    )
    assert report["model_manifest_sha256"] == "a" * 64
    assert report["decision_policy_sha256"] == "b" * 64
    assert report["run_id"] == "normal-b2"
    assert report["evidence_checksums_sha256"] == hashlib.sha256(
        checksums.read_bytes()
    ).hexdigest()

    path.write_text(json.dumps({**record, "window_end": 2.0}) + "\n")
    with pytest.raises(ValueError, match="checksum"):
        evaluate(
            [path],
            evidence_checksums_path=checksums,
            expected_model_sha256="a" * 64,
            expected_policy_sha256="b" * 64,
        )
