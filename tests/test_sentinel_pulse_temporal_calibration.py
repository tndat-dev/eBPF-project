import json
import hashlib

import pytest

from sentinel_pulse.calibrate_temporal_join import calibrate


def _record(window_end, *, model=False, semantic=False, status="normal"):
    return {
        "schema": "sentinel-pulse-decision-v1",
        "status": status,
        "model_manifest_sha256": "a" * 64,
        "decision_policy_sha256": "b" * 64,
        "run_id": "normal-run",
        "workload_key": "production/catalog:app",
        "node_name": "worker",
        "pod_uid": "pod",
        "container_name": "app",
        "cgroup_id": "7",
        "window_end": window_end,
        "raw_model_anomalous": model,
        "score_corroborated": model,
        "semantic_corroborated": semantic,
        "semantic_signal_groups": {
            "common": {"triggered": semantic},
            "rare": {"triggered": False},
        },
    }


def test_normal_replay_projects_bounded_join_and_consumes(tmp_path):
    path = tmp_path / "normal.jsonl"
    records = [
        _record(1.0, status="warming"),
        _record(2.0, model=True, status="suppressed"),
        _record(2.5, semantic=True),
        _record(3.0, semantic=True),
    ]
    # Frozen A2 warming records predate full node/pod/container provenance;
    # they are unscored and must not weaken identity gates on scored rows.
    for field in ("node_name", "pod_uid", "container_name"):
        records[0].pop(field)
    path.write_text("".join(json.dumps(item) + "\n" for item in records))
    report = calibrate(
        [path], [0.25, 1.0], maximum_contiguous_gap_seconds=1.5,
        expected_model_sha256="a" * 64,
        expected_policy_sha256="b" * 64,
    )
    assert report["normal_only"] is True
    assert report["baseline_alerts"] == 0
    assert report["horizons"][0]["projected_alerts"] == 0
    assert report["horizons"][1]["projected_alerts"] == 1


def test_risk_tiered_replay_excludes_cross_window_common_group(tmp_path):
    path = tmp_path / "normal.jsonl"
    records = [
        _record(1.0, semantic=True, status="suppressed"),
        _record(1.5, model=True, status="alert"),
    ]
    path.write_text("".join(json.dumps(item) + "\n" for item in records))
    report = calibrate(
        [path], [1.0], maximum_contiguous_gap_seconds=1.5,
        eligible_semantic_signal_groups=["rare"],
    )
    assert report["baseline_alerts"] == 1
    assert report["eligible_semantic_signal_groups"] == ["rare"]
    assert report["horizons"][0]["projected_alerts"] == 0


def test_normal_replay_can_bind_frozen_evidence_checksums(tmp_path):
    root = tmp_path / "evidence"
    decision = root / "nodes" / "worker" / "decisions.jsonl"
    decision.parent.mkdir(parents=True)
    decision.write_text(json.dumps(_record(1.0)) + "\n")
    digest = hashlib.sha256(decision.read_bytes()).hexdigest()
    checksums = root / "FINAL_SHA256SUMS"
    checksums.write_text(f"{digest}  nodes/worker/decisions.jsonl\n")
    report = calibrate(
        [decision], [1.0], maximum_contiguous_gap_seconds=1.5,
        evidence_checksums_path=checksums,
    )
    assert report["evidence_checksums_sha256"] == hashlib.sha256(
        checksums.read_bytes()
    ).hexdigest()

    decision.write_text(json.dumps(_record(2.0)) + "\n")
    with pytest.raises(ValueError, match="checksum"):
        calibrate(
            [decision], [1.0], maximum_contiguous_gap_seconds=1.5,
            evidence_checksums_path=checksums,
        )


def test_normal_replay_rejects_attack_attribution_and_non_monotonic_input(tmp_path):
    path = tmp_path / "invalid.jsonl"
    attack = _record(1.0)
    attack["injection_id"] = "attack-1"
    path.write_text(json.dumps(attack) + "\n")
    with pytest.raises(ValueError, match="attack-attributed"):
        calibrate([path], [1.0], maximum_contiguous_gap_seconds=1.5)

    path.write_text(json.dumps(_record(2.0)) + "\n" + json.dumps(_record(1.0)) + "\n")
    with pytest.raises(ValueError, match="non-monotonic"):
        calibrate([path], [1.0], maximum_contiguous_gap_seconds=1.5)
