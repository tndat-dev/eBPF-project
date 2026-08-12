import hashlib
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service"
sys.path.insert(0, str(SERVICE_ROOT))

from fast_path_normal_evidence_finalizer import (
    EvidenceError, EvidenceNotReady, finalize, write_exclusion_report,
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(tmp_path, *, warning=True, corrupt_inside=False, counter_change=False):
    capture = tmp_path / "capture"
    capture.mkdir()
    split = {
        "release_id": "v8-test",
        "normal": {
            "regimes": ["steady", "burst", "recovery", "toolmix"],
            "runs": [
                {"run_id": f"normal-run-{run:02d}", "role": "independent_evaluation"}
                for run in range(2, 7)
            ],
        },
    }
    release = {"eligible_targets": ["production/api"]}
    split_path, release_path = tmp_path / "split.json", tmp_path / "release.json"
    split_path.write_text(json.dumps(split))
    release_path.write_text(json.dumps(release))
    start = 1_786_453_000.0
    intervals = []
    index = 0
    for run in range(2, 7):
        for regime in split["normal"]["regimes"]:
            phase = f"aims-{regime}-run-{run:02d}"
            phase_start = start + index * 20
            phase_end = phase_start + 10
            directory = capture / phase
            directory.mkdir()
            (directory / "collection_manifest.json").write_text(json.dumps({
                "phase": phase,
                "collection_started_at": f"{__import__('datetime').datetime.fromtimestamp(phase_start, __import__('datetime').timezone.utc).isoformat()}",
                "collection_ended_at": f"{__import__('datetime').datetime.fromtimestamp(phase_end, __import__('datetime').timezone.utc).isoformat()}",
                "actual_duration_seconds": 10,
                "minimum_duration_satisfied": True,
                "sensor_health": {"coverage_healthy": True},
            }))
            intervals.append((phase_start, phase_end))
            index += 1

    detector, fast_path, unit = (
        tmp_path / "detector.py", tmp_path / "fast_path.py", tmp_path / "unit.service"
    )
    detector.write_text("detector")
    fast_path.write_text("fast-path")
    unit.write_text("unit")
    started = "Tue 2026-08-11 06:44:55 UTC"
    contract = {
        "schema": "sentinel-fast-path-normal-contract/v1",
        "release_id": "v8-test", "evidence_class": "retrospective",
        "registration_boundary": {"claim_limit": "retrospective only"},
        "parent_contracts": {
            split_path.name: digest(split_path), release_path.name: digest(release_path),
        },
        "runtime": {
            "detector_source_sha256": digest(detector),
            "fast_path_source_sha256": digest(fast_path),
            "service_unit_sha256": digest(unit),
            "service_name": "sentinel-detector.service",
            "service_started_at": started,
            "maximum_health_gap_seconds": 9,
        },
        "normal_role": "independent_evaluation", "expected_runs": 5,
        "expected_phases": 20,
        "allowed_rules": ["exec_to_privilege_transition", "exec_to_network"],
        "privacy": {"raw_arguments_or_payloads_forbidden": True},
        "automatic_promotion": False,
    }
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(json.dumps(contract))
    metrics = tmp_path / "metrics.jsonl"
    rows = [{"kind": "runtime_health", "ts": start - 1000, "sensor_health": {}}]
    for phase_index, (phase_start, phase_end) in enumerate(intervals):
        for position, timestamp in enumerate((phase_start + 1, phase_end - 1)):
            rows.append({
                "kind": "runtime_health", "ts": timestamp, "reason": "periodic",
                "sensor_health": {
                    "coverage_healthy": True, "expected_tetragon_pods": 2,
                    "active_tetragon_pods": ["a", "b"],
                    "ready_tetragon_pods": ["a", "b"],
                    "queue_size": 0, "queue_capacity": 100,
                    "backpressure_events": 1 if counter_change and phase_index == 0 and position else 0,
                    "coverage_failures": 0, "membership_failures": 0,
                    "stale_streams_removed": 0, "stream_failures": 3,
                },
            })
    if warning:
        rows.append({
            "kind": "early_warning", "ts": intervals[0][0] + 5,
            "pod_key": "production/api-abc", "model_key": "production/api",
            "rule": "exec_to_privilege_transition", "first_syscall": "execve",
            "second_syscall": "unshare", "sequence_seconds": .2,
            "severity": "early-warning", "detection_latency": None,
            "event_to_warning_seconds": .01, "processing_ms": .1,
        })
    rows.sort(key=lambda row: row["ts"])
    with metrics.open("wb") as handle:
        for row in rows:
            handle.write((json.dumps(row) + "\n").encode())
            if corrupt_inside and row["ts"] == intervals[0][0] + 1:
                handle.write(b"\x00\x00broken\n")
    state = {
        "ActiveState": "active", "SubState": "running", "NRestarts": "0",
        "ExecMainStartTimestamp": started, "FragmentPath": str(unit.resolve()),
        "MainPID": "123",
    }
    return {
        "capture": capture, "metrics": metrics, "split": split_path,
        "release": release_path, "contract": contract_path,
        "detector": detector, "fast_path": fast_path, "unit": unit,
        "output": tmp_path / "output", "state": state,
        "now": intervals[-1][1] + 31,
    }


def run(paths):
    return finalize(
        paths["capture"], paths["metrics"], paths["split"], paths["release"],
        paths["contract"], paths["detector"], paths["fast_path"], paths["unit"],
        paths["output"], state=paths["state"], now=paths["now"],
    )


def test_finalizer_maps_live_warning_and_publishes_hash_checked_bundle(tmp_path):
    paths = fixture(tmp_path)
    report = run(paths)
    assert report["valid"]
    assert report["phase_count"] == 20
    assert report["independent_runs"] == 5
    assert report["early_warning_count"] == 1
    assert sum(row["early_warning_count"] for row in report["phase_outcomes"]) == 1
    assert run(paths)["metrics_source"]["sha256"] == digest(paths["metrics"])
    report_path = paths["output"] / "fast-path-normal-evidence.report.json"
    report_path.write_text("tampered")
    with pytest.raises(EvidenceError, match="checksum mismatch"):
        run(paths)


def test_finalizer_waits_for_all_twenty_phases(tmp_path):
    paths = fixture(tmp_path)
    phase = paths["capture"] / "aims-toolmix-run-06" / "collection_manifest.json"
    phase.unlink()
    with pytest.raises(EvidenceNotReady, match="incomplete"):
        run(paths)


def test_finalizer_rejects_metrics_corruption_inside_phase(tmp_path):
    paths = fixture(tmp_path, corrupt_inside=True)
    with pytest.raises(EvidenceError, match="corruption may overlap"):
        run(paths)


def test_finalizer_rejects_sensor_counter_change(tmp_path):
    paths = fixture(tmp_path, counter_change=True)
    with pytest.raises(EvidenceError, match="backpressure_events changed"):
        run(paths)


def test_exclusion_report_preserves_failed_track_without_claim(tmp_path):
    paths = fixture(tmp_path, counter_change=True)
    exclusion = tmp_path / "fast-path.exclusion.json"
    error = EvidenceError("stream_failures changed during aims-burst-run-02")
    report = write_exclusion_report(
        exclusion, error, contract_path=paths["contract"],
        metrics_path=paths["metrics"], split_path=paths["split"],
        release_path=paths["release"],
    )
    assert report["status"] == "excluded"
    assert report["valid"] is False
    assert report["claim_available"] is False
    assert report["automatic_promotion"] is False
    assert report["reason"] == str(error)
    assert report["provenance_sha256"]["metrics_snapshot"] == digest(paths["metrics"])
    assert write_exclusion_report(
        exclusion, error, contract_path=paths["contract"],
        metrics_path=paths["metrics"], split_path=paths["split"],
        release_path=paths["release"],
    ) == report


def test_exclusion_report_rejects_reason_drift(tmp_path):
    paths = fixture(tmp_path)
    exclusion = tmp_path / "fast-path.exclusion.json"
    arguments = {
        "contract_path": paths["contract"], "metrics_path": paths["metrics"],
        "split_path": paths["split"], "release_path": paths["release"],
    }
    write_exclusion_report(exclusion, EvidenceError("first"), **arguments)
    with pytest.raises(EvidenceError, match="exclusion report drift"):
        write_exclusion_report(exclusion, EvidenceError("second"), **arguments)
