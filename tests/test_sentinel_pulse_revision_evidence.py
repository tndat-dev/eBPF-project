import hashlib
import json

import pytest

from sentinel_pulse.revision_evidence import validate_completed_observer


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_index(root, name, filenames):
    (root / name).write_text("".join(
        f"{sha256(root / filename)}  /immutable/evidence/{filename}\n"
        for filename in filenames
    ))


def observer_fixture(tmp_path):
    fingerprint = {
        "schema": "sentinel-pulse-workload-fingerprint-v1",
        "sha256": "a" * 64,
        "workloads": {"production/catalog": ["revision-a"]},
    }
    for name in ("APPROVED_FINGERPRINT.json", "final-fingerprint.json"):
        (tmp_path / name).write_text(json.dumps(fingerprint, sort_keys=True) + "\n")
    (tmp_path / "START").write_text("started_at=2026-09-27T00:00:00Z\n")
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "observer.sh").write_text("#!/bin/sh\n")
    (tmp_path / "SOURCE_SHA256SUMS").write_text(
        f"{sha256(runtime / 'observer.sh')}  /immutable/evidence/runtime/observer.sh\n"
    )
    (tmp_path / "OBSERVATIONS.log").write_text("stable\n")
    (tmp_path / "COMPLETE").write_text("completed_at=2026-09-28T00:00:00Z\n")
    write_index(tmp_path, "START_SHA256SUMS", (
        "START", "APPROVED_FINGERPRINT.json", "SOURCE_SHA256SUMS"
    ))
    write_index(tmp_path, "FINAL_SHA256SUMS", (
        "APPROVED_FINGERPRINT.json", "final-fingerprint.json", "OBSERVATIONS.log"
    ))
    return fingerprint


def test_completed_observer_and_live_fingerprint_are_accepted(tmp_path):
    fingerprint = observer_fixture(tmp_path)
    current = tmp_path / "live.json"
    current.write_text(json.dumps(fingerprint, indent=2) + "\n")
    report = validate_completed_observer(tmp_path, current)
    assert report["approved_workload_fingerprint_sha256"] == "a" * 64
    assert report["workload_count"] == 1
    assert report["live_fingerprint_verified"] is True


def test_active_or_incomplete_observer_is_rejected(tmp_path):
    observer_fixture(tmp_path)
    (tmp_path / "ACTIVE").touch()
    with pytest.raises(ValueError, match="still active"):
        validate_completed_observer(tmp_path)


def test_checksum_drift_is_rejected(tmp_path):
    observer_fixture(tmp_path)
    (tmp_path / "OBSERVATIONS.log").write_text("tampered\n")
    with pytest.raises(ValueError, match="checksum mismatch"):
        validate_completed_observer(tmp_path)


def test_live_revision_drift_is_rejected(tmp_path):
    fingerprint = observer_fixture(tmp_path)
    current = tmp_path / "live.json"
    fingerprint["sha256"] = "b" * 64
    fingerprint["workloads"]["production/catalog"] = ["revision-b"]
    current.write_text(json.dumps(fingerprint) + "\n")
    with pytest.raises(ValueError, match="live workload fingerprint"):
        validate_completed_observer(tmp_path, current)
