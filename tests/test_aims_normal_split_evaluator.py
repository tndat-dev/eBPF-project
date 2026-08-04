import hashlib
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("sklearn")

SERVICE_ROOT = Path(__file__).resolve().parents[1] / "ml-service"
if not SERVICE_ROOT.is_dir():
    SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from evaluate_aims_normal_split import (candidate_hashes,
                                        resumable_phase_reports,
                                        validate_blind_prerequisite,
                                        write_report)


def test_candidate_hashes_are_name_sorted_and_content_bound(tmp_path):
    (tmp_path / "z").write_bytes(b"last")
    (tmp_path / "a").write_bytes(b"first")
    result = candidate_hashes(tmp_path)
    assert list(result) == ["a", "z"]
    assert result["a"] == hashlib.sha256(b"first").hexdigest()


def test_blind_test_requires_passed_validation_for_exact_candidate(tmp_path):
    report = tmp_path / "validation.json"
    hashes = {"model": "abc"}
    report.write_text(json.dumps({
        "role": "independent_validation", "passed": True,
        "candidate_sha256": hashes,
    }))
    report_doc = json.loads(report.read_text())
    report_doc["initial_calibration_sha256"] = "c" * 64
    report.write_text(json.dumps(report_doc))
    result = validate_blind_prerequisite(report, hashes, "c" * 64)
    assert result["sha256"] == hashlib.sha256(report.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="different candidate"):
        validate_blind_prerequisite(report, {"model": "changed"}, "c" * 64)
    with pytest.raises(ValueError, match="different calibration"):
        validate_blind_prerequisite(report, hashes, "d" * 64)


def test_blind_test_rejects_failed_or_missing_validation(tmp_path):
    report = tmp_path / "validation.json"
    report.write_text(json.dumps({
        "role": "independent_validation", "passed": False,
        "candidate_sha256": {},
    }))
    with pytest.raises(ValueError, match="not a passed"):
        validate_blind_prerequisite(report, {}, "c" * 64)
    with pytest.raises(ValueError, match="requires"):
        validate_blind_prerequisite(None, {}, "c" * 64)


def test_evaluation_checkpoint_is_atomic_and_identity_bound(tmp_path):
    output = tmp_path / "evaluation.json"
    identity = {
        "status": "evaluating",
        "role": "independent_validation",
        "evidence_root": "/evidence",
        "candidate_sha256": {"model": "a"},
        "initial_calibration_sha256": "b",
        "split_contract_sha256": "c",
        "release_contract_sha256": "d",
        "phases": [{"phase": "steady-02", "passed": True}],
    }
    write_report(output, identity)
    assert not output.with_suffix(".json.tmp").exists()
    assert resumable_phase_reports(
        output, identity, ["steady-02", "burst-02"],
    ) == identity["phases"]

    changed = dict(identity, initial_calibration_sha256="changed")
    with pytest.raises(ValueError, match="identity mismatch"):
        resumable_phase_reports(output, changed, ["steady-02"])


def test_evaluation_checkpoint_rejects_non_prefix_phases(tmp_path):
    output = tmp_path / "evaluation.json"
    report = {
        "status": "evaluating", "role": "independent_validation",
        "evidence_root": "/evidence", "candidate_sha256": {},
        "initial_calibration_sha256": "b",
        "split_contract_sha256": "c", "release_contract_sha256": "d",
        "phases": [{"phase": "burst-02"}],
    }
    write_report(output, report)
    with pytest.raises(ValueError, match="not a phase prefix"):
        resumable_phase_reports(output, report, ["steady-02", "burst-02"])
