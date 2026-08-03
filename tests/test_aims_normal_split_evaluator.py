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
                                        validate_blind_prerequisite)


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
