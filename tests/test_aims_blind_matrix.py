import hashlib
import json
import stat
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

from run_aims_blind_matrix import (run_trial, resumable_trials, validated_trials,
                                   validate_normal_prerequisite)


def test_blind_attack_prerequisite_binds_candidate_calibration_and_split(tmp_path):
    path = tmp_path / "blind-normal.json"
    path.write_text(json.dumps({
        "role": "blind_normal_test", "status": "complete", "passed": True,
        "candidate_sha256": {"model": "a"},
        "initial_calibration_sha256": "b" * 64,
        "split_contract_sha256": "c" * 64,
    }))
    result = validate_normal_prerequisite(
        path, {"model": "a"}, "b" * 64, "c" * 64
    )
    assert result["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="different calibration"):
        validate_normal_prerequisite(
            path, {"model": "a"}, "d" * 64, "c" * 64
        )


def test_resume_keeps_detection_miss_and_quarantines_incomplete_trial(tmp_path):
    good_dir = tmp_path / "api-trial-01" / "scenario"
    bad_dir = tmp_path / "api-trial-02" / "scenario"
    miss_dir = tmp_path / "api-trial-03" / "scenario"
    good_dir.mkdir(parents=True)
    bad_dir.mkdir(parents=True)
    miss_dir.mkdir(parents=True)
    good = good_dir / "report.json"
    bad = bad_dir / "report.json"
    miss = miss_dir / "report.json"
    good.write_text(json.dumps({
        "all_passed": True, "detected": 1, "total": 1,
        "scenarios": {"attack": {"detected": True}},
    }))
    bad.write_text("{}")
    miss.write_text(json.dumps({
        "all_passed": False, "detected": 0, "total": 1,
        "scenarios": {"attack": {"detected": False}},
    }))
    aggregate = {"trials": [
        {"target": "production/api", "trial": 1, "exit_code": 0,
         "all_passed": True, "detected": 1, "total": 1,
         "report_path": str(good),
         "report_sha256": hashlib.sha256(good.read_bytes()).hexdigest()},
        {"target": "production/api", "trial": 2, "exit_code": 8,
         "all_passed": False, "detected": 0, "total": 1,
         "report_path": str(bad),
         "report_sha256": hashlib.sha256(bad.read_bytes()).hexdigest()},
        {"target": "production/api", "trial": 3, "exit_code": 4,
         "all_passed": False, "detected": 0, "total": 1,
         "report_path": str(miss),
         "report_sha256": hashlib.sha256(miss.read_bytes()).hexdigest()},
    ]}
    retained, completed = resumable_trials(tmp_path, aggregate)
    assert len(retained) == 2
    assert completed == {("production/api", 1), ("production/api", 3)}
    assert good.is_file()
    assert miss.is_file()
    assert not bad_dir.parent.exists()
    assert list((tmp_path / "rejected").glob("api-trial-02-*"))


def test_validation_is_read_only_for_completed_matrix(tmp_path):
    invalid_dir = tmp_path / "api-trial-02" / "scenario"
    invalid_dir.mkdir(parents=True)
    report = invalid_dir / "report.json"
    report.write_text("{}")
    aggregate = {"trials": [{
        "target": "production/api", "trial": 2, "exit_code": 8,
        "all_passed": False, "detected": 0, "total": 1,
        "report_path": str(report),
        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
    }]}
    assert validated_trials(tmp_path, aggregate) == ([], set())
    assert invalid_dir.is_dir()
    assert not (tmp_path / "rejected").exists()


def test_blind_runner_and_unit_have_no_promotion_path():
    root = Path(__file__).resolve().parents[1]
    service_root = root / "ml-service" if (root / "ml-service").is_dir() else root
    wrapper_path = service_root / "run_aims_blind_attack.sh"
    wrapper = wrapper_path.read_text().lower()
    assert wrapper_path.stat().st_mode & stat.S_IXUSR
    assert "run_aims_blind_matrix.py" in wrapper
    assert "promote_candidate" not in wrapper
    assert "aims-candidate-fit-v1.service" not in wrapper
    assert 'basename "$aims_candidate"' in wrapper
    unit_path = root / "sentinel/systemd/aims-blind-attack.service"
    if unit_path.is_file():
        unit = unit_path.read_text()
        assert "NoNewPrivileges=true" in unit
        assert "TimeoutStartSec=12h" in unit


def test_blind_workload_trial_timeout_is_a_resumable_failure(monkeypatch):
    command = ["runner", "--trial"]

    def timeout(*_args, **_kwargs):
        raise __import__("subprocess").TimeoutExpired(command, 1800)

    monkeypatch.setattr("run_aims_blind_matrix.subprocess.run", timeout)
    result, timed_out = run_trial(command)
    assert timed_out is True
    assert result.returncode == 124
    assert result.args == command
