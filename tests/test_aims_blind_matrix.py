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

from run_aims_blind_matrix import (freeze_paired_attack_evidence,
                                   quarantine_incomplete_pair, run_trial,
                                   resumable_trials, validated_trials,
                                   validate_normal_prerequisite,
                                   validate_v8_contracts)
from validate_feature_capture import validate_capture


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


def test_v8_prerequisite_and_contract_bind_pre_registered_seeds(tmp_path):
    prerequisite = tmp_path / "independent.json"
    prerequisite.write_text(json.dumps({
        "role": "independent_evaluation", "status": "complete", "passed": True,
        "candidate_sha256": {"model": "a"},
        "initial_calibration_sha256": "b" * 64,
        "split_contract_sha256": "c" * 64,
    }))
    validate_normal_prerequisite(
        prerequisite, {"model": "a"}, "b" * 64, "c" * 64,
        allowed_roles=("independent_evaluation",),
    )
    attack = {
        "schema": "sentinel-v8-blind-attack-contract/v1",
        "release_id": "v8", "trial_seeds": [19, 32],
        "capture_mode": "sequence", "split_contract_sha256": "c" * 64,
        "seed_pre_registration": {
            "source_sha256": "e" * 64, "frozen_before_v8_capture": True,
        },
    }
    split = {"release_id": "v8"}
    evaluation = {
        "release_id": "v8", "trial_seeds": [19, 32],
        "frozen_before_v8_capture": True, "paired_replay_required": True,
    }
    validate_v8_contracts(
        attack, split, evaluation, attack_split_sha256="c" * 64,
        evaluation_sha256="e" * 64, capture_release_id="v8",
    )
    attack["trial_seeds"] = [99]
    with pytest.raises(ValueError, match="pre-registered"):
        validate_v8_contracts(
            attack, split, evaluation, attack_split_sha256="c" * 64,
            evaluation_sha256="e" * 64, capture_release_id="v8",
        )


def _write_attack_capture(path, *, base, injection_id):
    context = {
        "release_id": "v8", "run_id": f"run-{injection_id}",
        "phase_id": "namespace_probe", "traffic_regime": "attack",
    }
    rows = [
        {
            "kind": "injection", "schema": "sentinel-injection-interval/v2",
            "ts": base, "injection_id": injection_id,
            "pod_key": "production/api-gateway-abc",
            "attack_type": "namespace_probe", "rate": 6, "seed": 19,
            **context,
        },
        {
            "kind": "feature_window", "schema": "sentinel-feature-window/v2",
            "ts": base + 10, "pod_key": "production/api-gateway-abc",
            "model_key": "production/api-gateway", "node_name": "worker",
            "window_start": base, "window_end": base + 10,
            "event_count": 2, "vector_size": 2,
            "sparse_vector": [[0, 0.5], [1, 0.5]],
            "syscall_counts": {"execve": 1, "unshare": 1},
            "contains_arguments_or_payloads": False,
            "capture_mode": "sequence",
            "syscall_sequence": ["execve", "unshare"],
            **context,
        },
        {
            "kind": "injection_end", "schema": "sentinel-injection-interval/v2",
            "ts": base + 9, "injection_id": injection_id,
            "pod_key": "production/api-gateway-abc",
            "attack_type": "namespace_probe", "attack_exit_code": 0,
            **context,
        },
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def test_v8_freezes_all_child_attack_captures_into_one_labelled_replay(tmp_path):
    trials = []
    for index, base in enumerate((100.0, 200.0), 1):
        scenario_dir = tmp_path / f"api-trial-{index:02d}" / "scenario"
        scenario_dir.mkdir(parents=True)
        capture = scenario_dir / "capture.jsonl"
        _write_attack_capture(capture, base=base, injection_id=f"inj-{index}")
        validation = validate_capture(capture)
        assert validation["valid"] is True
        report = scenario_dir / "report.json"
        report.write_text(json.dumps({
            "scenarios": {"namespace_probe": {"feature_capture": {
                "path": str(capture),
                "sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
                "validation": validation,
            }}}
        }))
        trials.append({"report_path": str(report)})
    evidence = freeze_paired_attack_evidence(
        tmp_path, {"trials": trials}, expected_sources=2,
    )
    assert evidence["source_count"] == 2
    assert evidence["injection_intervals"] == 2
    assert evidence["attack_windows"] == 2
    assert evidence["labels_used_for_training"] is False
    assert Path(evidence["capture"]).is_file()
    assert Path(evidence["dataset_manifest"]).is_file()


def test_incomplete_derived_pair_is_preserved_before_rebuild(tmp_path):
    capture = tmp_path / "capture.jsonl"
    manifest = tmp_path / "capture.manifest.json"
    capture.write_text("partial")
    quarantine_incomplete_pair(capture, manifest)
    assert not capture.exists()
    rejected = list((tmp_path / "rejected-derived").glob("capture.jsonl.incomplete-*"))
    assert len(rejected) == 1
    assert rejected[0].read_text() == "partial"


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
