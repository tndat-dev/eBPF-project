import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml-service"))
from aims_matrix_validation import validate_matrix


TARGETS = ("production/frontend", "production/api")
REGIMES = ("steady", "burst", "recovery", "toolmix")


def _contract():
    return {
        "contract_version": 1,
        "release_track": "test",
        "eligible_targets": list(TARGETS),
        "normal_protocol": {
            "regimes": list(REGIMES),
            "minimum_total_hours": 4 / 60,
        },
    }


def _write_phase(root, phase, *, actual=60.0, coverage=True):
    directory = root / phase
    directory.mkdir()
    targets = {}
    for target in TARGETS:
        data = directory / f"{target.replace('/', '__')}.npy"
        data.write_bytes((target + phase).encode())
        metadata = directory / f"{target.replace('/', '__')}_metadata.jsonl"
        metadata.write_text("".join(json.dumps({"event_count": 10}) + "\n" for _ in range(3)))
        targets[target] = {
            "shape": [3, 4],
            "sha256": hashlib.sha256(data.read_bytes()).hexdigest(),
            "metadata": str(metadata),
        }
    manifest = {
        "phase": phase,
        "requested_duration_seconds": 60,
        "minimum_duration_seconds": 60,
        "actual_duration_seconds": actual,
        "minimum_duration_satisfied": actual >= 58,
        "minimum_windows": 3,
        "vocabulary": {"size": 4, "sha256": "vocab-digest"},
        "experiment_artifacts": {
            "tetragon_policy": {"sha256": "policy-digest"},
            "loadgen_manifest": {"sha256": "loadgen-digest"},
        },
        "sensor_health": {
            "backpressure_events": 0,
            "membership_failures": 0,
            "coverage_failures": 0,
            "stream_failures": 0,
            "require_full_coverage": True,
            "coverage_healthy": coverage,
            "expected_tetragon_pods": 2,
            "active_tetragon_pods": ["tetragon-a", "tetragon-b"],
        },
        "targets": targets,
    }
    (directory / "collection_manifest.json").write_text(json.dumps(manifest))


def _matrix(tmp_path):
    for regime in REGIMES:
        _write_phase(tmp_path, f"aims-{regime}-run-01")


def test_matrix_gate_accepts_only_complete_duration_and_evidence(tmp_path):
    _matrix(tmp_path)
    report = validate_matrix(tmp_path, _contract(), runs_per_regime=1, minutes_per_run=1)
    assert report["valid"] is True
    assert report["completed_phases"] == 4
    assert report["total_actual_seconds"] == 240.0


def test_matrix_gate_records_frozen_phase_roles(tmp_path):
    _matrix(tmp_path)
    contract = _contract()
    contract["normal_protocol"].update({
        "phase_roles": {"candidate_fit": {"runs": [1]}},
        "holdout_training_forbidden": True,
    })
    report = validate_matrix(tmp_path, contract, runs_per_regime=1, minutes_per_run=1)
    assert report["valid"] is True
    assert report["phase_roles"] == {"candidate_fit": [1]}
    assert {item["dataset_role"] for item in report["captures"]} == {
        "candidate_fit"
    }


def test_matrix_gate_rejects_time_collapse(tmp_path):
    _matrix(tmp_path)
    path = tmp_path / "aims-steady-run-01" / "collection_manifest.json"
    manifest = json.loads(path.read_text())
    manifest["actual_duration_seconds"] = 3
    manifest["minimum_duration_satisfied"] = False
    path.write_text(json.dumps(manifest))
    report = validate_matrix(tmp_path, _contract(), runs_per_regime=1, minutes_per_run=1)
    assert report["valid"] is False
    assert any("time collapsed" in error for error in report["errors"])


def test_matrix_gate_rejects_missing_phase_and_sensor_coverage(tmp_path):
    _matrix(tmp_path)
    missing = tmp_path / "aims-toolmix-run-01"
    for path in missing.iterdir():
        path.unlink()
    missing.rmdir()
    path = tmp_path / "aims-burst-run-01" / "collection_manifest.json"
    manifest = json.loads(path.read_text())
    manifest["sensor_health"]["coverage_healthy"] = False
    path.write_text(json.dumps(manifest))
    report = validate_matrix(tmp_path, _contract(), runs_per_regime=1, minutes_per_run=1)
    assert report["valid"] is False
    assert any("missing phases" in error for error in report["errors"])
    assert any("coverage was unhealthy" in error for error in report["errors"])


def test_matrix_gate_rejects_tampered_array(tmp_path):
    _matrix(tmp_path)
    data = tmp_path / "aims-recovery-run-01" / "production__api.npy"
    data.write_bytes(b"tampered")
    report = validate_matrix(tmp_path, _contract(), runs_per_regime=1, minutes_per_run=1)
    assert report["valid"] is False
    assert any("data digest mismatch" in error for error in report["errors"])
