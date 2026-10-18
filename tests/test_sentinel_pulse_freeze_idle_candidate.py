import json

import pytest

from sentinel_pulse.detector.freeze_idle_reference_candidate import freeze
from sentinel_pulse.integrity import sha256_file


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _fixture(root):
    (root / "inputs").mkdir()
    raw = root / "inputs" / "raw.jsonl"
    raw.write_text("normal reference input\n", encoding="utf-8")
    inputs = root / "INPUTS.json"
    _write_json(inputs, {"reference_files": [{"path": str(raw), "sha256": sha256_file(raw)}]})
    start = root / "START.json"
    _write_json(start, {
        "include_idle_windows": True,
        "feature_dimensions": 249,
        "attack_data_used_for_fit": False,
        "normal_training_admission": False,
        "input_manifest_sha256": sha256_file(inputs),
        "history_windows": 3,
        "source_commit": "fit-commit",
        "software": {"python": "3.12"},
        "reference_label": "unadjudicated_observation",
    })
    index_rows = {}
    results = {}
    for key, constant in (("production/app:main", 3), ("production/app:idle", 249)):
        data = root / "workloads" / ("data-" + str(constant) + ".jsonl")
        data.parent.mkdir(parents=True, exist_ok=True)
        data.write_text("row\n", encoding="utf-8")
        artifact = root / ("model-" + str(constant) + ".pkl")
        artifact.write_bytes(b"artifact-" + str(constant).encode())
        index_rows[key] = {"file": str(data.relative_to(root)), "sha256": sha256_file(data)}
        results[key] = {
            "state": "fitted_exploratory_reference",
            "artifact": artifact.name,
            "artifact_sha256": sha256_file(artifact),
            "fit": {"feature_dim": 249, "calibration_examples": 1300,
                    "minimum_calibration_examples": 999, "train_examples": 1000},
            "support": {"constant_training_coordinates": constant,
                        "calibration_rows": 1300,
                        "minimum_calibration_examples_per_branch": 1199},
        }
    index = root / "INDEX.json"
    _write_json(index, {"workloads": index_rows})
    _write_json(root / "RESULTS.json", {
        "start_sha256": sha256_file(start), "workloads": results,
    })
    _write_json(root / "TERMINAL.json", {
        "state": "completed_reference_experiment", "completed": 2, "fitted": 2,
    })


def test_freeze_includes_only_non_degenerate_verified_artifacts(tmp_path):
    experiment = tmp_path / "experiment"
    experiment.mkdir()
    _fixture(experiment)

    manifest = freeze(experiment, tmp_path / "CANDIDATE.json")

    assert manifest["eligible_workload_count"] == 1
    assert list(manifest["workloads"]) == ["production/app:main"]
    assert manifest["excluded_degenerate_workload_count"] == 1
    assert manifest["decision_policy"] is None
    assert manifest["serving_compatible"] is False
    assert manifest["workloads"]["production/app:main"]["artifact_sha256"]


def test_freeze_rejects_changed_indexed_input(tmp_path):
    experiment = tmp_path / "experiment"
    experiment.mkdir()
    _fixture(experiment)
    data = experiment / "workloads" / "data-3.jsonl"
    data.write_text("modified\n", encoding="utf-8")

    with pytest.raises(ValueError, match="indexed training data checksum"):
        freeze(experiment, tmp_path / "CANDIDATE.json")
