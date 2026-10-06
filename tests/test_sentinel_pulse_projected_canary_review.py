import json
from pathlib import Path

import pytest

from sentinel_pulse.encoding import compact_record
from sentinel_pulse.evaluate_projected_counter_canary import (
    REQUIRED_SOURCE_PATHS, evaluate,
)
from sentinel_pulse.features import PulseFeatureBuilder, PulseSnapshot
from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.validate_capture import validate
from sentinel_pulse.select_projected_collector import select


KEY = "production/test:app"


def write_json(path, payload):
    path.write_text(json.dumps(payload))


@pytest.fixture
def run(tmp_path):
    root = tmp_path / "source"
    hashes = {}
    for name in REQUIRED_SOURCE_PATHS:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name)
        hashes[name] = sha256_file(path)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    write_json(run_dir / "START.json", {
        "schema": "sentinel-pulse-projected-counter-canary-start-v1",
        "run_id": "test-canary", "started_at_unix": 100.0,
        "registered_duration_seconds": 60, "window_seconds": 0.5,
        "source_root": str(root), "sha256": hashes,
        "control_collector_remains_active": True,
        "ML_evaluation": False, "automatic_promotion": False,
    })
    write_json(run_dir / "TERMINAL.json", {
        "schema": "sentinel-pulse-projected-counter-canary-terminal-v1",
        "completed_at_unix": 160.5, "capture_exit_code": 0,
        "validation_exit_code": 0, "ML_evaluation": False,
        "automatic_promotion": False,
    })
    builder = PulseFeatureBuilder()
    builder.ingest(PulseSnapshot(7, 100.0, {0: 0}, {}), KEY)
    with (run_dir / "features.jsonl").open("w") as stream:
        for index in range(1, 121):
            feature = builder.ingest(PulseSnapshot(7, 100 + index * .5,
                                                   {0: index}, {}), KEY)
            row, schema = compact_record(feature.as_record())
            row["emitted_at"] = row["window_end"] + .01
            row["collector_snapshot_interval_seconds"] = .5
            row["collector_stats"] = {"capture_interval_violation": 0}
            if index == 1:
                stream.write(json.dumps(schema) + "\n")
            stream.write(json.dumps(row) + "\n")
    full = validate(run_dir / "features.jsonl", interval_min_seconds=.35,
                    interval_max_seconds=.8, nominal_interval_seconds=.5)
    assert full["valid"], full["errors"]
    write_json(run_dir / "VALIDATION.json", full)
    return run_dir


def mutate(path, **values):
    payload = json.loads(path.read_text())
    payload.update(values)
    write_json(path, payload)


def test_completed_canary_pass_is_collector_only_not_ml_promotion(run):
    report = evaluate(run, [KEY])
    assert report["valid"], report["errors"]
    assert report["measured_span_seconds"] == 60
    assert report["accuracy_claim_allowed"] is False
    assert report["automatic_promotion"] is False


def test_partial_capture_with_zero_exit_codes_is_rejected(run):
    # 110 rows still pass the 100-row validator but cover only 55 of 60 seconds.
    capture = run / "features.jsonl"
    capture.write_text("\n".join(capture.read_text().splitlines()[:111]) + "\n")
    full = validate(capture, interval_min_seconds=.35, interval_max_seconds=.8,
                    nominal_interval_seconds=.5)
    assert full["valid"]
    write_json(run / "VALIDATION.json", full)
    assert "capture ended early" in " ".join(evaluate(run, [KEY])["errors"])


def test_missing_expected_workload_rejects_good_tail(run):
    report = evaluate(run, [KEY, "production/missing:app"])
    assert not report["valid"]
    assert report["missing_workload_keys"] == ["production/missing:app"]


@pytest.mark.parametrize("keys", [[], [KEY, KEY], [7], KEY, {KEY: 1}])
def test_explicit_unique_coverage_required(run, keys):
    assert not evaluate(run, keys)["valid"]


def test_capture_tamper_detected_even_when_stored_validation_says_pass(run):
    with (run / "features.jsonl").open("a") as stream:
        stream.write("{}\n")
    assert "SHA-256 mismatch" in " ".join(evaluate(run, [KEY])["errors"])


def test_source_tamper_is_not_a_valid_canary(run):
    start = json.loads((run / "START.json").read_text())
    path = Path(start["source_root"]) / next(iter(REQUIRED_SOURCE_PATHS))
    path.write_text("changed")
    assert "SHA-256 mismatch" in " ".join(evaluate(run, [KEY])["errors"])


@pytest.mark.parametrize("change", [
    {"completed_at_unix": 159.0}, {"capture_exit_code": 1},
    {"ML_evaluation": True}, {"automatic_promotion": True},
])
def test_inconsistent_terminal_is_rejected(run, change):
    mutate(run / "TERMINAL.json", **change)
    assert not evaluate(run, [KEY])["valid"]


def test_unexpected_workload_is_not_silently_admitted(run):
    report = evaluate(run, ["production/other:app"])
    assert report["unexpected_workload_keys"] == [KEY]
    assert not report["valid"]


@pytest.fixture
def selection(run):
    start = json.loads((run / "START.json").read_text())
    (Path(start["source_root"]) / "sentinel_pulse/ebpf/pulse_counter_projected_loader").chmod(0o555)
    metadata = {"cgroups": {"7": {"namespace": "production", "workload_name": "test",
                                "container_name": "app", "workload_revision": "r1"}}}
    write_json(run / "start-cgroups.json", metadata)
    write_json(run / "live-cgroups.json", metadata)
    manifest = run / "manifest.json"
    write_json(manifest, {"schema": "sentinel-pulse-model-manifest-v2", "window_seconds": .5,
                         "workloads": {KEY: {}}, "approved_workload_revisions": {KEY: ["r1"]}})
    (run / "manifest.sha256").write_text(sha256_file(manifest) + "  manifest.json\n")
    return run, manifest, run / "live-cgroups.json"


def test_selector_uses_only_verified_projected_pair(selection):
    output = select(*selection)
    assert output["variant"] == "projected"
    assert output["safety_review"]["valid"]
    assert output["automatic_promotion"] is False


def test_selector_rejects_revision_drift_before_install(selection):
    run, manifest, live = selection
    metadata = json.loads(live.read_text())
    metadata["cgroups"]["7"]["workload_revision"] = "r2"
    write_json(live, metadata)
    with pytest.raises(ValueError, match="unapproved live"):
        select(run, manifest, live)


def test_selector_rejects_node_coverage_drift(selection):
    run, manifest, live = selection
    write_json(live, {"cgroups": {}})
    with pytest.raises(ValueError, match="live node model coverage"):
        select(run, manifest, live)


def test_selector_rejects_tampered_model_manifest(selection):
    run, manifest, live = selection
    manifest.write_text("{}")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        select(run, manifest, live)


def test_observation_scope_change_preserves_safety_verification(selection):
    run,manifest,live=selection
    write_json(live,{'cgroups':{}})
    result=select(run,manifest,live,allow_scope_changes=True)
    assert result['observational_scope_changes'] and result['live_workloads']==[]
    assert result['safety_review']['valid']
    manifest.write_text('{}')
    with pytest.raises(ValueError,match='SHA-256 mismatch'):
        select(run,manifest,live,allow_scope_changes=True)


def test_projected_install_does_not_overwrite_control_binaries():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    installer = (root / "sentinel_pulse/install_500ms_experiment.sh").read_text()
    assert 'COLLECTOR_VARIANT=${COLLECTOR_VARIANT:-legacy}' in installer
    assert installer.index('sentinel_pulse.select_projected_collector') < installer.index('install -d -m 0755 /opt/sentinel-pulse/sentinel_pulse')
    assert 'PRIVATE_BIN=/opt/sentinel-pulse/experiments/$RUN_ID' in installer
    assert '"$COLLECTOR_LOADER"' in installer
    assert 'PULSE_500MS_LOADER=$COLLECTOR_LOADER' in installer
    unit = (root / "sentinel_pulse/systemd/sentinel-pulse-collector-500ms-experiment.service").read_text()
    assert '"${PULSE_500MS_LOADER}" --object "${PULSE_500MS_BPF_OBJECT}"' in unit
