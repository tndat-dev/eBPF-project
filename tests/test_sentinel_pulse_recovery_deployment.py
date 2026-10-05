import json
from pathlib import Path

import pytest

from sentinel_pulse.recovery_deployment import bind_detector, bind_freshness_preregistration, contract, render_unit

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "sentinel_pulse/protocol/telemetry-recovery-v1.json"


def make_run(tmp_path):
    profile = tmp_path / "telemetry-recovery-profile.json"
    profile.write_bytes(PROFILE.read_bytes())
    feature = tmp_path / "features.jsonl"
    feature.touch()
    binding = contract(profile, .5, .999, 30)
    (tmp_path / "START.json").write_text(json.dumps({
        "telemetry_recovery_contract": binding,
        "telemetry_availability_contract": {"nominal_interval_seconds": .5,
            "minimum_availability": .999, "maximum_single_gap_seconds": 30},
    }))
    return profile, feature, binding


@pytest.mark.parametrize("values", [(1, .999, 30), (.5, .99, 30), (.5, 1, 30), (.5, .999, 10)])
def test_deployment_cannot_silently_change_recovery_contract(values):
    with pytest.raises(ValueError, match="differs"):
        contract(PROFILE, *values)


def test_detector_requires_explicit_matching_opt_in(tmp_path):
    profile, feature, binding = make_run(tmp_path)
    assert bind_detector(feature, profile) == binding
    with pytest.raises(ValueError, match="explicit"):
        bind_detector(feature, None)
    profile.write_text(profile.read_text() + " ")
    with pytest.raises(ValueError, match="mismatch"):
        bind_detector(feature, profile)


def test_detector_refuses_unbound_recovery_or_missing_installed_copy(tmp_path):
    profile, feature, _ = make_run(tmp_path)
    profile.unlink()
    with pytest.raises(FileNotFoundError):
        bind_detector(feature, PROFILE)
    (tmp_path / "START.json").write_text("{}")
    assert bind_detector(feature, None) is None
    with pytest.raises(ValueError, match="START binding"):
        bind_detector(feature, PROFILE)


def test_legacy_control_path_remains_compatible(tmp_path):
    assert bind_detector(tmp_path / "features.jsonl", None) is None


@pytest.mark.parametrize("kind,path", [
    ("collector", "/var/lib/sentinel-pulse-500ms/runs/new-run/telemetry-recovery-profile.json"),
    ("detector", "/opt/sentinel-pulse/policies/recovery-" + "a" * 64 + ".json"),
])
def test_rendered_units_opt_in_without_modifying_default(kind, path):
    name = "collector-500ms-experiment" if kind == "collector" else "detector-candidate"
    source = (ROOT / f"sentinel_pulse/systemd/sentinel-pulse-{name}.service").read_text()
    result = render_unit(source, kind, path)
    assert "--recovery-profile " in result
    assert "--recovery-profile" not in source
    assert ("--from-start" in result) == (kind == "detector")
    for section in ("CPUQuota=200%", "NoNewPrivileges=yes", "MemoryMax=1G"):
        assert section in result
    with pytest.raises(ValueError, match="already rendered"):
        render_unit(result, kind, path)


@pytest.mark.parametrize("path", ["/tmp/p.json", "/opt/sentinel-pulse/policies/x.json",
    "/var/lib/sentinel-pulse-500ms/runs/x/../telemetry-recovery-profile.json",
    "/var/lib/sentinel-pulse-500ms/runs/$(id)/telemetry-recovery-profile.json",
    "/var/lib/sentinel-pulse-500ms/runs/x/telemetry-recovery-profile.json\nExecStart=/bin/id"])
def test_profile_paths_cannot_inject_systemd_or_shell(path):
    with pytest.raises(ValueError, match="unsafe"):
        render_unit("ExecStart=x\n", "collector", path)


def test_default_finalizer_and_launchers_fail_closed_for_recovery():
    for name in ("start_500ms_normal_soak.sh", "start_bounded_live_canary.sh"):
        source = (ROOT / "sentinel_pulse" / name).read_text()
        assert 'TELEMETRY_RECOVERY_PROFILE_SOURCE' in source
        assert 'recovery requires its separate diagnostic launcher' in source
    source = (ROOT / "sentinel_pulse/finalize_500ms_experiment.sh").read_text()
    assert 'recovery capture requires its separate diagnostic validator' in source


def test_binding_precedes_installer_mutations():
    collector = (ROOT / "sentinel_pulse/install_500ms_experiment.sh").read_text()
    assert collector.index('contract(Path(sys.argv[1])') < collector.index('install -d -m 0755 /opt')
    detector = (ROOT / "sentinel_pulse/install_detector_candidate.sh").read_text()
    assert detector.index('bind_detector(Path(sys.argv[1])') < detector.index('useradd --system')
    assert '--from-start' in (ROOT / "sentinel_pulse/recovery_deployment.py").read_text()


def test_root_launcher_scopes_git_trust_and_records_preregistration_failure():
    source = (ROOT / "sentinel_pulse/run_recovery_runtime_smoke.sh").read_text()
    assert 'source_status=$(git -c safe.directory="$SOURCE_ROOT"' in source
    assert '[[ -z $source_status ]]' in source
    assert '"safe.directory=" + os.environ["SOURCE_ROOT"]' in source
    assert 'git config --global' not in source
    assert source.index('trap preregistration_failure EXIT') < source.index('PYTHONPATH="$SOURCE_ROOT" python3')


def test_freshness_is_explicit_and_does_not_change_legacy_units():
    source = (ROOT / "sentinel_pulse/systemd/sentinel-pulse-detector-candidate.service").read_text()
    path = "/opt/sentinel-pulse/policies/recovery-" + "a" * 64 + ".json"
    assert "--live-freshness" not in render_unit(source, "detector", path)
    assert "--live-freshness" in render_unit(source, "detector", path, live_freshness=True)
    with pytest.raises(ValueError, match="detector-only"):
        render_unit(source, "detector", path, live_freshness="true")
    launcher = (ROOT / "sentinel_pulse/run_recovery_runtime_smoke.sh").read_text()
    assert "detector_freshness_contract_sha256" in launcher
    assert "--expected-live-freshness" in launcher


@pytest.mark.parametrize("mutation", [None, "old_run", "contract", "run_id"])
def test_freshness_requires_new_preregistration_not_retroactive_opt_in(tmp_path, mutation):
    from sentinel_pulse.detector_freshness import CONTRACT, CONTRACT_SHA256
    registered = {"schema": "sentinel-pulse-recovery-runtime-smoke-start-v1", "run_id": "new",
                  "detector_freshness_contract": CONTRACT,
                  "detector_freshness_contract_sha256": CONTRACT_SHA256}
    if mutation == "old_run":
        registered.pop("detector_freshness_contract")
    elif mutation == "contract":
        registered["detector_freshness_contract_sha256"] = "a" * 64
    elif mutation == "run_id":
        registered["run_id"] = "old"
    prereg = tmp_path / "preregister" / "new"
    prereg.mkdir(parents=True)
    (prereg / "START.json").write_text(json.dumps(registered))
    feature = tmp_path / "runs" / "new" / "features.jsonl"
    if mutation is None:
        assert bind_freshness_preregistration(feature, prereg.parent) == CONTRACT
    else:
        with pytest.raises(ValueError, match="preregistration"):
            bind_freshness_preregistration(feature, prereg.parent)


def test_formal_worker_attests_before_install_and_freshness_binding():
    source = (ROOT / "sentinel_pulse/run_recovery_formal_worker.sh").read_text()
    assert source.index('attest-worker --marker') < source.index('/bin/bash "$SOURCE_ROOT/sentinel_pulse/install_500ms_experiment.sh"')
    assert source.index('"$RUN_DIR/FORMAL_WORKER_START.json"') < source.index('/bin/bash "$SOURCE_ROOT/sentinel_pulse/install_detector_candidate.sh"')
    assert 'DURATION_SECONDS=$(jq -er' in source
    assert 'marker run/node mismatch' in source
    assert 'test ! -e "$RUN_DIR"' in source


def test_formal_worker_preserves_alerts_and_stops_only_owned_units():
    source = (ROOT / "sentinel_pulse/run_recovery_formal_worker.sh").read_text()
    assert 'grep -qx "PULSE_RUN_ID=$RUN_ID"' in source
    assert 'grep -qx "PULSE_500MS_RUN_ID=$RUN_ID"' in source
    assert '"$PULSE_ALERTS" "$RUN_DIR/alerts.jsonl"' in source
    assert 'ENABLE_INJECTION_TRACKING=false' in source
    loop = source.split('while systemctl is-active', 1)[1].split('\ndone', 1)[0]
    assert 'PULSE_ALERTS' not in loop  # No zero-alert early-stop budget.
    assert 'controlled_collector_pause' not in source
    assert "'formal_recovery_pass': False" in source


def test_formal_worker_seals_evidence_before_terminal_receipt():
    source = (ROOT / "sentinel_pulse/run_recovery_formal_worker.sh").read_text()
    assert source.index('>"$RUN_DIR/FORMAL_WORKER_SHA256SUMS"') < source.index("write_new(p/'WORKER_TERMINAL.json'")
    assert 'trap finish EXIT' in source and "trap 'exit 130' INT TERM" in source
    assert 'systemctl stop sentinel-pulse-detector-candidate.service || rc=2' in source
