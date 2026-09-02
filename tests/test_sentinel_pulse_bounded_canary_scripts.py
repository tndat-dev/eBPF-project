from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_bounded_canary_starts_all_finalizers_without_serial_wait():
    script = (ROOT / "sentinel_pulse" / "start_bounded_live_canary.sh").read_text()
    assert "systemd-run --no-block" in script
    assert "ENABLE_INJECTION_TRACKING=false" in script
    assert "automatic_promotion" in script
    assert "systemctl disable sentinel-pulse-detector-candidate.service" in script
    assert "DURATION_SECONDS >= 300" in script
    assert "DURATION_SECONDS <= 90000" in script
    assert "! -path '*/__pycache__/*'" in script
    assert "--exclude='*.pyc'" in script


def test_bounded_canary_supervisor_reaches_a_checksum_bound_terminal_state():
    script = (ROOT / "sentinel_pulse" / "run_bounded_live_canary.sh").read_text()
    assert "start_bounded_live_canary.sh" in script
    assert "collect_bounded_live_canary.sh" in script
    assert "freeze_failed_bounded_live_canary.sh" in script
    assert "CANARY_COMPLETE" in script
    assert "CANARY_FAILED.txt" in script
    assert "observed_alerts > 0" in script
    assert "SUPERVISOR_TIMEOUT" in script
    assert "automatic_promotion" not in script
    assert "install_production" not in script


def test_bounded_canary_collection_is_checksum_gated_and_never_promotes():
    script = (ROOT / "sentinel_pulse" / "collect_bounded_live_canary.sh").read_text()
    assert "sha256sum -c START_SHA256SUMS" in script
    assert "sha256sum -c CANARY_SHA256SUMS" in script
    assert "sentinel_pulse.aggregate_live_canary" in script
    assert "model/manifest.json" in script
    assert "coverage_preflight_gate" in script
    assert 'remote_sudo "$host"' in script
    assert "finalize_candidate" not in script
    assert "install_production" not in script


def test_failed_bounded_canary_is_stopped_and_checksum_archived():
    script = (
        ROOT / "sentinel_pulse" / "freeze_failed_bounded_live_canary.sh"
    ).read_text()
    assert "systemctl stop sentinel-pulse-collector-500ms-experiment.service" in script
    assert "CANARY_FAILED.txt" in script
    assert "FAILED_FINAL_SHA256SUMS" in script
    assert "valid_zero_alert_gate" in script
    assert "infrastructure_or_evidence_failure" in script
    assert "not_evaluated_by_this_run" in script
    assert "automatic_promotion" in script
    assert "install_production" not in script
