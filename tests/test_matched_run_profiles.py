from pathlib import Path

from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.pipeline.matched_worker import NullSink
from sentinel_pulse.pipeline.plan_matched_run import PROFILES

ROOT = Path(__file__).resolve().parents[1]


def test_profile_policies_and_fixtures_match_repository():
    for name, spec in PROFILES.items():
        assert sha256_file(ROOT/spec['policy']) == spec['policy_hash'], name
        assert (ROOT/spec['fixture']).is_file(), name


def test_pulse_live_recalibrated_profile_registers_benign_controls_without_raw_frames():
    spec = PROFILES['pulse-live-recalibrated']
    assert spec['benign_exec_control'] is True
    assert spec['write_raw_frames'] is False
    assert 'benign_exec_control' in (ROOT/spec['fixture']).read_text()


def test_null_sink_accepts_worker_calls():
    with NullSink() as sink:
        sink.write('{"type":"stat"}\n')
        sink.flush()


def test_attack_rates_option_validates_and_defaults():
    import subprocess, sys
    r = subprocess.run([sys.executable, '-m', 'sentinel_pulse.pipeline.plan_matched_run', '--source', '/x', '--root', '/y',
                        '--run-id', 'abc', '--attack-rates', '0,3'], capture_output=True, text=True)
    assert r.returncode == 2 and 'attack rates' in r.stderr
    import inspect
    from sentinel_pulse.pipeline.plan_matched_run import plan
    assert inspect.signature(plan).parameters['rates'].default == (6, 12, 24)
