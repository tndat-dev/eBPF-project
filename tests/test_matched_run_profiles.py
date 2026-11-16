from pathlib import Path

from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.pipeline.matched_worker import NullSink

ROOT = Path(__file__).resolve().parents[1]


def test_a_run_needs_every_pinned_value_and_the_frozen_source(tmp_path):
    import pytest
    from sentinel_pulse.pipeline.plan_matched_run import PROFILES, plan
    assert PROFILES == {}
    with pytest.raises(ValueError, match='custom profile'):
        plan(ROOT, tmp_path / 'run', 'abc', profile='custom', frozen_source=ROOT, custom=None)
    with pytest.raises(ValueError, match='frozen-source'):
        plan(ROOT, tmp_path / 'run', 'abc', profile='custom', frozen_source=None, custom=dict(candidate='/x'))


def test_campaign_fixtures_and_policies_are_in_the_repository():
    for fixture in ('testbed/attack/runtime_attack_with_benign_control.c', 'testbed/attack/runtime_attack_blind_b1.c'):
        assert (ROOT / fixture).is_file()
    assert 'benign_exec_control' in (ROOT / 'testbed/attack/runtime_attack_with_benign_control.c').read_text()


def test_null_sink_accepts_worker_calls():
    with NullSink() as sink:
        sink.write('{"type":"stat"}\n')
        sink.flush()


def test_attack_rates_option_validates_and_defaults():
    import subprocess, sys
    r = subprocess.run([sys.executable, '-m', 'sentinel_pulse.pipeline.plan_matched_run', '--source', '/x', '--root', '/y',
                        '--run-id', 'abc', '--frozen-source', '/z', '--attack-rates', '0,3'], capture_output=True, text=True)
    assert r.returncode == 2 and 'attack rates' in r.stderr
    import inspect
    from sentinel_pulse.pipeline.plan_matched_run import plan
    assert inspect.signature(plan).parameters['rates'].default == (6, 12, 24)
