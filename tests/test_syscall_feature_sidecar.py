import json
import sys
import time
from types import SimpleNamespace

from sentinel_pulse.syscall_study.syscall_histogram_pilot import FeatureSidecar


def make_sidecar(tmp_path):
    loader = tmp_path / 'loader'
    loader.write_text(
        '#!/usr/bin/python3\nimport signal,time,sys\n'
        'signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))\n'
        'print(\'{"type":"snapshot_end","observed_at":1}\',flush=True)\n'
        'while True: time.sleep(0.05)\n')
    loader.chmod(0o755)
    return FeatureSidecar(SimpleNamespace(feature_loader=loader, feature_object=tmp_path/'object',
                          allowlist=tmp_path/'allowlist', metadata=tmp_path/'metadata', output=tmp_path))


def test_sidecar_drains_and_seals_raw_and_feature_outputs(tmp_path, monkeypatch):
    def capture(source, dest, *args):
        count = 0
        for line in source:
            dest.write(line)
            dest.flush()
            count += 1
        return dict(emitted=count, malformed=0, unresolved=0)
    monkeypatch.setitem(sys.modules, 'sentinel_pulse.collector.capture', SimpleNamespace(run=capture))
    sidecar = make_sidecar(tmp_path)
    sidecar.start()
    deadline = time.monotonic() + 3
    output = tmp_path / 'features.jsonl'
    while (not output.exists() or output.stat().st_size == 0) and time.monotonic() < deadline:
        time.sleep(0.01)
    result = sidecar.finish()
    assert result['capture']['emitted'] == 1
    assert result['loader_exit_status'] == 0
    assert not result['unexpected_exit']
    assert (tmp_path/'feature-raw.jsonl').read_bytes() == output.read_bytes()
    assert json.loads((tmp_path/'FEATURE_CAPTURE.json').read_text()) == result


def test_sidecar_retains_parser_failure_instead_of_calling_it_valid(tmp_path, monkeypatch):
    def capture(source, dest, *args):
        next(source)
        raise ValueError('invalid feature snapshot')
    monkeypatch.setitem(sys.modules, 'sentinel_pulse.collector.capture', SimpleNamespace(run=capture))
    sidecar = make_sidecar(tmp_path)
    sidecar.start()
    sidecar.thread.join(timeout=3)
    result = sidecar.finish()
    assert result['error'] == 'invalid feature snapshot'
    assert 'capture' not in result
    assert (tmp_path/'feature-raw.jsonl').read_text()
