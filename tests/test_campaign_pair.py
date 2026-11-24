"""A pair whose event-generator binary cannot be staged keeps its other steps (pulse-live-final-1119 lost whole pairs)."""
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import sentinel_pulse.attack.preview_campaign as pc  # noqa: E402


class FakeRuntime:
    def __init__(self):
        self.sudo = []

    def remote_sudo(self, host, command):
        self.sudo.append(command)
        if 'sentinel-eventgen' in command:
            raise RuntimeError('cp: /tmp/sentinel-eventgen: No space left on device')

    def run(self, args, timeout=None, check=True):
        if 'tracingpolicy' in args:
            return SimpleNamespace(returncode=0, stdout=f'{pc.EXEC_PROVENANCE_POLICY} enabled'.encode(), stderr=b'')
        if 'sh' in args:
            return SimpleNamespace(returncode=0, stdout=b'lotl-done', stderr=b'')
        return SimpleNamespace(returncode=0, stdout=b'', stderr=b'done')

    def kubectl_json(self, *args):
        return dict(items=[dict(metadata=dict(name='tetragon-x'), spec=dict(nodeName='n1'))])

    environment = {}


def test_eventgen_stage_failure_skips_only_that_step(tmp_path, monkeypatch):
    worker_dir = tmp_path / 'w'
    worker_dir.mkdir()
    import time as _time
    (worker_dir / 'STATUS.json').write_text(json.dumps(dict(updated_at_unix=_time.time())))
    cfg = dict(workers={'h1': dict(node_name='n1', output=str(worker_dir))}, model_hash='m', policy_hash='p', binary='/b',
               binary_hash='x', source='/src', eventgen_binary='/eg', eventgen_hash='y', lotl_attack=True,
               benign_exec_control=True, admin_control=True, run_id='r')
    item = dict(workload_key='production/kafka:kafka', workload_controller='kafka', scenario='seccomp_api_probe',
                rate_per_second=12, seed=1)
    pod = dict(name='kafka-0', uid='u', node_name='n1')
    monkeypatch.setattr(pc, 'select_target', lambda rt, it, nw, i: (pod, dict(cfg['workers']['h1'], host='h1'), 'kafka', '7'))
    monkeypatch.setattr(pc, 'target_identity', lambda *a: dict(container_id='c', pod_uid='u'))
    monkeypatch.setattr(pc, 'step_order', lambda c, it, i: ['eventgen', 'admin', 'benign', 'attack', 'lotl'])
    monkeypatch.setattr(pc, 'tail_rows', lambda *a: [])
    monkeypatch.setattr(pc, 'evaluate_interval', lambda rows, iv, mh, ph: dict(trial_id=iv['trial_id']))
    monkeypatch.setattr(pc, 'find_execve_kprobe_event', lambda *a, **k: dict(kernel_event_at=1.0))
    monkeypatch.setattr(pc.time, 'sleep', lambda s: None)
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **k: SimpleNamespace(wait=lambda timeout=None: 0, terminate=lambda: None))
    out = pc.one_pair(FakeRuntime(), cfg, tmp_path, item, 3)
    labels = [json.loads(l)['trial_id'] for l in (tmp_path / 'INTERVALS.jsonl').read_text().splitlines()]
    assert labels == ['3:control', '3:admin', '3:benign', '3:attack', '3:lotl']        # no eventgen interval
    eg = [json.loads(l) for l in (tmp_path / 'EVENTGEN.jsonl').read_text().splitlines()]
    assert eg == [dict(trial_id='3:eventgen', action=eg[0]['action'], outcome='skipped', reason='stage_failed', returncode=None)]
    assert [r['trial_id'] for r in out] == ['3:control', '3:benign', '3:attack']
