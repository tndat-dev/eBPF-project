import importlib.util
import io
import json
import zipfile
from pathlib import Path

import numpy as np

from sentinel_pulse.lidds import convert

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lidds_evaluate', ROOT/'scripts'/'analysis'/'lidds_evaluate.py')
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)
NAMES = ['read', 'write', 'close', 'epoll_wait', 'futex', 'sendto', 'recvfrom']


def _trace(rng, start, seconds, attack_at=None):
    lines, t = [], start
    while t < start + seconds:
        tid = int(rng.integers(1, 4))
        name = NAMES[int(rng.integers(0, len(NAMES)))]
        if attack_at is not None and t > attack_at:
            name = 'ptrace' if rng.random() < .3 else name             # a new behaviour after the exploit
        lines.append(f'{int(t * 1e9)} 33 {tid} apache2 {tid} {name} > fd=3')
        t += float(rng.exponential(.004))
    return '\n'.join(lines)


def _archive(tmp_path):
    rng = np.random.default_rng(5)
    outer = tmp_path/'SCN.zip'
    with zipfile.ZipFile(outer, 'w') as z:
        plan = [('training', 40, None), ('validation', 45, None), ('test/normal', 6, None), ('test/normal_and_attack', 6, 12.0)]
        for split, count, attack in plan:
            for i in range(count):
                start = 1000.0 + 100 * i
                inner = io.BytesIO()
                with zipfile.ZipFile(inner, 'w') as r:
                    meta = dict(exploit=attack is not None, time=dict(exploit=[dict(absolute=start + attack)] if attack else []))
                    r.writestr(f'rec{i}.json', json.dumps(meta))
                    r.writestr(f'rec{i}.sc', _trace(rng, start, 30.0, None if attack is None else start + attack))
                z.writestr(f'SCN/{split}/{split.replace("/", "_")}_{i}.zip', inner.getvalue())
    return outer


def test_end_to_end_on_a_synthetic_scenario(tmp_path):
    archive = _archive(tmp_path)
    header = tmp_path/'unistd.h'
    header.write_text('\n'.join(f'#define __NR_{n} {i}' for i, n in enumerate(NAMES + ['ptrace'] + [f'x{j}' for j in range(320)])) + '\n')
    convert.convert_scenario(archive, tmp_path/'conv'/'SCN', header=header)
    result, raw = ev.evaluate_scenario('SCN', tmp_path/'conv'/'SCN', archive, exec_set={59, 322})
    arms = result['arms']
    assert set(arms) == {'ml', 'tripwire', 'system', 'stide'}
    assert arms['tripwire']['detection_rate'] == 1.0 and arms['tripwire']['false_alarm_rate'] == 0.0   # ptrace is new
    assert arms['system']['detection_rate'] >= max(arms['ml']['detection_rate'], arms['tripwire']['detection_rate'])
    assert arms['stide']['attack_recordings'] == 6 and arms['stide']['normal_recordings'] == 6
    assert result['fit']['calibration_examples'] >= 1199
    assert all(l > 0 for l in [arms['tripwire']['latency_p50']])


def test_recording_outcome_counts_alarms_before_the_exploit_as_false():
    assert ev.recording_outcome([5.0, 6.0, 40.0], exploit_at=30.0) == (True, 10.0, 1)
    assert ev.recording_outcome([5.0, 30.0], exploit_at=None) == (False, None, 2)
    assert ev.recording_outcome([], exploit_at=30.0) == (False, None, 0)
