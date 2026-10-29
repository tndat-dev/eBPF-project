import importlib.util
import io
import json
from pathlib import Path
import sys
import zipfile

import numpy as np

from sentinel_pulse.lidds import convert

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'/'analysis'))
spec = importlib.util.spec_from_file_location('lidds_evaluate_v2', ROOT/'scripts'/'analysis'/'lidds_evaluate_v2.py')
ev2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev2)
NAMES = ['read', 'write', 'close', 'epoll_wait', 'futex', 'sendto', 'recvfrom', 'openat']


def _trace(rng, start, seconds, attack_at=None):
    """A server that reads, writes small responses and opens files under /srv/data; after ``attack_at`` it writes
    into /etc once and sends one 64 KiB response (in-process exploit: no new syscall, no exec)."""
    lines, t, done = [], start, False
    while t < start + seconds:
        tid = int(rng.integers(1, 4))
        name = NAMES[int(rng.integers(0, len(NAMES)))]
        ts = int(t * 1e9)
        lines.append(f'{ts} 33 {tid} srv {tid} {name} > fd=3')
        if name == 'openat':
            path, flags = f'/srv/data/f{int(rng.integers(0, 50))}', '1(O_RDONLY)'
            if attack_at is not None and t > attack_at and not done:
                path, flags, done = '/etc/passwd', '577(O_TRUNC|O_CREAT|O_WRONLY)', True
            lines.append(f'{ts + 1000} 33 {tid} srv {tid} openat < fd=4(<f>{path}) name={path} flags={flags}')
        elif name in ('read', 'write', 'sendto', 'recvfrom'):
            size = int(rng.integers(100, 2000))
            if attack_at is not None and t > attack_at + 1 and name == 'sendto':
                size = 65536
            lines.append(f'{ts + 1000} 33 {tid} srv {tid} {name} < res={size} data=AA')
        t += float(rng.exponential(.004))
    return '\n'.join(lines)


def _archive(tmp_path):
    rng = np.random.default_rng(7)
    outer = tmp_path/'SCN.zip'
    with zipfile.ZipFile(outer, 'w') as z:
        plan = [('training', 40, None), ('validation', 45, None), ('test/normal', 6, None), ('test/normal_and_attack', 10, 12.0)]
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


def test_end_to_end_in_process_exploit_is_found_by_the_argument_branches(tmp_path):
    archive = _archive(tmp_path)
    header = tmp_path/'unistd.h'
    header.write_text('\n'.join(f'#define __NR_{n} {i}' for i, n in enumerate(NAMES + [f'x{j}' for j in range(320)])) + '\n')
    convert.convert_scenario(archive, tmp_path/'conv'/'SCN', header=header)
    result, raw = ev2.evaluate_scenario('SCN', tmp_path/'conv'/'SCN', archive, exec_set=set())
    arms = {a: r['all'] for a, r in result['arms'].items()}
    assert set(arms) == set(ev2.ARMS)
    assert arms['tripwire']['detection_rate'] == 0.0                     # no new syscall ID
    assert arms['path']['detection_rate'] == 1.0 and arms['path']['false_alarm_rate'] == 0.0
    assert arms['bytes']['detection_rate'] == 1.0 and arms['bytes']['false_alarm_rate'] == 0.0
    assert arms['step2']['detection_rate'] == 1.0 and arms['step3']['detection_rate'] == 1.0
    assert arms['step3']['detection_rate'] >= arms['step2']['detection_rate'] >= arms['step1']['detection_rate']
    assert len(result['development_recordings']) == 3                    # 30 % of 10 attack recordings
    assert result['arms']['step3']['official']['attack_recordings'] == 7
    assert result['limits']['prefix_w'] == 0 and result['reference']['prefixes'] >= 1


def test_development_set_is_seeded_and_scenario_specific():
    names = [f'r{i}' for i in range(120)]
    a = ev2.development_set('ZipSlip', names)
    assert a == ev2.development_set('ZipSlip', list(reversed(names))) and len(a) == 36
    assert a != ev2.development_set('CVE-2014-0160', names)


def test_criteria_follow_the_registered_rules():
    def arm(dr, fa):
        return dict(official=dict(detection_rate=dr, false_alarm_rate=fa))
    per = {'A': dict(arms=dict(system=arm(1.0, 0.01), step3=arm(1.0, 0.015))),
           'B': dict(arms=dict(system=arm(0.05, 0.02), step3=arm(0.9, 0.06)))}
    c = ev2.criteria(per, dict(step3=dict(detection_rate=0.95, false_alarm_rate=0.03)))
    assert c['H1'] is True and c['H2'] is False and c['H3'] is True and c['H3_per_scenario'] == {'A': True}


def test_parts_merge_into_the_same_document(tmp_path):
    archive = _archive(tmp_path)
    header = tmp_path/'unistd.h'
    header.write_text('\n'.join(f'#define __NR_{n} {i}' for i, n in enumerate(NAMES + [f'x{j}' for j in range(320)])) + '\n')
    convert.convert_scenario(archive, tmp_path/'conv'/'SCN', header=header)
    result, raw = ev2.evaluate_scenario('SCN', tmp_path/'conv'/'SCN', archive, exec_set=set())
    whole = ev2.document({'SCN': result}, {'SCN': raw})
    part = tmp_path/'part.json'
    part.write_text(json.dumps(whole, default=float))
    merged = ev2.merge([part])
    assert json.loads(json.dumps(merged['pooled'], default=float)) == json.loads(json.dumps(whole['pooled'], default=float))
    assert merged['recordings']['SCN']['step3'][0][-1] == raw['step3'][0][-1]
