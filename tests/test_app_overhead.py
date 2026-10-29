import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT/'scripts'/'analysis'/'app_overhead.py'
spec = importlib.util.spec_from_file_location('app_overhead', SCRIPT)
ao = importlib.util.module_from_spec(spec); spec.loader.exec_module(ao)
RUNNER = importlib.util.spec_from_file_location('app_overhead_ab', ROOT/'scripts'/'app_overhead_ab.py')
ab = importlib.util.module_from_spec(RUNNER); RUNNER.loader.exec_module(ab)


def synthetic(rounds=4, block=100.0, settle=30.0):
    """off latency 10 ms (/api/products/ 200 ms), probe +10 %; one failed request per block; a slow request in each
    settle window that must be ignored."""
    requests, events, t, k = [], [], 1000.0, 0
    for rnd in range(1, rounds + 1):
        for cond in (('off', 'probe') if rnd % 2 else ('probe', 'off')):
            f = 1.1 if cond == 'probe' else 1.0
            events.append(dict(event='block', round=rnd, condition=cond, start=t, end=t + block,
                               probe_cpu_ns={'w': int(0.05e9 * block)} if cond == 'probe' else None,
                               nodes={'w': dict(busy=30 if cond == 'probe' else 20, total=100, mem_available_kb=1)}))
            requests.append(dict(k=k, endpoint='/', scheduled=t + 1, sent=t + 1, done=t + 1 + 5.0, status=200)); k += 1
            for i in range(int(settle) + 1, int(block)):
                ep = '/api/products/' if i % 2 else '/'
                lat = (0.2 if i % 2 else 0.01) * f
                requests.append(dict(k=k, endpoint=ep, scheduled=t + i, sent=t + i + 0.001, done=t + i + lat,
                                     status=500 if i == int(settle) + 1 else 200)); k += 1
            t += block
    return requests, events


def test_paired_ratio_is_the_probe_effect_and_settle_is_dropped():
    requests, events = synthetic()
    d = ao.analyse(requests, events, settle=30.0)
    for m in ('p50', 'p95', 'p99'):
        assert abs(d['all_requests'][m]['overhead'] - 0.10) < 1e-9 and d['all_requests'][m]['rounds'] == 4
    ep = d['per_endpoint']['p50']
    assert abs(ep['/']['off_ms'] - 10) < 1e-9 and abs(ep['/api/products/']['added_ms'] - 20) < 1e-9
    assert d['pooled']['off']['errors'] == 4 and d['pooled']['probe']['p99_ms'] < 1000   # the 5 s settle request is out


def test_cpu_in_cores_and_busy_share():
    _, events = synthetic()
    c = ao.cpu([e for e in events if e['event'] == 'block'])
    assert abs(c['probe_cores']['w'] - 0.05) < 1e-12
    assert c['node_busy_share']['w'] == {'off': 0.2, 'probe': 0.3}


def test_cli(tmp_path):
    requests, events = synthetic()
    (tmp_path/'requests.jsonl').write_text('\n'.join(map(json.dumps, requests)))
    (tmp_path/'blocks.jsonl').write_text('\n'.join(map(json.dumps, [dict(event='start')] + events)))
    subprocess.run([sys.executable, str(SCRIPT), str(tmp_path), '--output', str(tmp_path/'o.json')], check=True, capture_output=True)
    d = json.loads((tmp_path/'o.json').read_text())
    assert d['blocks'] == 8 and d['stopped'] == []


def test_runner_spreads_endpoints_and_nodes(tmp_path, monkeypatch):
    seen = []
    class Reply:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'ok'
    monkeypatch.setattr(ab.urllib.request, 'urlopen', lambda url, timeout: seen.append(url) or Reply())
    c = ab.Client(tmp_path/'r.jsonl')
    for k in range(12):
        c.one(k, 1000.0 + k)
    assert c.flush_errors(1000.0, 1012.0) == 0.0
    c.close()
    assert seen[:4] == [f'http://10.1.16.237:31088{e}' for e in ab.ENDPOINTS]
    assert seen[4].startswith('http://10.1.16.238') and seen[8].startswith('http://10.1.16.239')
    rows = [json.loads(l) for l in (tmp_path/'r.jsonl').read_text().splitlines()]
    assert len(rows) == 12 and all(r['status'] == 200 for r in rows)
