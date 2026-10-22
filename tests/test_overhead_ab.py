import importlib.util
import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).parents[1]/'scripts'/'analysis'/'overhead_ab.py'
spec = importlib.util.spec_from_file_location('overhead_ab', SCRIPT)
oa = importlib.util.module_from_spec(spec); spec.loader.exec_module(oa)


def test_paired_overhead_uses_rounds_as_pairs():
    rows = [(r, 'off', 500.0 + r) for r in range(1, 6)] + [(r, 'monitored', (500.0 + r) * 1.10) for r in range(1, 6)]
    rel, ci, n = oa.paired_overhead(rows, 'monitored', reps=500)
    assert abs(rel - 0.10) < 1e-9 and ci[0] <= rel <= ci[1] and n == 5
    assert oa.paired_overhead(rows, 'filtered') is None


def test_end_to_end(tmp_path):
    lines = []
    for r in range(1, 4):
        for cond, k in (('off', 1.0), ('filtered', 1.02), ('monitored', 1.2)):
            lines.append(json.dumps(dict(node='w', mode='getpid', round=r, condition=cond, ns_per_op=500 * k)))
    (tmp_path/'w.jsonl').write_text('\n'.join(lines))
    subprocess.run([sys.executable, str(SCRIPT), str(tmp_path/'w.jsonl'), '--output', str(tmp_path/'o.json')], check=True, capture_output=True)
    d = json.loads((tmp_path/'o.json').read_text())['nodes']['w']['getpid']
    assert abs(d['monitored_overhead']['relative'] - 0.2) < 1e-9 and abs(d['filtered_overhead']['added_ns_per_op'] - 10) < 1e-9
