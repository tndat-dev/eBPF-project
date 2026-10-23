import importlib.util
import json
from pathlib import Path

import numpy as np

from sentinel_pulse.attack.window_table import FLOATS, SIGNALS, load, save

spec = importlib.util.spec_from_file_location('replica_compare', Path(__file__).parents[1]/'scripts/analysis/replica_compare.py')
rc = importlib.util.module_from_spec(spec); spec.loader.exec_module(rc)

FIELDS = ['workload_key', 'node_name', 'pod_uid', 'container_name', 'workload_revision', 'cgroup_id']


def table(tmp_path):
    # three kafka replicas and one other workload; replica w1 is flagged on every launch window, others never
    rows = []
    for ident, node in ((0, 'w1'), (1, 'w3'), (2, 'w4')):
        for k in range(10):
            launch = k % 2 == 0
            low = node == 'w1' and launch
            rows.append(dict(ident=ident, workload=0, start=100.0 + k, end=100.5 + k, tree_p=0.5,
                             support_p=0.0005 if low else 0.5, joint_p=0.001 if low else 1.0, alpha=0.0167,
                             launch=launch, preview=low))
    rows.append(dict(ident=3, workload=1, start=100.0, end=100.5, tree_p=0.0001, support_p=0.5, joint_p=0.0002,
                     alpha=0.0167, launch=False, preview=True))
    rows.append(dict(ident=0, workload=0, start=500.0, end=500.5, tree_p=0.0001, support_p=0.5, joint_p=0.0002,
                     alpha=0.0167, launch=False, preview=True))          # inside the excluded span
    arrays = {name: np.array([r.get(name, 0.0) for r in rows], dtype=float) for name in FLOATS}
    arrays.update(ident=np.array([r['ident'] for r in rows], dtype=np.int32),
                  workload=np.array([r['workload'] for r in rows], dtype=np.int16),
                  eligible=np.ones(len(rows), dtype=np.int8), launch=np.array([r['launch'] for r in rows], dtype=np.int8),
                  preview=np.array([r['preview'] for r in rows], dtype=np.int8))
    arrays.update({name: np.zeros(len(rows), dtype=np.int16) for name in SIGNALS})
    ids = [['production/kafka:kafka', n, f'{n}-pod-uid', 'kafka', 'r', '1'] for n in ('w1', 'w3', 'w4')]
    meta = dict(schema='pulse-window-table-v1', identity_fields=FIELDS,
                identities=ids + [['production/app:app', 'w1', 'app-pod', 'app', 'r', '2']],
                workloads=['production/kafka:kafka', 'production/app:app'])
    path = tmp_path/'table.npz'
    save(path, arrays, meta)
    return path


def test_replicas_of_one_workload_are_compared_and_excluded_spans_left_out(tmp_path):
    arrays, meta = load(table(tmp_path))
    r = rc.compare(arrays, meta, 'production/kafka:kafka', exclude=[(400.0, 600.0)])['replicas']
    assert set(r) == {'w1/w1-pod-u', 'w3/w3-pod-u', 'w4/w4-pod-u'}             # the other workload is not mixed in
    w1, w3 = r['w1/w1-pod-u'], r['w3/w3-pod-u']
    assert w1['windows'] == 10 and w1['launch_share'] == 0.5                     # the excluded window is gone
    assert w1['flagged'] == dict(n=10, share=0.5)
    assert w1['flagged_launch'] == dict(n=5, share=1.0) and w1['flagged_no_launch'] == dict(n=5, share=0.0)
    assert w1['flagged_smaller_branch'] == dict(tree=0, support=5)
    assert w3['flagged']['share'] == 0.0 and w3['flagged_smaller_branch'] == dict(tree=0, support=0)


def test_command_line_writes_the_comparison(tmp_path):
    import sys
    path, out = table(tmp_path), tmp_path/'out.json'
    sys.argv = ['replica_compare', '--table', str(path), '--workload', 'production/kafka:kafka',
                '--exclude', '400,600', '--output', str(out)]
    rc.main()
    d = json.loads(out.read_text())
    assert d['schema'] == 'pulse-replica-compare-v1' and d['excluded'] == [[400.0, 600.0]]
    assert len(d['replicas']) == 3
