import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np

from sentinel_pulse.detector.support_model import pvalues
from sentinel_pulse.pipeline import live_recalibration as lr
from sentinel_pulse.pipeline import retention as rt

SCRIPT = Path(__file__).parents[1] / 'scripts' / 'analysis' / 'live_recalibration_check.py'
spec = importlib.util.spec_from_file_location('live_recalibration_check', SCRIPT)
chk = importlib.util.module_from_spec(spec); spec.loader.exec_module(chk)
H = 3600
W = 'production/a:app'


def model():
    return SimpleNamespace(base=SimpleNamespace(calibration_scores=np.linspace(0, 1, 50)), support_calibration=np.linspace(0, 1, 50))


def live_run(tmp_path, tamper=False):
    """Two workers: buffers for hours 100-101, a refresh at 102, decision rows scored under the swapped arrays."""
    rng = np.random.default_rng(9); root = tmp_path / 'run'; shared = root / 'shared'; workers = {}
    (root / 'campaign').mkdir(parents=True)
    (root / 'campaign' / 'INTERVALS.jsonl').write_text(json.dumps(dict(start_at=100 * H + 600.0)) + '\n')
    for i, node in enumerate(('n1', 'n2')):
        out = root / 'workers' / node; local = tmp_path / 'local' / node
        buf = rt.ScoreBuffer(local, 48, clock=lambda: 102 * H)
        for t in np.arange(100 * H, 102 * H, 2.0):
            buf.add(dict(status=rt.SCORED, window_end=float(t), tree_score=float(rng.random()), support_score=float(rng.random()),
                         workload_key=W, node_name=node, pod_uid='p', container_name='c', workload_revision='r', cgroup_id=1,
                         eligible_for_normal_review=True))
        buf.close()
        models = {W: model()}
        r = lr.LiveRecalibration(models, local, shared, node, window_hours=2, minimum_examples=100,
                                 exclude_intervals=root / 'campaign' / 'INTERVALS.jsonl', log=out / 'recalibration.jsonl')
        out.mkdir(parents=True, exist_ok=True)
        workers[f'10.0.0.{i}'] = dict(node_name=node, output=str(out))
        workers[node] = (r, models)
    for node in ('n1', 'n2'):
        r, _ = workers[node]
        r.publish(100); r.publish(101)
    rows = {}
    for node in ('n1', 'n2'):
        r, models = workers.pop(node)
        r.ready.put(r.build(102)); epoch = r.apply(); r.write_logs()
        seg = root / 'workers' / node / 'segments' / 's00001'; seg.mkdir(parents=True)
        lines = []
        for k in range(20):
            ts, ss = float(rng.random()), float(rng.random())
            tp = float(pvalues(np.array([ts]), models[W].base.calibration_scores)[0])
            sp = float(pvalues(np.array([ss]), models[W].support_calibration)[0])
            row = dict(status=rt.SCORED, workload_key=W, window_end=102 * H + k, tree_score=ts, support_score=ss,
                       tree_p=tp, support_p=sp, joint_p=min(1.0, 2 * min(tp, sp)), calibration_epoch=epoch)
            if tamper and k == 3:
                row['tree_p'] = tp + 1e-9
            lines.append(json.dumps(row))
        (seg / 'decisions.jsonl').write_text('\n'.join(lines) + '\n')
        rows[node] = lines
    cfg = dict(run_id='test-run', workers=workers, recalibration=dict(shared=str(shared), exclude_intervals=str(root / 'campaign' / 'INTERVALS.jsonl')))
    (root / 'CONFIG.json').write_text(json.dumps(cfg))
    return root


def test_live_p_values_equal_the_independent_rebuild(tmp_path):
    d = chk.check(live_run(tmp_path))
    for node in ('n1', 'n2'):
        w = d['workers'][node]
        assert w['epochs'] == [1] and w['compared'] == 20 and w['agreement'] == 1.0 and w['sizes_match_rebuild']
    assert d['same_sizes_on_every_worker'] == {lr.hour_name(102): True}


def test_a_changed_p_value_is_reported(tmp_path):
    d = chk.check(live_run(tmp_path, tamper=True))
    w = d['workers']['n1']
    assert w['equal'] == 19 and w['first_difference']['window_end'] == 102 * H + 3
