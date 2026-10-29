import json
from types import SimpleNamespace

import numpy as np
import pytest

from sentinel_pulse.attack import rolling_recalibration as rr
from sentinel_pulse.detector.recalibration import Recalibrator
from sentinel_pulse.detector.support_model import pvalues
from sentinel_pulse.pipeline import live_recalibration as lr
from sentinel_pulse.pipeline import retention as rt

H = 3600
W_A, W_B = 'production/a:app', 'production/b:app'


def decision(t, w, tree, support, eligible=True, node='n1'):
    return dict(status=rt.SCORED, window_end=t, tree_score=tree, support_score=support, workload_key=w, node_name=node,
                pod_uid='p', container_name='app', workload_revision='r', cgroup_id=1, eligible_for_normal_review=eligible)


def fake_model(n=50):
    return SimpleNamespace(base=SimpleNamespace(calibration_scores=np.linspace(0, 1, n)), support_calibration=np.linspace(0, 1, n),
                           minimum_calibration_examples_per_branch=10)


def write_buffers(tmp_path, hours=range(100, 114), per_hour=400, seed=3):
    """Two workers' local buffers; workload B only on n2 and sparse; returns every decision row."""
    rng = np.random.default_rng(seed); rows = []
    for node in ('n1', 'n2'):
        buf = rt.ScoreBuffer(tmp_path / 'local' / node, 48, clock=lambda: 114 * H)
        for h in hours:
            for i in range(per_hour):
                w = W_B if node == 'n2' and i % 20 == 0 else W_A
                r = decision(h * H + i * (H / per_hour), w, float(rng.random()), float(rng.random()), eligible=i % 9 != 0, node=node)
                buf.add(r); rows.append(r)
        buf.close()
    return rows


def recalibrators(tmp_path, **kw):
    models = {W_A: fake_model(), W_B: fake_model()}
    out = {}
    for node in ('n1', 'n2'):
        out[node] = lr.LiveRecalibration(models, tmp_path / 'local' / node, tmp_path / 'shared', node,
                                         minimum_examples=kw.get('minimum', 10), exclude_intervals=kw.get('intervals'),
                                         log=tmp_path / f'{node}.jsonl', clock=lambda: 0.0)
    return models, out


def test_refresh_equals_the_offline_rolling_calibration_with_campaign_exclusion(tmp_path):
    rows = write_buffers(tmp_path)
    intervals = tmp_path / 'INTERVALS.jsonl'
    intervals.write_text('\n'.join(json.dumps(dict(start_at=s)) for s in (105 * H + 100.0, 110 * H + 2000.0)))
    models, rc = recalibrators(tmp_path, intervals=intervals)
    for node in rc:
        for h in range(100, 114):
            rc[node].publish(h)
    hour, cal, info = rc['n1'].build(114)
    assert info['missing'] == [] and info['nodes'] == ['n1', 'n2'] and info['excluded_spans'] == 2
    # offline: rolling_recalibration.calibration over [H - 12 h, H) of the pooled rows, eligible and outside the spans
    spans = rr.campaign_spans([tmp_path])
    for w in (W_A, W_B):
        sel = sorted((r for r in rows if r['workload_key'] == w), key=lambda r: r['window_end'])
        a = dict(end=np.array([r['window_end'] for r in sel]), tree=np.array([r['tree_score'] for r in sel]),
                 support=np.array([r['support_score'] for r in sel]))
        usable = np.array([r['eligible_for_normal_review'] for r in sel]) & ~rr.masked(a['end'], spans)
        lo, hi = 102 * H, 114 * H
        i, j = np.searchsorted(a['end'], lo), np.searchsorted(a['end'], hi)
        np.testing.assert_array_equal(cal[w][0], np.sort(a['tree'][i:j][usable[i:j]]))
        np.testing.assert_array_equal(cal[w][1], np.sort(a['support'][i:j][usable[i:j]]))
    assert hour == 114


def test_apply_swaps_arrays_and_p_values_match_the_recalibrator(tmp_path):
    rows = write_buffers(tmp_path)
    models, rc = recalibrators(tmp_path, minimum=250)      # B: 17 eligible windows x 12 h = 204 < 250 -> kept
    for h in range(100, 114):
        rc['n1'].publish(h); rc['n2'].publish(h)
    before_b = models[W_B].base.calibration_scores
    rc['n1'].ready.put(rc['n1'].build(114))
    assert rc['n1'].apply() == 1 and rc['n1'].apply() == 1           # nothing more queued
    assert models[W_B].base.calibration_scores is before_b
    window = [r for r in rows if r['workload_key'] == W_A and 102 * H <= r['window_end'] < 114 * H and r['eligible_for_normal_review']]
    ref = Recalibrator.from_rows(window, 250)
    probe = dict(rows[-1], tree_score=0.97, support_score=0.42, joint_p=1.0)
    want = ref.rewrite(probe)
    m = models[W_A]
    tree_p = float(pvalues(np.array([0.97]), m.base.calibration_scores)[0]); support_p = float(pvalues(np.array([0.42]), m.support_calibration)[0])
    assert (tree_p, support_p) == (want['tree_p'], want['support_p'])
    rc['n1'].write_logs()
    log = [json.loads(l) for l in (tmp_path / 'n1.jsonl').read_text().splitlines()]
    assert log[-1]['event'] == 'applied' and log[-1]['kept'] == [W_B] and W_A in log[-1]['swapped']


def test_schedule_publishes_then_refreshes_once_per_period(tmp_path):
    write_buffers(tmp_path, hours=range(100, 103))
    models = {W_A: fake_model()}
    r = lr.LiveRecalibration(models, tmp_path / 'local' / 'n1', tmp_path / 'shared', 'n1', window_hours=2, refresh_hours=2,
                             minimum_examples=10)
    r.tick(103 * H + 30)                       # before the publish delay
    assert r.published == set() and r.ready.empty()
    r.tick(103 * H + 61)
    assert r.published == {102} and (tmp_path / 'shared' / 'n1' / (lr.hour_name(102) + '.bin')).exists() and r.ready.empty()
    r.tick(103 * H + 400)                      # odd hour: no refresh with refresh_hours=2
    assert r.ready.empty()
    r.tick(104 * H + 301); r.tick(104 * H + 900)
    assert r.ready.qsize() == 1 and r.apply() == 1


def test_missing_worker_hour_is_left_out_and_logged(tmp_path):
    write_buffers(tmp_path)
    _, rc = recalibrators(tmp_path)
    for h in range(100, 114):
        rc['n1'].publish(h)
        if h != 110:
            rc['n2'].publish(h)
    _, cal, info = rc['n1'].build(114)
    assert info['missing'] == [['n2', lr.hour_name(110)]] and W_A in cal


def test_shared_copy_is_bounded_and_schedule_is_validated(tmp_path):
    write_buffers(tmp_path)
    _, rc = recalibrators(tmp_path)
    for h in range(100, 114):
        rc['n1'].publish(h)
    kept = sorted(p.stem for p in (tmp_path / 'shared' / 'n1').glob('*.json'))
    assert kept[0] == lr.hour_name(100) and len(kept) == 14   # window 12: nothing older than 113 - 13 = 100 yet
    rc['n1'].publish(120)
    assert sorted(p.stem for p in (tmp_path / 'shared' / 'n1').glob('*.json'))[0] == lr.hour_name(107)
    with pytest.raises(ValueError):
        lr.LiveRecalibration({}, tmp_path, tmp_path / 's', 'n', publish_delay_seconds=400, refresh_delay_seconds=300)


def test_swap_reaches_both_scoring_paths_of_a_real_model(tmp_path):
    """After a swap the reference path and the fast path give identical p-values, those of the new arrays."""
    from sklearn.ensemble import ExtraTreesClassifier
    from sentinel_pulse.detector import fast_forest
    from sentinel_pulse.detector.extended_reference_experiment import PulseExtendedReferenceTree
    from sentinel_pulse.detector.support_model import PulseSupportEnsemble
    rng = np.random.default_rng(5)
    x = rng.random((400, 8)).astype(np.float32); y = (x[:, 0] > 0.5).astype(int)
    base = PulseExtendedReferenceTree(history=1, alpha=.001); base.feature_dim = 4
    base.estimator = ExtraTreesClassifier(n_estimators=16, random_state=0, n_jobs=1).fit(x, y)
    base.calibration_scores = np.sort(rng.random(30))
    model = PulseSupportEnsemble(base); model.low = np.zeros(4); model.high = np.full(4, 0.8); model.scale = np.ones(4)
    model.support_calibration = np.sort(rng.random(30)); model.alpha = 0.01
    r = lr.LiveRecalibration({W_A: model}, tmp_path / 'b', tmp_path / 's', 'n1', minimum_examples=100)
    tree, support = np.sort(rng.random(500)), np.sort(rng.random(500) * 0.3)
    r.ready.put((114, {W_A: (tree, support)}, dict(span=[0, 1], nodes=['n1'], missing=[], excluded_spans=0)))
    assert r.apply() == 1
    ref, fast = model.predict_contexts(x[:50]), fast_forest.predict_contexts(model, x[:50])
    for k in ('tree_p', 'support_p', 'joint_p'):
        np.testing.assert_array_equal(ref[k], fast[k])
    np.testing.assert_array_equal(ref['tree_p'], pvalues(ref['tree_score'], tree))
    np.testing.assert_array_equal(ref['support_p'], pvalues(ref['support_score'], support))
