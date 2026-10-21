import json

import numpy as np
import pytest

from sentinel_pulse.detector.recalibration import Recalibrator
from sentinel_pulse.pipeline import retention as rt


def decision(t, w='production/a:app', tree=0.1, support=0.2, eligible=True, preview=False, passed=False, status=rt.SCORED, pod='p1'):
    return dict(status=status, window_end=t, tree_score=tree, support_score=support, workload_key=w, node_name='n',
                pod_uid=pod, container_name='app', workload_revision='r', cgroup_id=1,
                eligible_for_normal_review=eligible, candidate_alert_preview=preview, window_passed=passed)


def test_buffer_roundtrip_matches_recalibrator_from_decisions(tmp_path):
    rng = np.random.default_rng(1)
    rows = [decision(36000.0 + 0.5 * i, w=('production/a:app' if i % 3 else 'production/b:app'),
                     tree=float(rng.normal()), support=float(rng.normal()), eligible=i % 7 != 0) for i in range(20000)]
    buf = rt.ScoreBuffer(tmp_path, 12, clock=lambda: 36000.0 + 10000)
    assert sum(buf.add(r) for r in rows) == len(rows)
    assert not buf.add(decision(1.0, status='warming'))
    buf.close()
    assert len(list(tmp_path.glob('*.bin'))) == 3            # 10 000 s span = 3 UTC hours
    got = rt.calibration_from_buffer([tmp_path], 36000.0, 46000.0, minimum_examples=100)
    ref = Recalibrator.from_rows([r for r in rows if r['eligible_for_normal_review']], 100)   # bit-identical inputs
    for w in ref.tree:
        np.testing.assert_array_equal(got.tree[w], ref.tree[w]); np.testing.assert_array_equal(got.support[w], ref.support[w])
    assert rt.RECORD.itemsize == 31


def test_buffer_prunes_files_older_than_the_retention(tmp_path):
    now = [10 * 3600.0]
    buf = rt.ScoreBuffer(tmp_path, 1, clock=lambda: now[0])
    for h in range(10):
        buf.add(decision(h * 3600.0 + 10))
    buf.close()
    now[0] = 10 * 3600.0
    rt.ScoreBuffer(tmp_path, 1, clock=lambda: now[0]).prune()
    hours = sorted(f.stem for f in tmp_path.glob('*.bin'))
    assert len(hours) <= 2 and all((tmp_path / f'{h}.json').exists() for h in hours)
    with pytest.raises(ValueError):
        rt.ScoreBuffer(tmp_path, 100)


def test_output_policy_operational_mode_keeps_positives_and_a_sample():
    full = rt.OutputPolicy(None)
    assert full.keep_feature() and full.keep_decision(decision(1.0))
    op = rt.OutputPolicy(dict(features='off', decisions='positives', sample_every=10))
    assert not op.keep_feature()
    kept = [op.keep_decision(decision(float(i))) for i in range(100)]
    assert sum(kept) == 10
    assert op.keep_decision(decision(1.0, preview=True)) and op.keep_decision(decision(1.0, passed=True))
    assert not op.keep_decision(decision(1.0, status='warming'))
    with pytest.raises(ValueError):
        rt.OutputPolicy(dict(decisions='some'))
