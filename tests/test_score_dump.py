import json

import numpy as np

from sentinel_pulse.syscall_study.score_dump import ScoreCollector


def test_collector_roundtrip_keeps_identity_and_scores(tmp_path):
    c = ScoreCollector()
    rows = [dict(workload_key='w', node_name='n', pod_uid=p, container_name='c', workload_revision='r',
                 cgroup_id=1, window_start=t - .5, window_end=t) for p, t in (('a', 1.), ('b', 1.), ('a', 1.5))]
    c('w|base29|1', rows, dict(tree_score=np.array([.1, .2, .3]), support_score=np.array([1., 2., 3.])))
    c.save(tmp_path / 'scores.npz')
    d = np.load(tmp_path / 'scores.npz', allow_pickle=False)
    assert d['w|base29|1::identity'].tolist() == [0, 1, 0]
    assert d['w|base29|1::window_end'].tolist() == [1., 1., 1.5]
    assert np.allclose(d['w|base29|1::tree_score'], [.1, .2, .3])
    assert json.loads(str(d['identities']))[1] == ['w', 'n', 'b', 'c', 'r', '1']
