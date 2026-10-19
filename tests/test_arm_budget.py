import numpy as np

from sentinel_pulse.syscall_study import arm_budget as ab


def test_episodes_merge_positive_windows_per_container():
    identity = np.array([1, 1, 1, 2, 1])
    end = np.array([0.5, 1.0, 30.0, 1.0, 40.0])
    positive = np.array([True, True, True, True, True])
    # container 1: {0.5, 1.0}, {30.0}; 40.0 is < 15 s after 30.0; container 2: {1.0}
    assert ab.count_episodes(identity, end, positive) == 3
    assert ab.count_episodes(identity, end, np.zeros(5, dtype=bool)) == 0


def test_joint_p_matches_recalibrator_combination():
    cal = np.sort(np.arange(100, dtype=float))
    p = ab.joint_p(np.array([99.5, 0.0]), np.array([0.0, 0.0]), cal, cal)
    assert p[0] == 2/101 and p[1] == 1.0


def test_evaluate_arm_and_matched_budget():
    rng = np.random.default_rng(0)
    n = 4000
    end = np.arange(n)*0.5
    holdout = {'ns/w:c|armA|1': dict(identity=np.zeros(n, dtype=np.int64), window_end=end,
                                       tree=rng.normal(size=n), support=rng.normal(size=n))}
    attack = [dict(start=100.0+0.5*i, end=100.5+0.5*i, alpha=0.01, tree_score=10.0, support_score=10.0, joint_p=1.0)
              for i in range(30)]
    control = [dict(w, start=w['start']+100, end=w['end']+100, tree_score=0.0, support_score=0.0) for w in attack]
    replay = {'ns/w:c|armA|1': {'/c/1:attack': attack, '/c/1:control': control}}
    trials = [dict(trial_id='1:attack', campaign_path='/c', workload_key='ns/w:c', label='attack', start_at=100.0, kernel_event_at=100.2),
              dict(trial_id='1:control', campaign_path='/c', workload_key='ns/w:c', label='expected_normal', start_at=200.0)]
    result = ab.evaluate_arm('armA', holdout, replay, trials, split_at=end[n//2], scales=(1, 5))
    s1 = result['scales']['1']
    assert result['calibrated_models'] == 1
    assert s1['recall'] == 1.0 and s1['control_positive_rate'] == 0.0
    assert result['scales']['5']['episodes_per_replica_hour'] >= s1['episodes_per_replica_hour']
    pick = ab.matched({'armA': result}, budgets=(1e9,))['1e+09']['armA']
    assert pick['alpha_scale'] == 5
