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


def _reference_confirm(identity, end, passed, k, n):
    """Row-by-row reference: Pulse's own ConfirmationState."""
    from sentinel_pulse.detector.confirmation import ConfirmationPolicy, ConfirmationState
    state = ConfirmationState(ConfirmationPolicy(k=k, n=n, alpha_scale=1.0))
    out = np.zeros(len(end), dtype=bool)
    for i in np.lexsort((end, identity)):
        row = dict(workload_key='w', node_name='n', pod_uid=str(identity[i]), container_name='c',
                   workload_revision='r', cgroup_id=1, window_start=end[i]-0.5, window_end=end[i],
                   candidate_policy_alpha=0.5, joint_p=0.1 if passed[i] else 0.9)
        out[i] = state.update(row)
    return out


def test_vectorised_confirmation_matches_pulse_confirmation_state():
    rng = np.random.default_rng(7)
    m = 3000
    identity = rng.integers(0, 4, m)
    # mostly 0.5 s cadence with occasional gaps (> 1 s) and overlaps, as in real captures
    steps = rng.choice([0.5, 0.5, 0.5, 0.5, 2.0, 0.2], size=m)
    end = np.cumsum(steps)
    passed = rng.random(m) < 0.4
    for k, n in ((1, 1), (2, 2), (2, 3), (3, 5)):
        assert np.array_equal(ab.confirm(identity, end, passed, k, n), _reference_confirm(identity, end, passed, k, n)), (k, n)


def test_confirmed_windows_only_keep_confirmed_positives():
    windows = [dict(start=0.5*i, end=0.5*i+0.5, joint_p=p) for i, p in enumerate([0.001, 0.9, 0.001, 0.001, 0.9])]
    out = ab.confirmed_windows(windows, 0.01, k=2, n=2)
    assert [w['joint_p'] <= 0.01 for w in out] == [False, False, False, True, False]
    assert out[0]['raw_joint_p'] == 0.001
    assert ab.confirmed_windows(windows, 0.01) is windows
