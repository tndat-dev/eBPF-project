import numpy as np

from sentinel_pulse.attack import rolling_recalibration as rr


def drifting_rows(hours=12, rate=2.0):
    """One container whose normal scores drift upward by one unit per hour."""
    n = int(hours*3600*rate)
    end = np.arange(n)/rate
    rng = np.random.default_rng(1)
    drift = end/3600
    return {'ns/w:c': dict(identity=np.zeros(n, dtype=np.int64), end=end,
                           tree=rng.normal(size=n)+drift, support=rng.normal(size=n)+drift,
                           eligible=np.ones(n, dtype=bool), alpha=0.01)}


def burden(rows, kind, guarded=False):
    static = (0.0, 3600.0)
    blocks = rr.schedule(kind, 3*3600, 12*3600, static, 1, 1)
    flags, cals = rr.run_strategy(rows, blocks, [], guarded=guarded, static_span=static)
    return rr.normal_metrics(rows, flags, 3*3600, 12*3600, [])['1']


def test_rolling_calibration_tracks_drift_that_static_does_not():
    static = burden(drifting_rows(), 'static')
    rolling = burden(drifting_rows(), 'rolling')
    assert static['positive_window_rate'] > 0.5
    assert rolling['positive_window_rate'] < static['positive_window_rate']/4
    assert len(rolling['hourly_episodes_per_replica_hour']) == 9


def test_episode_starts_align_with_inputs():
    identity = np.array([0, 1, 0, 0])
    end = np.array([1.0, 1.0, 1.5, 40.0])
    starts = rr.episode_starts(identity, end, np.array([True, True, True, True]))
    assert starts.tolist() == [True, True, False, True]


def test_campaign_intervals_are_masked():
    end = np.arange(0, 100, 0.5)
    m = rr.masked(end, [(10.0, 20.0)])
    assert m.sum() == 20 and m[np.searchsorted(end, 10.0)]


def test_k_of_n_confirmation_lowers_normal_positives():
    rows = drifting_rows(hours=6)
    static = (0.0, 3600.0)
    blocks = rr.schedule('rolling', 3*3600, 6*3600, static, 1, 1)
    flags, _ = rr.run_strategy(rows, blocks, [], guarded=False, scales=(3.0,), static_span=static)
    one = rr.normal_metrics(rows, flags, 3*3600, 6*3600, [], scales=(3.0,))['3']
    two = rr.normal_metrics(rows, flags, 3*3600, 6*3600, [], scales=(3.0,), confirmation=(2, 2))['3']
    assert 0 < two['positive_window_rate'] < one['positive_window_rate']


def with_nodes(rows, shift_node_b=0.0):
    """Two replicas on two nodes; node B's scores shifted by ``shift_node_b``; recorded p = 0.5."""
    out = {}
    for w, a in rows.items():
        n = len(a['end'])
        node = np.where(np.arange(n) % 2 == 0, 'node-a', 'node-b')
        shift = np.where(node == 'node-b', shift_node_b, 0.0)
        out[w] = dict(a, identity=(np.arange(n) % 2).astype(np.int64), node=node,
                      tree=a['tree'] + shift, support=a['support'] + shift, jp=np.full(n, 0.5),
                      start=a['end'] - 0.5, tp=np.full(n, 0.5), sp=np.full(n, 0.5))
    return out


def test_weighted_pvalues_with_unit_weights_equal_the_unweighted_ones():
    rng = np.random.default_rng(3)
    tree, support = rng.normal(size=5000), rng.normal(size=5000)
    test_t, test_s = rng.normal(size=300), rng.normal(size=300)
    plain = rr.Calibration(tree, support).joint_p(test_t, test_s)
    weighted = rr.Calibration(tree, support, np.ones(5000)).joint_p(test_t, test_s)
    np.testing.assert_array_equal(plain, weighted)


def test_weighted_calibration_tracks_drift_better_than_static():
    rows = with_nodes(drifting_rows())
    def rate(name):
        flags, _, _, _ = rr.run_strategy_ext(rows, name, 3*3600, 12*3600, (0.0, 3600.0), [], scales=(1.0,))
        return rr.normal_metrics(rows, flags, 3*3600, 12*3600, [], scales=(1.0,))['1']['positive_window_rate']
    static, weighted = rate('static'), rate('weighted-3-1-1')
    assert static > 0.5 and weighted < static / 4


def test_mondrian_calibration_equalises_nodes():
    rows = with_nodes(drifting_rows(hours=4), shift_node_b=1.0)
    def node_rates(name):
        flags, _, _, _ = rr.run_strategy_ext(rows, name, 2*3600, 4*3600, (0.0, 3600.0), [], scales=(3.0,))
        a, f = rows['ns/w:c'], flags[3.0]['ns/w:c'] & flags['scored']['ns/w:c']
        return [f[a['node'] == n].mean() for n in ('node-a', 'node-b')]
    pooled, mondrian = node_rates('rolling-2-1'), node_rates('mondrian-2-1')
    assert pooled[1] > 3 * max(pooled[0], 1e-4)          # pooled: node B flagged ~4.6x as often
    assert abs(mondrian[0] - mondrian[1]) < 0.5 * max(mondrian)


def test_aci_holds_the_target_rate_within_the_gibbs_candes_bound():
    rng = np.random.default_rng(5)
    T, target = 400_000, 0.02
    p = 0.3 * rng.uniform(size=T)            # stale calibration: 3.3x too many positives at the target
    gamma = rr.ACI_GAMMA * target
    flags, alpha = rr.aci_alpha(p, np.ones(T, dtype=bool), target, gamma)
    bound = (max(target, 1 - target) + gamma) / (T * gamma)
    assert abs(flags.mean() - target) <= bound
    assert abs(flags.mean() - target) < 0.15 * target and alpha[-1] < target


def test_trial_rows_use_their_node_cell_and_the_aci_alpha():
    cal_a = rr.Calibration(np.arange(2000.0), np.arange(2000.0))
    cal_b = rr.Calibration(np.arange(2000.0) + 1000, np.arange(2000.0) + 1000)
    rescorers = [(0.0, 100.0, {'w': {None: cal_a, 'node-b': cal_b}})]
    row = dict(status=rr.SCORED, joint_p=0.5, workload_key='w', node_name='node-b', tree_score=1999.5, support_score=1999.5,
               candidate_policy_alpha=0.001)
    alphas = {'w': (np.array([10.0, 20.0, 30.0]), np.array([0.02, 0.01, 0.005]))}
    out = rr.rescore_trial_rows([row, dict(row, node_name='node-c')], rescorers, 25.0, alphas, scale=10.0)
    assert out[0]['joint_p'] == float(cal_b.joint_p(np.array([1999.5]), np.array([1999.5]))[0])
    assert out[1]['joint_p'] == float(cal_a.joint_p(np.array([1999.5]), np.array([1999.5]))[0])   # pooled fallback
    assert abs(out[0]['candidate_policy_alpha'] - 0.01 / 10.0) < 1e-12


def test_asrun_uses_recorded_pvalues_only_inside_the_evaluation_span():
    rows = with_nodes(drifting_rows(hours=2))
    flags, rescorers, alphas, blocks = rr.run_strategy_ext(rows, 'asrun', 3600.0, 7200.0, (0.0, 1.0), [], scales=(1.0,))
    end = rows['ns/w:c']['end']
    assert rescorers is None and alphas is None and blocks == 1
    assert flags['scored']['ns/w:c'].sum() == ((end >= 3600) & (end < 7200)).sum()
    assert not flags[1.0]['ns/w:c'].any()      # recorded p = 0.5 never passes alpha 0.01


def test_run_end_to_end_on_a_synthetic_capture_and_campaign(tmp_path):
    """CLI-level path the fresh run uses: worker root on disk, campaign trial, every registered strategy."""
    import json
    M, P = 'm' * 64, 'p' * 64
    ident = dict(workload_key='ns/w:c', pod_uid='pod', container_name='c', workload_revision='r', cgroup_id=7)
    rng = np.random.default_rng(11)
    rows = []
    for node in ('node-a', 'node-b'):
        for i in range(4 * 3600 * 2):                        # 4 h of 0.5 s windows per node
            a = i * 0.5; b = a + 0.5
            attack = node == 'node-a' and 3 * 3600 + 30 <= a < 3 * 3600 + 45
            rows.append(dict(ident, node_name=node, pod_uid=f'pod-{node}', window_start=a, window_end=b,
                             status=rr.SCORED, policy_evaluated=True, candidate_manifest_sha256=M, policy_sha256=P,
                             eligible_for_normal_review=True, candidate_policy_alpha=0.002, alert=False,
                             policy_applied=False, serving_compatible=False, preview_emitted_at=b + 0.2,
                             candidate_alert_preview=False, tree_score=float(rng.normal() + (8 if attack else 0)),
                             support_score=float(rng.normal() + (8 if attack else 0)), joint_p=0.5,
                             tree_p=0.5, support_p=0.5))
    seg = tmp_path / 'workers' / 'w1' / 'segments' / 's00001'; seg.mkdir(parents=True)
    (seg / 'decisions.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    camp = tmp_path / 'campaign'; (camp / 'trials' / '1').mkdir(parents=True)
    start = 3 * 3600 + 30.0
    trial = dict(ident, node_name='node-a', pod_uid='pod-node-a', start_at=start, kernel_event_at=start + 0.2, label='attack')
    control = dict(trial, start_at=start - 30.0, label='expected_normal'); control.pop('kernel_event_at')
    decisions = [r for r in rows if r['node_name'] == 'node-a' and start - 40 <= r['window_start'] < start + 20]
    (camp / 'trials' / '1' / 'EVALUATION_INPUT.json').write_text(json.dumps(dict(attack=trial, control=control, decisions=decisions)))
    (camp / 'INTERVALS.jsonl').write_text(json.dumps(dict(start_at=start - 30.0)) + '\n' + json.dumps(dict(start_at=start)) + '\n')
    out = tmp_path / 'RESULTS.json'
    strategies = ('asrun', 'static', 'rolling-1-1', 'weighted-2-1-1', 'mondrian-1-1', 'aci-asrun', 'aci-rolling-1-1')
    result = rr.run([tmp_path / 'workers' / 'w1'], [camp], out, (0.0, 3600.0), 3600.0, strategies=strategies,
                    scales=(5.0,), confirmation=(2, 2), model_hash=M, policy_hash=P)
    # combined replay (5.19): calibration strategies x Cauchy / CUSUM, same capture and campaign
    for temporal in ('cauchy', 'cusum-3-6'):
        combo = rr.run([tmp_path / 'workers' / 'w1'], [camp], tmp_path / f'{temporal}.json', (0.0, 3600.0), 3600.0,
                       strategies=('rolling-1-1', 'mondrian-1-1', 'weighted-2-1-1'), scales=(5.0,), confirmation=(2, 2),
                       model_hash=M, policy_hash=P, temporal=temporal)
        assert combo['temporal'] == temporal
        for name, r in combo['strategies'].items():
            cm = r['attack']['5']['confusion_matrix_expected_control_labels']
            assert cm['TP'] == 1 and cm['FP'] == 0, (temporal, name, cm)
    assert set(result['strategies']) == set(strategies) and out.exists()
    for name in strategies:
        attack = result['strategies'][name]['attack']['5']
        cm = attack['confusion_matrix_expected_control_labels']
        if name in ('asrun', 'aci-asrun'):
            assert cm['TP'] == 0                             # recorded p = 0.5 everywhere
        else:
            assert cm['TP'] == 1 and cm['FP'] == 0, (name, cm)
    assert 'aci_alpha_over_target' in result['strategies']['aci-rolling-1-1']


def test_branch_pvalues_reproduce_the_joint_pvalue():
    rng = np.random.default_rng(4)
    tree, support, test = rng.normal(size=3000), rng.normal(size=3000), rng.normal(size=(2, 500))
    for weights in (None, rng.uniform(0.1, 1, size=3000)):
        cal = rr.Calibration(tree, support, weights)
        pt, ps = cal.branch_p(*test)
        np.testing.assert_array_equal(np.minimum(1.0, 2 * np.minimum(pt, ps)), cal.joint_p(*test))


def test_cusum_flags_match_the_offline_screen():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location('ideas_screen', Path(__file__).parents[1] / 'scripts' / 'analysis' / 'ideas_screen.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    rng = np.random.default_rng(8)
    n = 3000
    end = 100 + 0.5 * np.arange(n) + np.where(np.arange(n) >= 1500, 3.0, 0.0)   # one gap restarts the statistic
    p = np.where((np.arange(n) % 400) < 12, rng.uniform(1e-6, 1e-3, n), rng.uniform(1e-3, 1, n))
    a = dict(identity=np.zeros(n, dtype=np.int64), start=end - 0.5, end=end)
    live = rr.cusum_flags(a, p, rr.CusumPolicy(3.0, 6.0))
    offline = mod.alarms_cusum([dict(start=s, end=e, joint_p=q) for s, e, q in zip(a['start'], end, p)], 3.0, 6.0)
    assert live.tolist() == offline and live.any()
