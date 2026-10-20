import json

from sentinel_pulse.syscall_study import arm_bootstrap as boot


def test_bootstrap_pairs_trials_and_clusters_by_workload(tmp_path):
    rows = []
    for w in range(6):
        for t in range(5):
            for arm, hit_attack, hit_benign in (('base29', t < 4, t < 3), ('armX', True, t < 1)):
                for seed in (1, 2, 3):
                    rows.append(dict(arm=arm, seed=seed, scale=1.0, trial_key=f'c/{w}-{t}:attack', workload=f'w{w}',
                                     kind='attack', outcome='TP' if hit_attack else 'FN', delay=None))
                    rows.append(dict(arm=arm, seed=seed, scale=1.0, trial_key=f'c/{w}-{t}:benign', workload=f'w{w}',
                                     kind='benign', outcome='FP_expected' if hit_benign else 'TN_expected', delay=None))
    (tmp_path/'TRIAL_OUTCOMES.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    pick = dict(alpha_scale=1.0)
    (tmp_path/'RESULTS.json').write_text(json.dumps(dict(matched_budget={'5': {'base29': pick, 'armX': pick}})))
    result = boot.run(tmp_path, tmp_path/'out.json', budgets=('5',), reps=200)
    x = result['budgets']['5']['armX']
    assert abs(x['recall']['point'] - 1.0) < 1e-9 and abs(x['recall_diff']['point'] - 0.2) < 1e-9
    assert abs(x['separation_diff']['point'] - 0.6) < 1e-9
    assert x['paired_trials'] == 60 and x['workloads'] == 6 and x['non_inferior_recall']


def test_campaign_without_benign_controls_reports_control_rate(tmp_path):
    # pulse-attack-dev has attack and idle-control trials only; the bootstrap must not fail on benign columns
    rows = []
    for w in range(4):
        for t in range(4):
            for arm, hit_attack, hit_control in (('base29', t < 3, t < 1), ('armX', t < 2, False)):
                rows.append(dict(arm=arm, seed=1, scale=1.0, trial_key=f'c/{w}-{t}:attack', workload=f'w{w}',
                                 kind='attack', outcome='TP' if hit_attack else 'FN', delay=None))
                rows.append(dict(arm=arm, seed=1, scale=1.0, trial_key=f'c/{w}-{t}:control', workload=f'w{w}',
                                 kind='expected_normal', outcome='FP_expected' if hit_control else 'TN_expected', delay=None))
    (tmp_path/'TRIAL_OUTCOMES.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    pick = dict(alpha_scale=1.0)
    (tmp_path/'RESULTS.json').write_text(json.dumps(dict(matched_budget={'5': {'base29': pick, 'armX': pick}})))
    x = boot.run(tmp_path, tmp_path/'out.json', budgets=('5',), reps=200)['budgets']['5']['armX']
    assert x['benign_rate'] is None and x['separation'] is None and x['separation_diff'] is None
    assert abs(x['recall_diff']['point'] + 0.25) < 1e-9 and abs(x['control_diff']['point'] + 0.25) < 1e-9
    assert not x['non_inferior_recall']


def test_default_budgets_are_those_with_a_base29_match(tmp_path):
    rows = [dict(arm=arm, seed=1, scale=1.0, trial_key=f'c/{w}:attack', workload=f'w{w}', kind='attack',
                 outcome='TP', delay=None) for arm in ('base29', 'armX') for w in range(3)]
    (tmp_path/'TRIAL_OUTCOMES.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    pick = dict(alpha_scale=1.0)
    (tmp_path/'RESULTS.json').write_text(json.dumps(dict(matched_budget={
        '0.1': {'base29': None, 'armX': None}, '1': {'base29': pick, 'armX': pick}, '5': {'base29': pick, 'armX': pick}})))
    assert sorted(boot.run(tmp_path, tmp_path/'out.json', reps=50)['budgets']) == ['1', '5']
