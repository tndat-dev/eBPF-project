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
