#!/usr/bin/env python3
"""Per-scenario recall of every syscall arm at its matched budget (from arm_budget output).

Reads ``RESULTS.json`` (matched alpha scale per arm and budget) and ``TRIAL_OUTCOMES.jsonl``
of one arm_budget run, plus the campaigns' EVALUATION_INPUT files for the attack scenario of
each trial. For every budget and arm: recall per scenario (TP / (TP + FN), seeds pooled) and,
where the campaign has them, the benign-launch positive rate. Unknown outcomes are left out.
``--by rate`` (or ``scenario_rate``) groups by the fixture's attack rate instead (G4: does a slower attacker
escape?), and every group also reports the p50/p95 first-alarm delay of its attacks.
"""
import argparse, collections, glob, json, time
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--budget-dir', required=True)
p.add_argument('--campaign', action='append', required=True)
p.add_argument('--output', required=True)
p.add_argument('--by', choices=('scenario', 'rate', 'scenario_rate'), default='scenario')
a = p.parse_args()

scenario = {}
for campaign in a.campaign:
    for path in glob.glob(campaign.rstrip('/') + '/trials/*/EVALUATION_INPUT.json'):
        d = json.loads(Path(path).read_text())
        for label in ('control', 'benign', 'attack'):
            if label in d:
                group = dict(scenario=d['attack']['scenario'], rate=f"{d['attack'].get('rate_per_second')}/s",
                             scenario_rate=f"{d['attack']['scenario']}@{d['attack'].get('rate_per_second')}/s")[a.by]
                scenario[f"{campaign.rstrip('/')}/{d[label]['trial_id']}"] = group

results = json.loads(Path(a.budget_dir, 'RESULTS.json').read_text())
picks = {(b, arm): float(v['alpha_scale']) for b, arms in results['matched_budget'].items()
         for arm, v in arms.items() if v}
wanted = collections.defaultdict(list)
for (b, arm), scale in picks.items():
    wanted[arm, scale].append(b)

counts = collections.defaultdict(collections.Counter)   # (budget, arm, group) -> outcome counts
delays = collections.defaultdict(list)
missing = 0
with open(Path(a.budget_dir, 'TRIAL_OUTCOMES.jsonl')) as stream:
    for line in stream:
        r = json.loads(line)
        budgets = wanted.get((r['arm'], float(r['scale'])))
        if not budgets:
            continue
        sc = scenario.get(r['trial_key'])
        if sc is None:
            missing += 1; continue
        for b in budgets:
            counts[b, r['arm'], sc][f"{r['kind']}:{r['outcome']}"] += 1
            if r.get('delay') is not None:
                delays[b, r['arm'], sc].append(r['delay'])

table = {}
for (b, arm, sc), c in sorted(counts.items()):
    tp, fn = c['attack:TP'], c['attack:FN']
    bfp, btn = c['benign:FP_expected'], c['benign:TN_expected']
    d = sorted(delays[b, arm, sc])
    q = lambda f: d[min(len(d) - 1, int(f * len(d)))] if d else None   # nearest-rank percentile
    table.setdefault(b, {}).setdefault(arm, {})[sc] = dict(
        recall=tp / (tp + fn) if tp + fn else None, attack_trials=tp + fn,
        benign_positive_rate=bfp / (bfp + btn) if bfp + btn else None, delay_p50=q(.5), delay_p95=q(.95))
out = dict(schema='syscall-arm-scenarios-v1', budget_dir=a.budget_dir, campaigns=a.campaign, grouped_by=a.by,
           confirmation=results.get('confirmation', dict(k=1, n=1)), matched_alpha_scale={f'{b}|{arm}': s for (b, arm), s in picks.items()},
           outcome_rows_without_scenario=missing, budgets=table, computed_at_unix=time.time())
Path(a.output).write_text(json.dumps(out, indent=2))
for b, arms in table.items():
    print('== budget', b)
    scenarios = sorted({sc for v in arms.values() for sc in v})
    print(f"{'arm':24s} " + ' '.join(f'{s[:14]:>14s}' for s in scenarios))
    for arm, v in sorted(arms.items()):
        print(f'{arm:24s} ' + ' '.join(f"{(v.get(s) or {}).get('recall') or 0:14.3f}" for s in scenarios))
